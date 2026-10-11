// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    Result,
    credentials::subject_token::{
        Builder as SubjectTokenBuilder, SubjectToken, SubjectTokenProvider,
    },
    errors,
};
use google_cloud_gax::error::CredentialsError;
use hmac::{Hmac, KeyInit, Mac};
use jiff::Timestamp;
use crate::native::{HttpClient as Client, HttpResponse as Response, Zeroizing};
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const AWS_REGION: &str = "AWS_REGION";
const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";
const AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";

const IMDSV2_TOKEN_TTL_HEADER: &str = "x-aws-ec2-metadata-token-ttl-seconds";
const IMDSV2_TOKEN_HEADER: &str = "x-aws-ec2-metadata-token";
const IMDSV2_DEFAULT_TOKEN_TTL_SECONDS: &str = "21600";

const X_AMZ_DATE: &str = "x-amz-date";
const X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";
const X_GOOG_CLOUD_TARGET_RESOURCE: &str = "x-goog-cloud-target-resource";

const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";
const AWS4_REQUEST: &str = "aws4_request";
const AWS_STS_SERVICE: &str = "sts";

const DEFAULT_REGIONAL_CRED_VERIFICATION_URL: &str =
    "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";

const MSG: &str = "failed to fetch AWS credentials for subject token";

/// Credential source for AWS workloads using Workload Identity Federation.
///
/// This provider fetches a subject token by making a signed AWS STS `GetCallerIdentity`
/// request, following the specifications in [AIP-4117].
///
/// [AIP-4117]: https://google.aip.dev/auth/4117
#[derive(Debug, Clone)]
pub(crate) struct AwsSourcedCredentials {
    native_runtime: Option<std::sync::Arc<dyn crate::native::Runtime>>,
    /// The URL to fetch the AWS region from IMDS.
    pub region_url: Option<String>,
    /// The URL to fetch the AWS IAM role credentials from IMDS.
    pub role_url: Option<String>,
    /// The regional AWS STS endpoint used for verification.
    pub regional_cred_verification_url: Option<String>,
    /// The URL to fetch an IMDSv2 session token.
    pub imdsv2_session_token_url: Option<String>,
    /// The audience for the x-goog-cloud-target-resource header.
    pub audience: String,
}

impl AwsSourcedCredentials {
    pub(crate) fn with_native_runtime(mut self, runtime: Option<std::sync::Arc<dyn crate::native::Runtime>>) -> Self {
        self.native_runtime = runtime;
        self
    }
    fn hash(&self, data: &str) -> Result<String> {
        match &self.native_runtime {
            Some(runtime) => runtime.sha256(data.as_bytes()).map(hex::encode).map_err(crate::native::credential_error),
            None => Ok(hash_sha256(data)),
        }
    }
    fn mac(&self, key: &[u8], data: &str) -> Result<Zeroizing<Vec<u8>>> {
        match &self.native_runtime {
            Some(runtime) => {
                let digest = Zeroizing::new(runtime.hmac_sha256(key, data.as_bytes()).map_err(crate::native::credential_error)?);
                Ok(Zeroizing::new(digest.to_vec()))
            },
            None => hmac_sha256(key, data).map(Zeroizing::new),
        }
    }
    fn signing_key(&self, secret: &str, date: &str, region: &str) -> Result<Zeroizing<Vec<u8>>> {
        if self.native_runtime.is_none() { return get_signing_key(secret, date, region, AWS_STS_SERVICE).map(Zeroizing::new); }
        let secret = Zeroizing::new(format!("AWS4{secret}"));
        let date = self.mac(secret.as_bytes(), date)?;
        let region = self.mac(&date, region)?;
        let service = self.mac(&region, AWS_STS_SERVICE)?;
        self.mac(&service, AWS4_REQUEST)
    }
    pub(crate) fn new(
        region_url: Option<String>,
        role_url: Option<String>,
        regional_cred_verification_url: Option<String>,
        imdsv2_session_token_url: Option<String>,
        audience: String,
    ) -> Self {
        Self {
            native_runtime: None,
            region_url,
            role_url,
            regional_cred_verification_url,
            imdsv2_session_token_url,
            audience,
        }
    }
}

#[derive(Deserialize)]
struct AwsSecurityCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: Zeroizing<String>,
    #[serde(rename = "Token")]
    token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for AwsSecurityCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("AwsSecurityCredentials { redacted }") }
}
impl Drop for AwsSecurityCredentials {
    fn drop(&mut self) {
        self.access_key_id.zeroize(); self.secret_access_key.zeroize();
        if let Some(token) = &mut self.token { token.zeroize(); }
    }
}

#[derive(Serialize)]
struct AwsStsRequest {
    url: String,
    method: String,
    headers: Vec<AwsHeader>,
    body: String,
}

#[derive(Serialize)]
struct AwsHeader {
    key: String,
    value: String,
}

impl Drop for AwsHeader {
    fn drop(&mut self) { self.key.zeroize(); self.value.zeroize(); }
}
impl Drop for AwsStsRequest {
    fn drop(&mut self) { self.url.zeroize(); self.method.zeroize(); self.body.zeroize(); }
}

impl SubjectTokenProvider for AwsSourcedCredentials {
    type Error = CredentialsError;

    async fn subject_token(&self) -> Result<SubjectToken> {
        let client = Client::new(self.native_runtime.clone());

        let imdsv2_token = self.resolve_imdsv2_token(&client).await?;

        let region = self
            .resolve_region(&client, imdsv2_token.as_ref().map(|token| token.as_str()))
            .await?;
        let creds = self
            .resolve_credentials(&client, imdsv2_token.as_ref().map(|token| token.as_str()))
            .await?;

        if self.native_runtime.is_some() && (region.len() > 4096 || creds.access_key_id.len() > crate::native::MAXIMUM_BYTES
            || creds.secret_access_key.len() > crate::native::MAXIMUM_BYTES || creds.token.as_ref().is_some_and(|token| token.len() > crate::native::MAXIMUM_BYTES)) {
            return Err(crate::native::credential_error(crate::native::Error::LimitExceeded));
        }
        let now = Timestamp::now();
        let amz_date = now.strftime("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.strftime("%Y%m%d").to_string();

        let url = resolve_sts_url(self.regional_cred_verification_url.as_deref(), &region)?;
        let host = url.host_str().ok_or_else(|| crate::native::credential_error(crate::native::Error::InvalidConfiguration))?;
        let sts_url = url.to_string();

        let method = "POST";
        let body = "";
        let canonical_uri = "/";

        let query_params: BTreeMap<_, _> = url.query_pairs().collect();
        let canonical_query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query_params)
            .finish();

        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), Zeroizing::new(host.to_string()));
        headers.insert(X_AMZ_DATE.to_string(), Zeroizing::new(amz_date.clone()));
        if let Some(token) = &creds.token {
            headers.insert(X_AMZ_SECURITY_TOKEN.to_string(), token.clone());
        }
        headers.insert(
            X_GOOG_CLOUD_TARGET_RESOURCE.to_string(),
            Zeroizing::new(self.audience.clone()),
        );

        let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical_headers = Zeroizing::new(headers.iter().fold(String::new(), |mut acc, (k, v)| {
            acc.push_str(k); acc.push(':'); acc.push_str(v.trim()); acc.push('\n');
            acc
        }));

        let payload_hash = self.hash(body)?;

        let canonical_request = Zeroizing::new(format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, canonical_uri, canonical_query, canonical_headers.as_str(), signed_headers, payload_hash
        ));

        let credential_scope = format!(
            "{}/{}/{}/{}",
            date_stamp, region, AWS_STS_SERVICE, AWS4_REQUEST
        );
        let string_to_sign = Zeroizing::new(format!(
            "{}\n{}\n{}\n{}",
            AWS4_HMAC_SHA256,
            amz_date,
            credential_scope,
            self.hash(&canonical_request)?
        ));

        let signing_key = self.signing_key(&creds.secret_access_key, &date_stamp, &region)?;
        let signature = Zeroizing::new(hex::encode(self.mac(&signing_key, &string_to_sign)?.as_slice()));

        let authorization_header = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            AWS4_HMAC_SHA256, creds.access_key_id, credential_scope, signed_headers, signature.as_str()
        );

        let final_headers: Vec<_> = headers
            .into_iter()
            .map(|(key, mut value)| AwsHeader { key, value: std::mem::take(&mut *value) })
            .chain(std::iter::once(AwsHeader {
                key: "Authorization".to_string(),
                value: authorization_header,
            }))
            .collect();

        let aws_sts_request = AwsStsRequest {
            url: sts_url,
            method: method.to_string(),
            headers: final_headers,
            body: body.to_string(),
        };

        let json_token = Zeroizing::new(serde_json::to_string(&aws_sts_request)
            .map_err(|_| crate::native::credential_error(crate::native::Error::InvalidConfiguration))?);
        if self.native_runtime.is_some() && json_token.len() > crate::native::MAXIMUM_BYTES {
            return Err(crate::native::credential_error(crate::native::Error::LimitExceeded));
        }

        let subject_token: String =
            url::form_urlencoded::byte_serialize(json_token.as_bytes()).collect();

        if self.native_runtime.is_some() && subject_token.len() > crate::native::MAXIMUM_BYTES {
            let _subject = Zeroizing::new(subject_token);
            return Err(crate::native::credential_error(crate::native::Error::LimitExceeded));
        }
        Ok(SubjectTokenBuilder::new(subject_token).build())
    }
}

fn resolve_sts_url(template: Option<&str>, region: &str) -> Result<url::Url> {
    let sts_url = template
        .unwrap_or(DEFAULT_REGIONAL_CRED_VERIFICATION_URL)
        .replace("{region}", region);
    let sts_url = if sts_url.starts_with("http") {
        sts_url
    } else {
        format!("https://{sts_url}")
    };
    let url = url::Url::parse(&sts_url)
        .map_err(|e| CredentialsError::from_msg(false, format!("invalid AWS STS URL: {e}")))?;

    if url.host_str().is_none() {
        return Err(CredentialsError::from_msg(
            false,
            "invalid AWS STS URL: missing host",
        ));
    }
    Ok(url)
}

fn hash_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &str) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|e| {
        CredentialsError::from_msg(
            false,
            format!("failed to initialize HMAC from secret key: {e}"),
        )
    })?;
    mac.update(data.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn get_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Result<Vec<u8>> {
    let secret_key = format!("AWS4{}", secret);
    let k_date = hmac_sha256(secret_key.as_bytes(), date)?;
    let k_region = hmac_sha256(&k_date, region)?;
    let k_service = hmac_sha256(&k_region, service)?;
    hmac_sha256(&k_service, AWS4_REQUEST)
}

// Zone name "us-east-1d" -> Region "us-east-1"
fn parse_region_from_zone(zone: &str) -> Option<&str> {
    let zone = zone.trim();
    if zone.is_empty() {
        return None;
    }
    if let Some(last_char) = zone.chars().last()
        && last_char.is_ascii_alphabetic()
        && zone.len() > 1
    {
        let potential_region = &zone[..zone.len() - 1];
        if potential_region
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_digit())
        {
            return Some(potential_region);
        }
    }
    Some(zone)
}

impl AwsSourcedCredentials {
    async fn resolve_imdsv2_token(&self, client: &Client) -> Result<Option<Zeroizing<String>>> {
        if let Some(url) = &self.imdsv2_session_token_url {
            let response = client
                .put(url)
                .header(IMDSV2_TOKEN_TTL_HEADER, IMDSV2_DEFAULT_TOKEN_TTL_SECONDS)
                .send()
                .await
                .map_err(|e| errors::from_http_error(e, MSG))?;

            if !response.status().is_success() {
                return Err(
                    errors::from_http_response(response, "failed to resolve IMDSv2 token").await,
                );
            }

            let token = response
                .text()
                .await
                .map_err(|e| errors::from_http_error(e, "failed to read IMDSv2 token body"))?;

            return Ok(Some(token));
        }
        Ok(None)
    }

    async fn get_with_imdsv2_token(
        &self,
        client: &Client,
        url: &str,
        imdsv2_token: Option<&str>,
        error_msg: &str,
    ) -> Result<Response> {
        let request = client.get(url);
        let request = if let Some(token) = imdsv2_token {
            request.header(IMDSV2_TOKEN_HEADER, token)
        } else {
            request
        };
        let response = request
            .send()
            .await
            .map_err(|e| errors::from_http_error(e, MSG))?;
        if !response.status().is_success() {
            return Err(errors::from_http_response(response, error_msg).await);
        }
        Ok(response)
    }

    async fn resolve_region(&self, client: &Client, imdsv2_token: Option<&str>) -> Result<String> {
        if let Ok(region) = std::env::var(AWS_REGION) {
            return Ok(region);
        }
        if let Ok(region) = std::env::var(AWS_DEFAULT_REGION) {
            return Ok(region);
        }

        if let Some(url) = &self.region_url {
            let response = self
                .get_with_imdsv2_token(client, url, imdsv2_token, "could not resolve AWS region")
                .await?;

            let zone = response
                .text()
                .await
                .map_err(|e| errors::from_http_error(e, "failed to read AWS region body"))?;
            if let Some(region) = parse_region_from_zone(&zone) {
                return Ok(region.to_string());
            }
        }
        Err(CredentialsError::from_msg(
            false,
            "could not resolve AWS region",
        ))
    }

    async fn resolve_role_name(
        &self,
        client: &Client,
        imdsv2_token: Option<&str>,
    ) -> Result<String> {
        if let Some(url) = &self.role_url {
            let response = self
                .get_with_imdsv2_token(client, url, imdsv2_token, "could not resolve AWS role name")
                .await?;

            let role_name = response
                .text()
                .await
                .map_err(|e| errors::from_http_error(e, "failed to read AWS role name body"))?;

            return Ok(role_name.trim().to_string());
        }
        Err(CredentialsError::from_msg(
            false,
            "unable to determine the AWS metadata server security credentials endpoint",
        ))
    }

    async fn resolve_role_credentials(
        &self,
        client: &Client,
        role_name: &str,
        imdsv2_token: Option<&str>,
    ) -> Result<AwsSecurityCredentials> {
        if let Some(url) = &self.role_url {
            let role_url = format!("{}/{}", url.trim_end_matches('/'), role_name.trim());
            let response = self
                .get_with_imdsv2_token(
                    client,
                    &role_url,
                    imdsv2_token,
                    "could not resolve AWS credentials",
                )
                .await?;

            let creds = response
                .json()
                .await
                .map_err(|e| errors::from_http_error(e, "failed to parse AWS credentials JSON"))?;
            return Ok(creds);
        }
        Err(CredentialsError::from_msg(
            false,
            "unable to determine the AWS metadata server security credentials endpoint",
        ))
    }

    async fn resolve_credentials(
        &self,
        client: &Client,
        imdsv2_token: Option<&str>,
    ) -> Result<AwsSecurityCredentials> {
        if let Ok(ak) = std::env::var(AWS_ACCESS_KEY_ID)
            && let Ok(sk) = std::env::var(AWS_SECRET_ACCESS_KEY)
        {
            return Ok(AwsSecurityCredentials {
                access_key_id: ak,
                secret_access_key: Zeroizing::new(sk),
                token: std::env::var(AWS_SESSION_TOKEN).ok().map(Zeroizing::new),
            });
        }

        let role_name = self.resolve_role_name(client, imdsv2_token).await?;
        let role_credentials = self
            .resolve_role_credentials(client, &role_name, imdsv2_token)
            .await?;

        Ok(role_credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{Expectation, Server, matchers::*, responders::*};
    use scoped_env::ScopedEnv;
    use serde_json::json;
    use serial_test::{parallel, serial};
    use test_case::test_case;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test_case("us-east-1a", Some("us-east-1"); "zone_to_region")]
    #[test_case("us-east-1", Some("us-east-1"); "already_region")]
    #[test_case("us-gov-west-1a", Some("us-gov-west-1"); "gov_zone_to_region")]
    #[test_case("us-gov-west-1", Some("us-gov-west-1"); "gov_already_region")]
    #[test_case("  us-east-1a  ", Some("us-east-1"); "trimmed_zone")]
    #[test_case("", None; "empty")]
    #[test_case("   ", None; "whitespace")]
    #[test_case("a", Some("a"); "short_zone")]
    fn test_parse_region_from_zone(zone: &str, expected: Option<&str>) {
        assert_eq!(parse_region_from_zone(zone), expected);
    }

    #[test_case(None, "us-east-1", "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"; "default_template")]
    #[test_case(Some("http://custom.sts.url/{region}"), "us-west-2", "http://custom.sts.url/us-west-2"; "custom_template_with_region")]
    #[test_case(Some("sts.amazonaws.com"), "us-east-1", "https://sts.amazonaws.com/"; "no_scheme")]
    #[test_case(Some("https://sts.amazonaws.com"), "us-east-1", "https://sts.amazonaws.com/"; "with_scheme")]
    fn test_resolve_sts_url(template: Option<&str>, region: &str, expected: &str) {
        let url = resolve_sts_url(template, region).expect("should resolve");
        assert_eq!(url.as_str(), expected);
    }

    #[test]
    fn test_resolve_sts_url_invalid() {
        let result = resolve_sts_url(Some("not a url"), "region");
        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_region_env() -> TestResult {
        let _e = ScopedEnv::set(AWS_REGION, "us-west-2");
        let _e2 = ScopedEnv::remove(AWS_DEFAULT_REGION);
        let creds = AwsSourcedCredentials::new(
            None,
            None,
            Some("sts.{region}.amazonaws.com".into()),
            None,
            "aud".into(),
        );
        let client = Client::new(None);
        assert_eq!(
            creds.resolve_region(&client, None).await?,
            "us-west-2",
            "{creds:?}"
        );
        Ok(())
    }

    #[tokio::test]
    #[parallel]
    async fn test_resolve_region_imds() -> TestResult {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/zone"))
                .respond_with(status_code(200).body("us-east-1d")),
        );

        let creds = AwsSourcedCredentials::new(
            Some(server.url("/zone").to_string()),
            None,
            Some("sts.{region}.amazonaws.com".into()),
            None,
            "aud".into(),
        );
        let client = Client::new(None);
        assert_eq!(
            creds.resolve_region(&client, None).await?,
            "us-east-1",
            "{creds:?}"
        );
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_credentials_env() -> TestResult {
        let _e1 = ScopedEnv::set(AWS_ACCESS_KEY_ID, "ACCESS_KEY_ID");
        let _e2 = ScopedEnv::set(AWS_SECRET_ACCESS_KEY, "SECRET");
        let _e3 = ScopedEnv::remove(AWS_SESSION_TOKEN);
        let creds = AwsSourcedCredentials::new(
            None,
            None,
            Some("sts.{region}.amazonaws.com".into()),
            None,
            "aud".into(),
        );
        let client = Client::new(None);
        let resolved = creds.resolve_credentials(&client, None).await?;
        assert_eq!(resolved.access_key_id, "ACCESS_KEY_ID", "{resolved:?}");
        assert_eq!(resolved.secret_access_key.as_str(), "SECRET", "{resolved:?}");
        Ok(())
    }

    #[tokio::test]
    #[parallel]
    async fn test_resolve_credentials_imds() -> TestResult {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/role"))
                .respond_with(status_code(200).body("my-role")),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/role/my-role")).respond_with(
                status_code(200).body(
                    json!({
                        "AccessKeyId": "ACCESS_KEY_ID_IMDS",
                        "SecretAccessKey": "SECRET_IMDS",
                        "Token": "TOKEN_IMDS"
                    })
                    .to_string(),
                ),
            ),
        );

        let creds = AwsSourcedCredentials::new(
            None,
            Some(server.url("/role").to_string()),
            Some("sts.{region}.amazonaws.com".into()),
            None,
            "aud".into(),
        );
        let client = Client::new(None);
        let resolved = creds.resolve_credentials(&client, None).await?;
        assert_eq!(resolved.access_key_id, "ACCESS_KEY_ID_IMDS", "{resolved:?}");
        assert_eq!(resolved.secret_access_key.as_str(), "SECRET_IMDS", "{resolved:?}");
        assert_eq!(
            resolved.token.as_ref().map(|v| v.as_str()),
            Some("TOKEN_IMDS"),
            "{resolved:?}"
        );
        Ok(())
    }

    #[tokio::test]
    #[parallel]
    async fn test_resolve_imdsv2_token() -> TestResult {
        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method("PUT"),
                request::path("/token"),
                request::headers(contains((
                    IMDSV2_TOKEN_TTL_HEADER,
                    IMDSV2_DEFAULT_TOKEN_TTL_SECONDS
                )))
            ])
            .respond_with(status_code(200).body("test-token")),
        );

        let creds = AwsSourcedCredentials::new(
            None,
            None,
            Some("sts.{region}.amazonaws.com".into()),
            Some(server.url("/token").to_string()),
            "aud".into(),
        );
        let client = Client::new(None);
        let token = creds.resolve_imdsv2_token(&client).await?;
        assert_eq!(token.as_ref().map(|v| v.as_str()), Some("test-token"), "{token:?}");
        Ok(())
    }

    #[tokio::test]
    #[parallel]
    async fn test_subject_token_imdsv2_success() -> TestResult {
        let server = Server::run();
        // IMDSv2 Token
        server.expect(
            Expectation::matching(all_of![request::method("PUT"), request::path("/token")])
                .respond_with(status_code(200).body("test-token")),
        );
        // Region
        server.expect(
            Expectation::matching(all_of![
                request::method("GET"),
                request::path("/zone"),
                request::headers(contains((IMDSV2_TOKEN_HEADER, "test-token")))
            ])
            .respond_with(status_code(200).body("us-east-1d")),
        );
        // Role Name
        server.expect(
            Expectation::matching(all_of![
                request::method("GET"),
                request::path("/role"),
                request::headers(contains((IMDSV2_TOKEN_HEADER, "test-token")))
            ])
            .respond_with(status_code(200).body("my-role")),
        );
        // Role Credentials
        server.expect(
            Expectation::matching(all_of![
                request::method("GET"),
                request::path("/role/my-role"),
                request::headers(contains((IMDSV2_TOKEN_HEADER, "test-token")))
            ])
            .respond_with(
                status_code(200)
                    .insert_header("Content-Type", "application/json")
                    .body(
                        json!({
                            "AccessKeyId": "ACCESS_KEY_ID_IMDS",
                            "SecretAccessKey": "SECRET_IMDS",
                            "Token": "TOKEN_IMDS"
                        })
                        .to_string(),
                    ),
            ),
        );

        let creds = AwsSourcedCredentials::new(
            Some(server.url("/zone").to_string()),
            Some(server.url("/role").to_string()),
            Some("sts.{region}.amazonaws.com".into()),
            Some(server.url("/token").to_string()),
            "another_audience".into(),
        );

        let mut subject_token = creds.subject_token().await?;
        let token_str = std::mem::take(&mut subject_token.token);

        // Subject token is URL encoded, so we need to decode it once before parsing JSON.
        let decoded_json: String = url::form_urlencoded::parse(token_str.as_bytes())
            .map(|(k, _)| k)
            .collect();

        let val: serde_json::Value = serde_json::from_str(&decoded_json)?;

        assert_eq!(val["method"], "POST", "{val:?}");
        assert_eq!(
            val["url"], "https://sts.us-east-1.amazonaws.com/",
            "{val:?}"
        );

        let headers = val["headers"]
            .as_array()
            .ok_or("headers should be an array")?;

        // Find x-goog-cloud-target-resource
        let target_resource = headers
            .iter()
            .find(|h| h["key"] == X_GOOG_CLOUD_TARGET_RESOURCE)
            .ok_or("missing target resource header")?;
        assert_eq!(target_resource["value"], "another_audience", "{val:?}");

        // Find Authorization
        let auth = headers
            .iter()
            .find(|h| h["key"] == "Authorization")
            .ok_or("missing auth header")?;
        assert!(
            auth["value"].as_str().unwrap().contains("AWS4-HMAC-SHA256"),
            "{val:?}"
        );
        assert!(
            auth["value"]
                .as_str()
                .unwrap()
                .contains("ACCESS_KEY_ID_IMDS"),
            "{val:?}"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_subject_token_env_success() -> TestResult {
        let _e1 = ScopedEnv::set(AWS_REGION, "us-west-2");
        let _e2 = ScopedEnv::set(AWS_ACCESS_KEY_ID, "AN_ACCESS_KEY_ID");
        let _e3 = ScopedEnv::set(AWS_SECRET_ACCESS_KEY, "SECRET_ENV");
        let _e4 = ScopedEnv::remove(AWS_SESSION_TOKEN);

        let creds = AwsSourcedCredentials::new(
            None,
            None,
            Some("sts.{region}.amazonaws.com".into()),
            None,
            "some_audience".into(),
        );

        let mut subject_token = creds.subject_token().await?;
        let token_str = std::mem::take(&mut subject_token.token);
        let decoded_json: String = url::form_urlencoded::parse(token_str.as_bytes())
            .map(|(k, _)| k)
            .collect();
        let val: serde_json::Value = serde_json::from_str(&decoded_json)?;

        assert_eq!(
            val["url"], "https://sts.us-west-2.amazonaws.com/",
            "{val:?}"
        );

        let headers = val["headers"]
            .as_array()
            .ok_or("headers should be an array")?;
        let auth = headers
            .iter()
            .find(|h| h["key"] == "Authorization")
            .ok_or("missing auth header")?;
        assert!(
            auth["value"].as_str().unwrap().contains("AN_ACCESS_KEY_ID"),
            "{auth:?}"
        );

        Ok(())
    }
}
