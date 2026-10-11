// Copyright 2025 Google LLC
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

use google_cloud_gax::error::CredentialsError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, time::Duration};

use crate::{
    Result,
    credentials::external_account::CredentialSourceFormat,
    credentials::subject_token::{
        Builder as SubjectTokenBuilder, SubjectToken, SubjectTokenProvider,
    },
    errors,
};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct UrlSourcedCredentials {
    #[serde(skip)]
    native_runtime: Option<std::sync::Arc<dyn crate::native::Runtime>>,
    pub url: String,
    pub headers: HashMap<String, zeroize::Zeroizing<String>>,
    pub format: String,
    pub subject_token_field_name: String,
}
impl std::fmt::Debug for UrlSourcedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("UrlSourcedCredentials { redacted }") }
}
impl Drop for UrlSourcedCredentials {
    fn drop(&mut self) { use zeroize::Zeroize; self.url.zeroize(); }
}


impl UrlSourcedCredentials {
    pub(crate) fn with_native_runtime(mut self, runtime: Option<std::sync::Arc<dyn crate::native::Runtime>>) -> Self {
        self.native_runtime = runtime;
        self
    }
    pub(crate) fn new(
        url: String,
        headers: Option<HashMap<String, zeroize::Zeroizing<String>>>,
        format_source: Option<CredentialSourceFormat>,
    ) -> Self {
        let (format, subject_token_field_name) = format_source
            .map(|f| {
                (
                    f.format_type,
                    f.subject_token_field_name.unwrap_or_default(),
                )
            })
            .unwrap_or(("text".to_string(), String::new()));
        Self {
            native_runtime: None,
            url,
            headers: headers.unwrap_or_default(),
            format,
            subject_token_field_name,
        }
    }
}

const MSG: &str = "failed to request subject token";
const JSON_FORMAT_TYPE: &str = "json";

impl SubjectTokenProvider for UrlSourcedCredentials {
    type Error = CredentialsError;
    async fn subject_token(&self) -> Result<SubjectToken> {
        let client = if let Some(runtime) = &self.native_runtime {
            crate::native::HttpClient::new(Some(runtime.clone()))
        } else {
            let client = Client::builder().timeout(Duration::from_secs(10)).build()
                .map_err(|error| errors::from_http_error(error, MSG))?;
            crate::native::HttpClient::from_upstream(client)
        };

        let request = client.get(&self.url);
        let request = self
            .headers
            .iter()
            .fold(request, |r, (k, v)| r.header(k.as_str(), v.as_str()));

        let response = request
            .send()
            .await
            .map_err(|e| errors::from_http_error(e, MSG))?;

        if !response.status().is_success() {
            let err = errors::from_http_response(response, MSG).await;
            return Err(err);
        }

        if self.native_runtime.is_some() {
            let bytes = response.bytes().await.map_err(|error| errors::from_http_error(error, MSG))?;
            let token = if self.format == JSON_FORMAT_TYPE {
                let guard = crate::native::SecretJson::parse(&bytes).map_err(crate::native::credential_error)?;
                guard.as_value().get(&self.subject_token_field_name).and_then(Value::as_str)
                    .ok_or_else(|| crate::native::credential_error(crate::native::Error::InvalidConfiguration))?.to_owned()
            } else {
                std::str::from_utf8(&bytes).map_err(|_| crate::native::credential_error(crate::native::Error::InvalidConfiguration))?.to_owned()
            };
            return Ok(SubjectTokenBuilder::new(token).build());
        }
        let mut response_text = response.text().await.map_err(|e| {
            let retryable = !e.is_body();
            CredentialsError::from_source(retryable, e)
        })?;

        match self.format.as_str() {
            JSON_FORMAT_TYPE => {
                let json_response: Value = serde_json::from_str(&response_text)
                    .map_err(|e| CredentialsError::from_source(false, e))?;

                match json_response.get(&self.subject_token_field_name) {
                    Some(Value::String(token)) => {
                        Ok(SubjectTokenBuilder::new(token.clone()).build())
                    }
                    None | Some(_) => {
                        let msg = format!(
                            "failed to read subject token field `{}` as string, body=<{}>",
                            self.subject_token_field_name, json_response,
                        );
                        Err(CredentialsError::from_msg(false, msg.as_str()))
                    }
                }
            }
            _ => Ok(SubjectTokenBuilder::new(std::mem::take(&mut *response_text)).build()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{Expectation, Server, matchers::*, responders::*};
    use serde_json::json;
    use std::{collections::HashMap, error::Error};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn get_json_token() -> TestResult {
        let response_body = json!({
            "access_token":"an_example_token",
        })
        .to_string();

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/token"),
                request::headers(contains(("metadata", "True"))),
            ])
            .respond_with(status_code(200).body(response_body)),
        );

        let url = server.url("/token").to_string();
        let token_provider = UrlSourcedCredentials {
            native_runtime: None,
            url,
            format: "json".into(),
            subject_token_field_name: "access_token".into(),
            headers: HashMap::from([("Metadata".to_string(), "True".to_string().into())]),
        };
        let resp = token_provider.subject_token().await?;

        assert_eq!(resp.token, "an_example_token".to_string());

        Ok(())
    }

    #[tokio::test]
    async fn get_text_token() -> TestResult {
        let response_body = "an_example_token".to_string();

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![request::method_path("GET", "/token"),])
                .respond_with(status_code(200).body(response_body)),
        );

        let url = server.url("/token").to_string();
        let token_provider = UrlSourcedCredentials {
            native_runtime: None,
            url,
            format: "text".into(),
            subject_token_field_name: "".into(),
            headers: HashMap::new(),
        };
        let resp = token_provider.subject_token().await?;

        assert_eq!(resp.token, "an_example_token".to_string());

        Ok(())
    }

    #[tokio::test]
    async fn get_json_token_missing_field() -> TestResult {
        let response_body = json!({
            "wrong_field":"an_example_token",
        })
        .to_string();

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/token"),
                request::headers(contains(("metadata", "True"))),
            ])
            .respond_with(status_code(200).body(response_body)),
        );

        let url = server.url("/token").to_string();
        let token_provider = UrlSourcedCredentials {
            native_runtime: None,
            url,
            format: "json".into(),
            subject_token_field_name: "access_token".into(),
            headers: HashMap::from([("Metadata".to_string(), "True".to_string().into())]),
        };

        let err = token_provider
            .subject_token()
            .await
            .expect_err("parsing should fail");

        assert!(!err.is_transient(), "{err:?}");
        assert!(err.source().is_none(), "{:?}", err.source());

        assert!(err.to_string().contains("`access_token`"), "{err:?}");
        assert!(
            err.to_string()
                .contains("{\"wrong_field\":\"an_example_token\"}"),
            "{err:?}"
        );

        Ok(())
    }
}
