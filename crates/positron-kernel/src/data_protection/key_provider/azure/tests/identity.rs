use super::*;

#[derive(Debug)]
struct Assertion;
#[async_trait::async_trait]
impl azure_identity::ClientAssertion for Assertion {
    async fn secret(
        &self,
        _: Option<azure_core::http::ClientMethodOptions<'_>>,
    ) -> azure_core::Result<String> {
        Ok("fictional-assertion".to_owned())
    }
}
#[derive(Debug)]
struct IdentityReply {
    status: azure_core::http::StatusCode,
    body: &'static str,
}
#[async_trait::async_trait]
impl azure_core::http::HttpClient for IdentityReply {
    async fn execute_request(
        &self,
        _: &azure_core::http::Request,
    ) -> azure_core::Result<azure_core::http::AsyncRawResponse> {
        Ok(azure_core::http::AsyncRawResponse::from_bytes(
            self.status,
            azure_core::http::headers::Headers::new(),
            azure_core::Bytes::from_static(self.body.as_bytes()),
        ))
    }
}
#[tokio::test]
async fn native_sdk_failure_is_secret_free_and_expiry_is_fallible()
-> Result<(), Box<dyn std::error::Error>> {
    for (status, body) in [
        (
            azure_core::http::StatusCode::BadRequest,
            r#"{"error_codes":[123],"error_description":"native-secret-canary"}"#,
        ),
        (
            azure_core::http::StatusCode::Ok,
            r#"{"access_token":"native-secret-canary","expires_in":"native-secret-canary"}"#,
        ),
        (
            azure_core::http::StatusCode::Ok,
            r#"{"access_token":"native-secret-canary","expires_in":9223372036854775807}"#,
        ),
    ] {
        let credential = azure_identity::ClientAssertionCredential::new(
            "00000000-0000-0000-0000-000000000001".to_owned(),
            "fictional-client".to_owned(),
            Assertion,
            Some(azure_identity::ClientAssertionCredentialOptions {
                client_options: azure_core::http::ClientOptions {
                    transport: Some(azure_core::http::Transport::new(Arc::new(IdentityReply {
                        status,
                        body,
                    }))),
                    ..Default::default()
                },
            }),
        )?;
        let error = credential
            .get_token(&["https://vault.azure.net/.default"], None)
            .await
            .expect_err("invalid native transcript rejected");
        assert!(!format!("{error:?} {error}").contains("native-secret-canary"));
    }
    Ok(())
}

#[derive(Debug)]
struct RefusedIdentity;
#[async_trait::async_trait]
impl azure_core::http::HttpClient for RefusedIdentity {
    async fn execute_request(
        &self,
        _: &azure_core::http::Request,
    ) -> azure_core::Result<azure_core::http::AsyncRawResponse> {
        Err(azure_core::Error::with_error(
            azure_core::error::ErrorKind::Other,
            KeyProviderFailure::LimitExceeded,
            "admission refused",
        ))
    }
}
#[tokio::test]
async fn provider_preserves_native_identity_admission_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let credential = azure_identity::ClientAssertionCredential::new(
        "00000000-0000-0000-0000-000000000001".to_owned(),
        "fixture-client".to_owned(),
        Assertion,
        Some(azure_identity::ClientAssertionCredentialOptions {
            client_options: azure_core::http::ClientOptions {
                transport: Some(azure_core::http::Transport::new(Arc::new(RefusedIdentity))),
                ..Default::default()
            },
        }),
    )?;
    let mut provider = fixture(vec![]);
    provider.credentials = credential;
    assert_eq!(
        provider.probe(context()).await,
        Err(KeyProviderFailure::LimitExceeded)
    );
    Ok(())
}
