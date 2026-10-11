use super::*;

#[test]
fn native_user_identity_uses_bounded_http_and_releases_refresh_task_on_drop()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_HTTP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::accounts::native_user_identity_uses_bounded_http_and_releases_refresh_task_on_drop"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(
            status.success(),
            "isolated native identity HTTP test failed"
        );
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let native = Arc::new(RejectedNativeAdc {
            authorized_user: true,
            allow_tasks: true,
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone())
            .build_access_token_credentials()?;
        let token = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            credentials.access_token(),
        )
        .await;
        assert_eq!(
            native.http_calls.load(Ordering::SeqCst),
            1,
            "native HTTP dispatch was bypassed"
        );
        let token = token??;
        assert_eq!(token.token, "native-access-canary");
        drop(token);
        drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "native refresh retained an idle task after credential drop"
            );
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_service_account_signs_through_the_admitted_crypto_owner()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_SERVICE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::accounts::native_service_account_signs_through_the_admitted_crypto_owner"])
            .env(CHILD, "1")
            .env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(
            status.success(),
            "isolated native service account test failed"
        );
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"service_account","client_email":"native@example.invalid","private_key_id":"native-id","private_key":"native-private-key-canary","project_id":"native-project"}"#.to_vec()),
            allow_tasks: true, allow_rsa: true, ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let token = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await;
        assert_eq!(native.rsa_calls.load(Ordering::SeqCst), 1, "native cryptographic boundary was bypassed");
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 0, "self-signed ADC unexpectedly made an HTTP call");
        let token = token??;
        assert_eq!(token.token.split('.').count(), 3);
        assert!(!format!("{token:?}").contains("canary"));
        drop(token); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "service-account refresh retained its owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_adc_metadata_fallback_uses_the_admitted_http_owner()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_METADATA_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::accounts::native_adc_metadata_fallback_uses_the_admitted_http_owner"])
            .env(CHILD, "1").env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env("HOME", "/fictional/positron-native-home")
            .env("GCE_METADATA_HOST", "127.0.0.1:9")
            .status()?;
        assert!(status.success(), "isolated metadata fallback test failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let native = Arc::new(RejectedNativeAdc {
                file_absent: true,
                allow_tasks: true,
                ..RejectedNativeAdc::default()
            });
            let credentials = google_cloud_auth::credentials::Builder::default()
                .with_native_runtime(native.clone())
                .build_access_token_credentials()?;
            let token = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                credentials.access_token(),
            )
            .await??;
            assert_eq!(token.token, "native-access-canary");
            assert_eq!(native.reads.load(Ordering::SeqCst), 1);
            assert_eq!(native.http_calls.load(Ordering::SeqCst), 1);
            {
                let requests = native.requests.lock().expect("fixture request lock");
                assert!(
                    requests[0]
                        .0
                        .contains("/computeMetadata/v1/instance/service-accounts/default/token")
                );
                assert_eq!(
                    requests[0]
                        .1
                        .get("metadata-flavor")
                        .and_then(|v| v.to_str().ok()),
                    Some("Google")
                );
            }
            drop(token);
            drop(credentials);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while native.tasks.load(Ordering::SeqCst) != 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "metadata refresh retained its owner after drop"
                );
                tokio::task::yield_now().await;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}
#[test]
fn native_adc_impersonation_propagates_the_owner_to_source_and_target()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_IMPERSONATED_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::accounts::native_adc_impersonation_propagates_the_owner_to_source_and_target"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated impersonation test failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let reply = |bytes: &[u8]| google_cloud_auth::native::Response {
            status: http::StatusCode::OK, headers: http::HeaderMap::new(), body: Zeroizing::new(bytes.to_vec())
        };
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"impersonated_service_account","service_account_impersonation_url":"http://127.0.0.1:9/v1/projects/-/serviceAccounts/native@example.invalid:generateAccessToken","source_credentials":{"type":"authorized_user","client_id":"native-client","client_secret":"native-secret-canary","refresh_token":"native-refresh-canary","token_uri":"http://127.0.0.1:9/token"},"scopes":["scope"],"delegates":[]}"#.to_vec()),
            allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                reply(br#"{"access_token":"native-access-canary","token_type":"Bearer","expires_in":3600}"#),
                reply(br#"{"accessToken":"native-impersonated-canary","expireTime":"2100-01-01T00:00:00Z"}"#),
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let token = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await??;
        assert_eq!(token.token, "native-impersonated-canary");
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 2);
        assert_eq!(native.spawn_attempts.load(Ordering::SeqCst), 2);
        {
            let requests = native.requests.lock().expect("fixture request lock");
            assert_eq!(requests.get(1).and_then(|(_, h)| h.get("authorization")).and_then(|v| v.to_str().ok()), Some("Bearer native-access-canary"));
        }
        drop(token); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "impersonated refresh retained source or target owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_adc_impersonation_rejects_past_expiry_without_panicking()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_IMPERSONATED_EXPIRY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::accounts::native_adc_impersonation_rejects_past_expiry_without_panicking"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated impersonation test failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let reply = |bytes: &[u8]| google_cloud_auth::native::Response {
            status: http::StatusCode::OK, headers: http::HeaderMap::new(), body: Zeroizing::new(bytes.to_vec())
        };
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"impersonated_service_account","service_account_impersonation_url":"http://127.0.0.1:9/v1/projects/-/serviceAccounts/native@example.invalid:generateAccessToken","source_credentials":{"type":"authorized_user","client_id":"native-client","client_secret":"native-secret-canary","refresh_token":"native-refresh-canary","token_uri":"http://127.0.0.1:9/token"},"scopes":["scope"],"delegates":[]}"#.to_vec()),
            allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                reply(br#"{"access_token":"native-access-canary","token_type":"Bearer","expires_in":3600}"#),
                reply(br#"{"accessToken":"native-impersonated-canary","expireTime":"2000-01-01T00:00:00Z"}"#),
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await?;
        let error = result.err().ok_or("expired native token was accepted")?;
        assert_eq!(source_failure(&error), Some(KeyProviderFailure::InvalidConfiguration), "untrusted native expiry must yield a typed configuration error");
        drop(error); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "impersonated refresh retained source or target owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

// Add `subject: Option<Vec<u8>>` to RejectedNativeAdc. Name read_file's Path `path`.
// Immediately after reads increment:
// if path == std::path::Path::new("/fictional/native-subject") {
//     return self.subject.clone().map(Zeroizing::new).ok_or(google_cloud_auth::native::Error::NotFound);
// }
#[test]
fn native_user_identity_preserves_permission_denied_without_secret_output()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_NATIVE_403_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin").env("HOME", "/fictional/positron-native-home")
            .env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .env(CHILD, "1")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::accounts::native_user_identity_preserves_permission_denied_without_secret_output"])
            .status()?;
        assert!(
            status.success(),
            "isolated native response failure regression failed"
        );
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let body = br#"{"error":"native-response-secret-canary"}"#.to_vec();
        let native = Arc::new(RejectedNativeAdc {
            authorized_user: true,
            allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                google_cloud_auth::native::Response {
                    status: http::StatusCode::FORBIDDEN,
                    headers: http::HeaderMap::new(),
                    body: Zeroizing::new(body),
                },
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone())
            .build_access_token_credentials()?;
        let error = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            credentials.access_token(),
        )
        .await?
        .expect_err("native response refusal must not become a later successful refresh");
        assert_eq!(
            source_failure(&error),
            Some(KeyProviderFailure::PermissionDenied)
        );
        assert_eq!(
            native.http_calls.load(Ordering::SeqCst),
            1,
            "native refusal was retried"
        );
        assert!(!format!("{error:?}").contains("native-response-secret-canary"));
        drop(error);
        drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "native response refusal retained refresh work"
            );
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_user_identity_refuses_amplified_response_without_retry()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_NATIVE_RESPONSE_BOUND_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin").env("HOME", "/fictional/positron-native-home")
            .env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .env(CHILD, "1")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::accounts::native_user_identity_refuses_amplified_response_without_retry"])
            .status()?;
        assert!(
            status.success(),
            "isolated native response failure regression failed"
        );
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let body = serde_json::to_vec(&serde_json::json!({"access_token":"native-response-secret-canary", "token_type":"Bearer", "expires_in":3600, "ignored":vec![0_u8; 2050]}))?;
        let native = Arc::new(RejectedNativeAdc { authorized_user: true, allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([google_cloud_auth::native::Response {
                status: http::StatusCode::OK, headers: http::HeaderMap::new(), body: Zeroizing::new(body),
            }])), ..RejectedNativeAdc::default() });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let error = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await?
            .expect_err("native response refusal must not become a later successful refresh");
        assert_eq!(source_failure(&error), Some(KeyProviderFailure::LimitExceeded));
        assert!(!error.is_transient(), "native response admission refusal was marked retryable");
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 1, "native refusal was retried");
        assert!(!format!("{error:?}").contains("native-response-secret-canary"));
        drop(error); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "native response refusal retained refresh work");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
