use super::*;

#[test]
fn native_adc_external_file_and_sts_use_the_admitted_owner()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_EXTERNAL_FILE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::external::native_adc_external_file_and_sts_use_the_admitted_owner"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated external-file ADC test failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"http://127.0.0.1:9/sts","credential_source":{"file":"/fictional/native-subject"}}"#.to_vec()),
            subject: Some(b"native-subject-canary".to_vec()), allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"access_token":"native-external-canary","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#.to_vec())
                },
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let token = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await??;
        assert_eq!(token.token, "native-external-canary");
        assert_eq!(native.reads.load(Ordering::SeqCst), 2);
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 1);
        assert_eq!(native.spawn_attempts.load(Ordering::SeqCst), 1);
        drop(token); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "external-file refresh retained its owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_adc_external_url_and_sts_use_the_admitted_owner() -> Result<(), Box<dyn std::error::Error>>
{
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_EXTERNAL_URL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::external::native_adc_external_url_and_sts_use_the_admitted_owner"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated external-url ADC test failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"http://127.0.0.1:9/sts","credential_source":{"url":"http://127.0.0.1:9/subject","headers":{"x-native-subject":"native-header-canary"},"format":{"type":"json","subject_token_field_name":"credential"}}}"#.to_vec()),
            allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"credential":"native-subject-canary"}"#.to_vec())
                },
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"access_token":"native-external-canary","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#.to_vec())
                },
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let token = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await??;
        assert_eq!(token.token, "native-external-canary");
        assert_eq!(native.reads.load(Ordering::SeqCst), 1);
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 2);
        assert_eq!(native.spawn_attempts.load(Ordering::SeqCst), 1);
        drop(token); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "external-url refresh retained its owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_adc_external_executable_and_sts_use_the_admitted_owner()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_EXTERNAL_EXECUTABLE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::external::native_adc_external_executable_and_sts_use_the_admitted_owner"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .env("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1")
            .status()?;
        assert!(
            status.success(),
            "isolated external-executable ADC test failed"
        );
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"http://127.0.0.1:9/sts","credential_source":{"executable":{"command":"/fictional/native-helper --credential","timeout_millis":1000}}}"#.to_vec()),
            execute_output: Some(br#"{"version":1,"success":true,"token_type":"urn:ietf:params:oauth:token-type:jwt","id_token":"native-executable-canary","expiration_time":4102444800}"#.to_vec()), allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"access_token":"native-external-canary","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#.to_vec())
                },
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let token = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await??;
        assert_eq!(token.token, "native-external-canary");
        assert_eq!(native.reads.load(Ordering::SeqCst), 1);
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 1);
        assert_eq!(native.execute_calls.load(Ordering::SeqCst), 1);
        assert_eq!(native.spawn_attempts.load(Ordering::SeqCst), 1);
        drop(token); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "external-executable refresh retained its owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_adc_external_aws_federation_uses_admitted_hash_and_hmac()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_EXTERNAL_AWS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::external::native_adc_external_aws_federation_uses_admitted_hash_and_hmac"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .env("AWS_REGION", "us-east-1").env("AWS_ACCESS_KEY_ID", "native-access-key-canary")
            .env("AWS_SECRET_ACCESS_KEY", "native-secret-key-canary").env("AWS_SESSION_TOKEN", "native-session-canary")
            .status()?;
        assert!(status.success(), "isolated external-AWS ADC test failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider","subject_token_type":"urn:ietf:params:aws:token-type:aws4_request","token_url":"http://127.0.0.1:9/sts","credential_source":{"environment_id":"aws1","region_url":"http://127.0.0.1:9/region","url":"http://127.0.0.1:9/role","regional_cred_verification_url":"https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"}}"#.to_vec()),
            allow_crypto: true, allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"access_token":"native-external-canary","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#.to_vec())
                },
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let token = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await??;
        assert_eq!(token.token, "native-external-canary");
        assert_eq!(native.reads.load(Ordering::SeqCst), 1);
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 1);
        assert_eq!(native.hash_calls.load(Ordering::SeqCst), 2);
        assert_eq!(native.hmac_calls.load(Ordering::SeqCst), 5);
        assert_eq!(native.spawn_attempts.load(Ordering::SeqCst), 1);
        drop(token); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "external-AWS refresh retained its owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_adc_external_sts_and_iam_share_the_admitted_owner()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_EXTERNAL_IAM_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::external::native_adc_external_sts_and_iam_share_the_admitted_owner"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated external-IAM ADC test failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let native = Arc::new(RejectedNativeAdc {
            adc: Some(br#"{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"http://127.0.0.1:9/sts","credential_source":{"file":"/fictional/native-subject"},"service_account_impersonation_url":"http://127.0.0.1:9/v1/projects/-/serviceAccounts/native@example.invalid:generateAccessToken"}"#.to_vec()),
            subject: Some(b"native-subject-canary".to_vec()), allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"access_token":"native-external-canary","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#.to_vec())
                },
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"accessToken":"native-iam-canary","expireTime":"2100-01-01T00:00:00Z"}"#.to_vec())
                },
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone()).build_access_token_credentials()?;
        let token = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await??;
        assert_eq!(token.token, "native-iam-canary");
        assert_eq!(native.reads.load(Ordering::SeqCst), 2);
        assert_eq!(native.http_calls.load(Ordering::SeqCst), 2);
        assert_eq!(native.spawn_attempts.load(Ordering::SeqCst), 1);
        drop(token); drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "external-IAM refresh retained its owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
