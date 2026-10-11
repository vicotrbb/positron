use super::*;

#[test]
fn native_adc_refuses_a_background_refresh_without_admitted_task_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_TASK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_refuses_a_background_refresh_without_admitted_task_capacity"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated native ADC task test failed");
        return Ok(());
    }
    let native = Arc::new(RejectedNativeAdc {
        authorized_user: true,
        ..RejectedNativeAdc::default()
    });
    let result = google_cloud_auth::credentials::Builder::default()
        .with_native_runtime(native.clone())
        .build_access_token_credentials();
    assert!(result.is_err(), "unadmitted native refresh was accepted");
    assert_eq!(native.reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn native_adc_uses_the_admitted_file_boundary_without_ambient_identity()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_ADC_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_uses_the_admitted_file_boundary_without_ambient_identity"])
            .env(CHILD, "1")
            .env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated native ADC test failed");
        return Ok(());
    }
    let native = Arc::new(RejectedNativeAdc::default());
    let result = google_cloud_auth::credentials::Builder::default()
        .with_native_runtime(native.clone())
        .build_access_token_credentials();
    assert!(result.is_err());
    assert_eq!(native.reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn native_adc_redacts_unrecognized_credential_material() -> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_REDACTION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_redacts_unrecognized_credential_material"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/native-adc.json").status()?;
        assert!(status.success());
        return Ok(());
    }
    let native = Arc::new(RejectedNativeAdc {
        adc: Some(br#"{"type":"native-secret-canary"}"#.to_vec()),
        ..RejectedNativeAdc::default()
    });
    let result = google_cloud_auth::credentials::Builder::default()
        .with_native_runtime(native)
        .build_access_token_credentials();
    let error = result.err().ok_or("unknown native credential accepted")?;
    assert!(!format!("{error:?} {error}").contains("canary"));
    Ok(())
}

#[test]
fn native_adc_refuses_amplification_before_creating_a_refresh_task()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_AMPLIFICATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_refuses_amplification_before_creating_a_refresh_task"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/native-adc.json").status()?;
        assert!(status.success());
        return Ok(());
    }
    let adc = serde_json::json!({"type":"authorized_user","client_id":"native-client","client_secret":"native-secret-canary","refresh_token":"native-refresh-canary","padding":vec![false; 2049]});
    let native = Arc::new(RejectedNativeAdc {
        adc: Some(serde_json::to_vec(&adc)?),
        ..RejectedNativeAdc::default()
    });
    assert!(
        google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone())
            .build_access_token_credentials()
            .is_err()
    );
    assert_eq!(
        native.spawn_attempts.load(Ordering::SeqCst),
        0,
        "oversized native structure reached task admission"
    );
    Ok(())
}

#[test]
fn native_admitted_adc_builder_refuses_the_general_signer_surface()
-> Result<(), Box<dyn std::error::Error>> {
    let native = Arc::new(RejectedNativeAdc::default());
    assert!(
        google_cloud_auth::credentials::Builder::default()
            .with_native_runtime(native.clone())
            .build_signer()
            .is_err()
    );
    assert_eq!(
        native.reads.load(Ordering::SeqCst),
        0,
        "unsupported native signer consumed identity input"
    );
    Ok(())
}

#[test]
fn native_adc_refuses_duplicate_secret_fields_before_task_admission()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_DUPLICATE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/fictional/positron-native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_refuses_duplicate_secret_fields_before_task_admission"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .status()?;
        assert!(status.success(), "isolated duplicate-field test failed");
        return Ok(());
    }
    let native = Arc::new(RejectedNativeAdc {
        adc: Some(br#"{"type":"authorized_user","client_id":"native-client","client_secret":"native-original-canary","client_secret":"native-replacement-canary","refresh_token":"native-refresh-canary"}"#.to_vec()),
        ..RejectedNativeAdc::default()
    });
    let error = google_cloud_auth::credentials::Builder::default()
        .with_native_runtime(native.clone())
        .build_access_token_credentials()
        .expect_err("ambiguous secret fields must be refused");
    assert_eq!(native.spawn_attempts.load(Ordering::SeqCst), 0);
    assert!(!format!("{error:?} {error}").contains("canary"));
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut native_error = None;
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<google_cloud_auth::native::Error>() {
            native_error = Some(*error);
            break;
        }
        source = current.source();
    }
    assert_eq!(
        native_error,
        Some(google_cloud_auth::native::Error::InvalidConfiguration)
    );
    Ok(())
}

#[test]
fn native_adc_rejects_overflowing_token_lifetimes_with_a_typed_error()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_TTL_CHILD";
    let Some(kind) = std::env::var_os(CHILD) else {
        for kind in ["oauth", "metadata", "sts"] {
            let mut command = isolated_child()?;
            command
                .env("PATH", "/usr/bin:/bin").env("HOME", "/fictional/native-home").args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_rejects_overflowing_token_lifetimes_with_a_typed_error"])
                .env(CHILD, kind).env("GCE_METADATA_HOST", "127.0.0.1:9");
            if kind == "metadata" {
                command
                    .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
                    .env("HOME", "/fictional/native-home");
            } else {
                command.env(
                    "GOOGLE_APPLICATION_CREDENTIALS",
                    "/fictional/positron-native-adc.json",
                );
            }
            assert!(
                command.status()?.success(),
                "isolated {kind} token TTL test failed"
            );
        }
        return Ok(());
    };
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let kind = kind.to_string_lossy();
        let external = br#"{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pool/providers/provider","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"http://127.0.0.1:9/sts","credential_source":{"file":"/fictional/native-subject"}}"#;
        let native = Arc::new(RejectedNativeAdc {
            adc: (kind == "sts").then(|| external.to_vec()),
            authorized_user: kind == "oauth", file_absent: kind == "metadata",
            subject: Some(b"native-subject-canary".to_vec()), allow_tasks: true,
            wire: std::sync::Mutex::new(std::collections::VecDeque::from([
                google_cloud_auth::native::Response {
                    status: http::StatusCode::OK, headers: http::HeaderMap::new(),
                    body: Zeroizing::new(br#"{"access_token":"native-access-canary","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":18446744073709551615}"#.to_vec())
                },
            ])),
            ..RejectedNativeAdc::default()
        });
        let credentials = google_cloud_auth::credentials::Builder::default().with_native_runtime(native.clone()).build_access_token_credentials()?;
        let error = tokio::time::timeout(std::time::Duration::from_millis(500), credentials.access_token()).await?
            .expect_err("overflowing native token TTL must fail");
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut native_error = None;
        while let Some(current) = source {
            if let Some(error) = current.downcast_ref::<google_cloud_auth::native::Error>() { native_error = Some(*error); break; }
            source = current.source();
        }
        assert_eq!(native_error, Some(google_cloud_auth::native::Error::InvalidConfiguration));
        drop(credentials);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while native.tasks.load(Ordering::SeqCst) != 0 {
            assert!(std::time::Instant::now() < deadline, "invalid-TTL refresh retained its owner after drop");
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn native_adc_bounds_the_complete_background_refresh_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_TEST_GOOGLE_NATIVE_REFRESH_DEADLINE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin").env("HOME", "/fictional/native-home")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_bounds_the_complete_background_refresh_deadline"])
            .env(CHILD, "1").env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/native-adc.json").status()?;
        assert!(status.success(), "isolated native refresh deadline failed");
        return Ok(());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::pause();
            let native = Arc::new(RejectedNativeAdc {
                authorized_user: true,
                allow_tasks: true,
                pending_http: true,
                ..RejectedNativeAdc::default()
            });
            let credentials = google_cloud_auth::credentials::Builder::default()
                .with_native_runtime(native.clone())
                .build_access_token_credentials()?;
            let error = tokio::time::timeout(Duration::from_secs(16), credentials.access_token())
                .await
                .expect("native refresh exceeded fifteen seconds")
                .expect_err("pending identity returned a token");
            assert_eq!(
                source_failure(&error),
                Some(KeyProviderFailure::Unavailable)
            );
            assert_eq!(native.http_calls.load(Ordering::SeqCst), 1);
            drop(credentials);
            let cleanup = std::time::Instant::now() + Duration::from_secs(1);
            while native.tasks.load(Ordering::SeqCst) != 0 {
                assert!(
                    std::time::Instant::now() < cleanup,
                    "native refresh owner failed to terminate"
                );
                tokio::task::yield_now().await;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
}
#[test]
fn native_adc_refuses_oversized_quota_project_before_cache_admission()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_NATIVE_QUOTA_ENV_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin").env("HOME", "/fictional/positron-native-home")
            .env("GOOGLE_APPLICATION_CREDENTIALS", "/fictional/positron-native-adc.json")
            .env("GOOGLE_CLOUD_QUOTA_PROJECT", "x".repeat(4097))
            .env(CHILD, "1")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_refuses_oversized_quota_project_before_cache_admission"])
            .status()?;
        assert!(
            status.success(),
            "isolated native environment refusal failed"
        );
        return Ok(());
    }
    let native = Arc::new(RejectedNativeAdc {
        authorized_user: true,
        ..RejectedNativeAdc::default()
    });
    let error = google_cloud_auth::credentials::Builder::default()
        .with_native_runtime(native.clone())
        .build_access_token_credentials()
        .expect_err("oversized native environment input accepted");
    assert_eq!(
        source_failure(&error),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(
        native.spawn_attempts.load(Ordering::SeqCst),
        0,
        "oversized native environment input was copied into an admitted provider"
    );
    Ok(())
}

#[test]
fn native_adc_refuses_oversized_metadata_host_before_cache_admission()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_NATIVE_MDS_ENV_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = isolated_child()?
            .env("PATH", "/usr/bin:/bin").env("HOME", "/fictional/positron-native-home")

            .env("GCE_METADATA_HOST", "x".repeat(4097))
            .env(CHILD, "1")
            .args(["--exact", "data_protection::key_provider::google::tests::adc::validation::native_adc_refuses_oversized_metadata_host_before_cache_admission"])
            .status()?;
        assert!(
            status.success(),
            "isolated native environment refusal failed"
        );
        return Ok(());
    }
    let native = Arc::new(RejectedNativeAdc {
        file_absent: true,
        ..RejectedNativeAdc::default()
    });
    let error = google_cloud_auth::credentials::Builder::default()
        .with_native_runtime(native.clone())
        .build_access_token_credentials()
        .expect_err("oversized native environment input accepted");
    assert_eq!(
        source_failure(&error),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(
        native.spawn_attempts.load(Ordering::SeqCst),
        0,
        "oversized native environment input was copied into an admitted provider"
    );
    Ok(())
}
