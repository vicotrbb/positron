use super::*;

#[test]
fn azure_key_vault_identity_rejects_non_vault_routing() {
    let version = "0123456789abcdef0123456789abcdef";
    for locator in [
        format!("https://vault.managedhsm.azure.net/keys/root/{version}"),
        format!("https://attacker.example/keys/root/{version}"),
        format!("https://vault.vault.azure.net:8443/keys/root/{version}"),
        format!("https://vault.vault.azure.net/keys/../{version}"),
        format!("https://vault.vault.azure.net/keys/root%2fother/{version}"),
    ] {
        assert!(ProviderKeyUri::new(ProviderFamily::AzureKeyVault, &locator, version).is_err());
    }
}

#[test]
fn azure_native_identity_is_admitted_before_files_and_releases_custody()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::{
        AzureKeyVaultKeyProvider, AzureWorkloadIdentity, CredentialFileReference,
        KeyProviderFailure,
    };
    const CHILD: &str = "POSITRON_TEST_AZURE_IDENTITY_INTEGRATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = Root::new()?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "azure::azure_native_identity_is_admitted_before_files_and_releases_custody",
                "--nocapture",
            ])
            .env_clear()
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)))
            .env(CHILD, "1")
            .env("HOME", &root.0)
            .env("PATH", "/usr/bin:/bin")
            .status()?;
        assert!(status.success(), "isolated Azure native custody failed");
        return Ok(());
    }
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, AzureKeyVaultKeyProvider::required_resources())?;
    let governor = authority.governor();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let token = root.0.join("projected-token");
    std::fs::write(&token, b"fictional-projected-native-secret")?;
    let alias = root.0.join("projected-token-reference");
    std::os::unix::fs::symlink(&token, &alias)?;
    let identity = || {
        ProviderKeyUri::new(
            ProviderFamily::AzureKeyVault,
            "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        )
    };
    let grant = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            AzureKeyVaultKeyProvider::required_resources(),
        )?)?)
    };
    let events = std::sync::Arc::new(std::sync::Mutex::new(
        zeroize::Zeroizing::new(String::new()),
    ));
    tracing::subscriber::set_global_default(IdentityEvents(events.clone()))?;
    runtime.block_on(async {
        let provider = AzureKeyVaultKeyProvider::from_workload_identity(identity()?, AzureWorkloadIdentity { tenant_id: Some("00000000-0000-0000-0000-000000000001".to_owned()), client_id: Some("fixture-client".to_owned()), token_file: Some(CredentialFileReference::new(&alias)?) }, grant()?).await?;
        assert_eq!(governor.inspect()?.outstanding_reservations(),1);
        drop(provider);
        assert_eq!(governor.inspect()?.outstanding_reservations(),0);
        std::fs::write(&token,vec![b'a';131073])?;
        let failure = AzureKeyVaultKeyProvider::from_workload_identity(identity()?, AzureWorkloadIdentity { tenant_id: Some("00000000-0000-0000-0000-000000000001".to_owned()), client_id: Some("fixture-client".to_owned()), token_file: Some(CredentialFileReference::new(&alias)?) }, grant()?).await.err().ok_or("oversized token accepted")?;
        assert_eq!(failure,KeyProviderFailure::LimitExceeded);
        assert_eq!(governor.inspect()?.outstanding_reservations(),0);
        for id in [None, Some(positron_kernel::key_provider::AzureManagedIdentityId::ClientId("fixture-client".to_owned())), Some(positron_kernel::key_provider::AzureManagedIdentityId::ObjectId("fixture-object".to_owned())), Some(positron_kernel::key_provider::AzureManagedIdentityId::ResourceId("/subscriptions/fixture/resourceGroups/fixture/providers/Microsoft.ManagedIdentity/userAssignedIdentities/fixture".to_owned()))] {
            let provider = AzureKeyVaultKeyProvider::from_managed_identity(identity()?, id, grant()?).await?;
            drop(provider);
            assert_eq!(governor.inspect()?.outstanding_reservations(),0);
        }
        assert!(!events.lock().map_err(|_| "event capture poisoned")?.contains("secret"));
        Ok::<(),Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[test]
fn azure_app_service_native_http_rejection_is_bounded_and_secret_free()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::{AzureKeyVaultKeyProvider, KeyProviderFailure};
    use std::io::{Read, Write};
    const CHILD: &str = "POSITRON_TEST_AZURE_APP_SERVICE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = Root::new()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "identity transcript was not requested",
                        ));
                    },
                    Err(error) => return Err(error),
                }
            };
            socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte)?;
                head.extend_from_slice(&byte);
                assert!(head.len() < 4096);
            }
            let head = String::from_utf8(head).map_err(std::io::Error::other)?;
            assert!(head.contains("x-identity-header: fictional-secret-header"));
            assert!(head.contains("resource=https%3A%2F%2Fvault.azure.net"));
            let body = b"native-secret-response-canary";
            socket.write_all(
                format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )?;
            socket.write_all(body)?;
            Ok(())
        });
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "azure::azure_app_service_native_http_rejection_is_bounded_and_secret_free",
                "--nocapture",
            ])
            .env_clear()
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)))
            .env(CHILD, "1")
            .env("HOME", &root.0)
            .env("PATH", "/usr/bin:/bin")
            .env(
                "IDENTITY_ENDPOINT",
                format!("http://{address}/metadata/identity/oauth2/token"),
            )
            .env("IDENTITY_HEADER", "fictional-secret-header")
            .status()?;
        server
            .join()
            .map_err(|_| "native HTTP fixture panicked")??;
        assert!(status.success(), "isolated App Service identity failed");
        return Ok(());
    }
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, AzureKeyVaultKeyProvider::required_resources())?;
    let governor = authority.governor();
    let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
        tenant,
        positron_kernel::WorkKind::SecurityLifecycle,
        AzureKeyVaultKeyProvider::required_resources(),
    )?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let events = std::sync::Arc::new(std::sync::Mutex::new(
        zeroize::Zeroizing::new(String::new()),
    ));
    tracing::subscriber::set_global_default(IdentityEvents(events.clone()))?;
    runtime.block_on(async {
        let identity = ProviderKeyUri::new(
            ProviderFamily::AzureKeyVault,
            "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        )?;
        let provider =
            AzureKeyVaultKeyProvider::from_managed_identity(identity, None, grant).await?;
        let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
        let error = provider
            .create_envelope(context)
            .await
            .err()
            .ok_or("rejected native identity accepted")?;
        assert_eq!(error, KeyProviderFailure::PermissionDenied);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(
            !events
                .lock()
                .map_err(|_| "capture poisoned")?
                .contains("secret")
        );
        drop(provider);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while governor.inspect()?.outstanding_reservations() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "native connection retained grant"
            );
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[test]
fn azure_native_source_rejects_oversized_presence_before_http()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::{AzureKeyVaultKeyProvider, KeyProviderFailure};
    const CHILD: &str = "POSITRON_TEST_AZURE_SOURCE_ADMISSION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = Root::new()?;
        for key in [
            "IDENTITY_ENDPOINT",
            "IDENTITY_HEADER",
            "MSI_SECRET",
            "MSI_SECRET_NORMAL",
        ] {
            let mut command = std::process::Command::new(std::env::current_exe()?);
            command
                .args([
                    "--exact",
                    "azure::azure_native_source_rejects_oversized_presence_before_http",
                    "--nocapture",
                ])
                .env_clear()
                .envs(
                    std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)),
                )
                .env(CHILD, key)
                .env("HOME", &root.0)
                .env("PATH", "/usr/bin:/bin")
                .env(key, "fictional-secret".repeat(600));
            if key.starts_with("MSI_SECRET") {
                command.env(
                    "MSI_ENDPOINT",
                    "http://127.0.0.1:9/metadata/identity/oauth2/token",
                );
                if key == "MSI_SECRET_NORMAL" {
                    command.env("MSI_SECRET", "fictional-secret");
                }
            } else {
                command.env(
                    "IDENTITY_ENDPOINT",
                    "http://127.0.0.1:9/metadata/identity/oauth2/token",
                );
            }
            if key == "IDENTITY_ENDPOINT" {
                command.env(key, "fictional-secret".repeat(600));
            }
            let status = command.status()?;
            assert!(
                status.success(),
                "oversized native source {key} was accepted"
            );
        }
        return Ok(());
    }
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, AzureKeyVaultKeyProvider::required_resources())?;
    let governor = authority.governor();
    let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
        tenant,
        positron_kernel::WorkKind::SecurityLifecycle,
        AzureKeyVaultKeyProvider::required_resources(),
    )?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let identity = ProviderKeyUri::new(
            ProviderFamily::AzureKeyVault,
            "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        )?;
        let sdk_error = azure_identity::ManagedIdentityCredential::new(None)
            .err()
            .ok_or("SDK selected an identity after admission rejection")?;
        let expected = if std::env::var(CHILD)? == "MSI_SECRET_NORMAL" {
            "Azure ML managed identity isn't supported"
        } else {
            "native identity selector exceeds admission"
        };
        assert!(
            sdk_error.to_string().contains(expected),
            "SDK changed identity source: {sdk_error}"
        );
        let error = AzureKeyVaultKeyProvider::from_managed_identity(identity, None, grant)
            .await
            .err()
            .ok_or("oversized source silently selected IMDS")?;
        assert_eq!(error, KeyProviderFailure::InvalidConfiguration);
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn azure_selected_app_service_remote_endpoint_is_rejected_before_http()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::{AzureKeyVaultKeyProvider, KeyProviderFailure};
    const CHILD: &str = "POSITRON_TEST_AZURE_REMOTE_ENDPOINT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = Root::new()?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "azure::azure_selected_app_service_remote_endpoint_is_rejected_before_http",
                "--nocapture",
            ])
            .env_clear()
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)))
            .env(CHILD, "1")
            .env("HOME", &root.0)
            .env("PATH", "/usr/bin:/bin")
            .env("IDENTITY_ENDPOINT", "http://192.0.2.1:8081/token")
            .env("IDENTITY_HEADER", "fictional-secret")
            .status()?;
        assert!(status.success(), "remote native endpoint accepted");
        return Ok(());
    }
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, AzureKeyVaultKeyProvider::required_resources())?;
    let governor = authority.governor();
    let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
        tenant,
        positron_kernel::WorkKind::SecurityLifecycle,
        AzureKeyVaultKeyProvider::required_resources(),
    )?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let identity = ProviderKeyUri::new(
            ProviderFamily::AzureKeyVault,
            "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        )?;
        let error = AzureKeyVaultKeyProvider::from_managed_identity(identity, None, grant)
            .await
            .err()
            .ok_or("remote endpoint accepted")?;
        assert_eq!(error, KeyProviderFailure::InvalidConfiguration);
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
