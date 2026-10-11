use super::*;

#[test]
fn managed_hsm_identity_rejects_other_services_and_noncanonical_versions() {
    let version = "0123456789abcdef0123456789abcdef";
    for locator in [
        format!("https://fixture.vault.azure.net/keys/root/{version}"),
        format!("https://attacker.example/keys/root/{version}"),
        format!("https://fixture.managedhsm.azure.net:443/keys/root/{version}"),
        format!("https://fixture.managedhsm.azure.net/keys/../{version}"),
        format!("https://fixture.managedhsm.azure.net/keys/root%2fother/{version}"),
    ] {
        assert!(ProviderKeyUri::new(ProviderFamily::AzureManagedHsm, &locator, version).is_err());
    }
}

#[test]
fn managed_hsm_native_app_service_uses_hsm_audience_and_releases_custody()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::{AzureManagedHsmKeyProvider, KeyProviderFailure};
    use std::io::{Read, Write};
    const CHILD: &str = "POSITRON_TEST_HSM_APP_SERVICE_CHILD";
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
            assert!(head.contains("resource=https%3A%2F%2Fmanagedhsm.azure.net"));
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
                "azure::hsm::managed_hsm_native_app_service_uses_hsm_audience_and_releases_custody",
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
        provider_authority(&root, AzureManagedHsmKeyProvider::required_resources())?;
    let governor = authority.governor();
    let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
        tenant,
        positron_kernel::WorkKind::SecurityLifecycle,
        AzureManagedHsmKeyProvider::required_resources(),
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
            ProviderFamily::AzureManagedHsm,
            "https://fixture.managedhsm.azure.net/keys/root/0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        )?;
        let provider =
            AzureManagedHsmKeyProvider::from_managed_identity(identity, None, grant).await?;
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
fn managed_hsm_workload_identity_admission_and_service_separation_release_custody()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::{
        AzureKeyVaultKeyProvider, AzureManagedHsmKeyProvider, AzureWorkloadIdentity,
        CredentialFileReference, KeyProviderFailure,
    };
    const CHILD: &str = "POSITRON_TEST_HSM_WORKLOAD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = Root::new()?;
        let status=std::process::Command::new(std::env::current_exe()?).args(["--exact","azure::hsm::managed_hsm_workload_identity_admission_and_service_separation_release_custody","--nocapture"]).env_clear().envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value|("LLVM_PROFILE_FILE",value))).env(CHILD,"1").env("HOME",&root.0).env("PATH","/usr/bin:/bin").status()?;
        assert!(status.success(), "isolated HSM workload custody failed");
        return Ok(());
    }
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, AzureManagedHsmKeyProvider::required_resources())?;
    let governor = authority.governor();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let token = root.0.join("projected-hsm-token");
    std::fs::write(&token, b"fictional-hsm-projected-secret")?;
    let id = || {
        ProviderKeyUri::new(
            ProviderFamily::AzureManagedHsm,
            "https://fixture.managedhsm.azure.net/keys/root/0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        )
    };
    let grant = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            AzureManagedHsmKeyProvider::required_resources(),
        )?)?)
    };
    let selectors = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(AzureWorkloadIdentity {
            tenant_id: Some("00000000-0000-0000-0000-000000000001".to_owned()),
            client_id: Some("fixture-hsm-client".to_owned()),
            token_file: Some(CredentialFileReference::new(&token)?),
        })
    };
    runtime.block_on(async {
        let provider =
            AzureManagedHsmKeyProvider::from_workload_identity(id()?, selectors()?, grant()?)
                .await?;
        assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
        drop(provider);
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        let rejected =
            AzureKeyVaultKeyProvider::from_workload_identity(id()?, selectors()?, grant()?)
                .await
                .err()
                .ok_or("vault accepted HSM identity")?;
        assert_eq!(rejected, KeyProviderFailure::InvalidConfiguration);
        let vault = ProviderKeyUri::new(
            ProviderFamily::AzureKeyVault,
            "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
        )?;
        let rejected = AzureManagedHsmKeyProvider::from_managed_identity(vault, None, grant()?)
            .await
            .err()
            .ok_or("HSM accepted vault identity")?;
        assert_eq!(rejected, KeyProviderFailure::InvalidConfiguration);
        std::fs::write(&token, vec![b'a'; 131073])?;
        let rejected =
            AzureManagedHsmKeyProvider::from_workload_identity(id()?, selectors()?, grant()?)
                .await
                .err()
                .ok_or("oversized HSM token accepted")?;
        assert_eq!(rejected, KeyProviderFailure::LimitExceeded);
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[test]
fn managed_hsm_canonical_cloud_endpoints_preserve_exact_version()
-> Result<(), Box<dyn std::error::Error>> {
    let version = "0123456789abcdef0123456789abcdef";
    for suffix in [
        "managedhsm.azure.net",
        "managedhsm.azure.cn",
        "managedhsm.usgovcloudapi.net",
    ] {
        let locator = format!("https://fixture.{suffix}/keys/root/{version}");
        let identity = ProviderKeyUri::new(ProviderFamily::AzureManagedHsm, &locator, version)?;
        assert_eq!(identity.locator(), locator);
        assert_eq!(identity.version(), version);
        assert!(
            ProviderKeyUri::new(
                ProviderFamily::AzureManagedHsm,
                &locator,
                "1123456789abcdef0123456789abcdef"
            )
            .is_err()
        );
    }
    Ok(())
}
