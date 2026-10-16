#![cfg(feature = "test-support")]
#[path = "shared/azure_admission.rs"]
mod azure_admission;
#[path = "shared/azure_simulator.rs"]
mod azure_simulator;
#[path = "shared/native_authority.rs"]
mod native_authority;
#[path = "shared/provider_behavior.rs"]
mod provider_behavior;
#[path = "shared/read_only_repository.rs"]
mod read_only_repository;
use positron_backup::*;
use positron_kernel::*;
#[tokio::test]
async fn native_azure_repository_protocol_and_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let server = azure_simulator::Server::start()?;
    azure_admission::admitted(
        AzureBlobRepository::required_resources(),
        move |resources| async move {
            let target = AzureBlobTarget::new("positronbackup", "backups", "owned/")?;
            let identity = RepositoryIdentity::azure_blob([1; 16], [2; 16], [3; 32], &target)?;
            let custody = || {
                RepositoryUploadAuthenticator::new(
                    CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
                    InstanceId::new([2; 16]).expect("instance"),
                )
            };
            let repository = AzureBlobRepository::from_local_simulator(
                target.clone(),
                identity.clone(),
                resources.clone(),
                custody(),
                server.address,
            )?;
            repository
                .initialize()
                .await
                .map_err(|e| format!("initialize: {e:?}"))?;
            let read_only = AzureBlobRepository::read_only_from_local_simulator(target.clone(), identity.clone(), resources.clone(), server.address)?;
            assert_eq!(read_only.initialize().await, Err(RepositoryFailure::PermissionDenied));
            read_only_repository::conformance(&read_only, &repository).await?;
            provider_behavior::conformance(
                &repository,
                identity.clone(),
                std::time::Duration::from_secs(60),
            )
            .await
            .map_err(|e| format!("shared conformance: {e}"))?;
            let encrypted = ImmutableObject::new(vec![47; 4 * 1024 * 1024 + 31])?;
            let state = repository
                .begin_upload(UploadPlan::new(
                    encrypted.id(),
                    encrypted.bytes().len() as u64,
                )?)
                .await?;
            let first = repository
                .resume_upload(UploadPart::new(
                    state,
                    encrypted.bytes()[..4 * 1024 * 1024].to_vec(),
                )?)
                .await?;
            let UploadOutcome::Pending(state) = first else {
                panic!("partial upload")
            };
            drop(repository);
            let repository = AzureBlobRepository::from_local_simulator(
                target.clone(),
                identity.clone(),
                resources.clone(),
                custody(),
                server.address,
            )?;
            assert_eq!(repository.inspect_upload(state.id()).await?, Some(state));
            assert!(matches!(
                repository
                    .resume_upload(UploadPart::new(
                        state,
                        encrypted.bytes()[4 * 1024 * 1024..].to_vec()
                    )?)
                    .await?,
                UploadOutcome::Complete(_)
            ));
            assert_eq!(
                repository.head(encrypted.id()).await?.size(),
                encrypted.bytes().len() as u64
            );
            repository.delete(encrypted.id()).await?;
        let wrong_identity=RepositoryIdentity::azure_blob([99;16],[2;16],[3;32],&target)?;
        let wrong=AzureBlobRepository::from_local_simulator(target.clone(),wrong_identity,resources.clone(),custody(),server.address)?;
        assert_eq!(wrong.attach().await,Err(RepositoryFailure::IdentityMismatch));
        assert_eq!(wrong.initialize().await,Err(RepositoryFailure::IdentityMismatch));
        assert_eq!(repository.attach().await?,identity);
        let partial=ImmutableObject::new(b"bounded partial abort".to_vec())?;
        let partial_state=repository.begin_upload(UploadPlan::new(partial.id(),partial.bytes().len() as u64)?).await?;
        let partial_state=match repository.resume_upload(UploadPart::new(partial_state,vec![b'b'])?).await?{UploadOutcome::Pending(state)=>state,_=>panic!("partial state")};
        let wrong_custody=AzureBlobRepository::from_local_simulator(target.clone(),identity.clone(),resources.clone(),RepositoryUploadAuthenticator::new(CatalogSecret::from_owned(Box::new([1;32]),Box::new([32;32])),InstanceId::new([2;16])?),server.address)?;
        assert_eq!(wrong_custody.inspect_upload(partial_state.id()).await,Err(RepositoryFailure::ChecksumMismatch));
        repository.abort_upload(partial_state.id()).await?;
        assert!(repository.inspect_upload(partial_state.id()).await?.is_none());
        let empty=ImmutableObject::new(Vec::new())?;repository.put_if_absent(empty.clone()).await?;
        assert!(repository.read_range(ObjectRange::new(empty.id(),0,0)?).await?.bytes().is_empty());
        repository.delete(empty.id()).await?;
        use azure_simulator::Action;
        let inject=|method:&str,path:String,action:Action| {server.rules.lock().expect("fixture rule").push_back((method.into(),path,action));};
        let name=|id:ObjectId|format!("/backups/owned/o-{}",id.checksum().iter().map(|b|format!("{b:02x}")).collect::<String>());
        let object=ImmutableObject::new(b"native Azure fault identity".to_vec())?;
        repository.put_if_absent(object.clone()).await?;
        inject("GET","/backups/?restype=container&comp=list".into(),Action::Status(200,String::new(),b"<EnumerationResults><Blobs/><NextMarker/></EnumerationResults>".to_vec()));
        assert!(repository.list(ListRequest::new(ListKind::Objects,None,1)?).await?.entries().is_empty());
        assert_eq!(repository.head(object.id()).await?.checksum(),object.id().checksum());
        inject("GET",name(object.id()),Action::CorruptBody);
        assert_eq!(repository.head(object.id()).await,Err(RepositoryFailure::ChecksumMismatch));
        inject("HEAD",name(object.id()),Action::CorruptMd5);
        assert_eq!(repository.head(object.id()).await,Err(RepositoryFailure::ChecksumMismatch));
        inject("HEAD",name(object.id()),Action::Status(429,"x-ms-retry-after-ms: 999999999\r\n".into(),b"secret credential canary".to_vec()));
        let failure=repository.head(object.id()).await.expect_err("throttle");
        assert_eq!(failure,RepositoryFailure::Throttled{retry_after_millis:60000});
        assert!(!format!("{failure:?}").contains("canary"));
        inject("HEAD",name(object.id()),Action::Status(403,String::new(),Vec::new()));
        assert_eq!(repository.head(object.id()).await,Err(RepositoryFailure::PermissionDenied));
        let unknown=ImmutableObject::new(b"native Azure uncertain put".to_vec())?;
        inject("PUT",name(unknown.id()),Action::DropAfter);
        assert_eq!(repository.put_if_absent(unknown.clone()).await?,PutOutcome::AlreadyPresent);
        repository.delete(unknown.id()).await?;
        let slot=HeadSlot::from_checksum([81;32]);let source=HeadSlot::from_checksum([82;32]);
        let old=match repository.compare_and_swap_head_at(slot,RegistryHeadChange::new(None,b"old signed head".to_vec())?).await?{CasOutcome::Published(v)=>v,_=>panic!("head")};
        let successor=match repository.compare_and_swap_head_at(source,RegistryHeadChange::new(None,b"independent signed successor".to_vec())?).await?{CasOutcome::Published(v)=>v,_=>panic!("source")};
        let head_path=format!("/backups/owned/h-{}","51".repeat(32));
        inject("GET",head_path.clone(),Action::Race(format!("owned/h-{}","52".repeat(32))));
        assert_eq!(repository.compare_and_swap_head_at(slot,RegistryHeadChange::new(Some(old),b"losing head".to_vec())?).await?,CasOutcome::Conflict(Some(successor)));
        inject("GET",head_path,Action::Race(format!("owned/h-{}","52".repeat(32))));
        assert_eq!(repository.delete_head_if_version(slot,successor).await,Err(RepositoryFailure::PreconditionFailed));
        assert_eq!(repository.registry_head_at(slot).await?.expect("successor").version(),successor);
        repository.delete_head_if_version(slot,successor).await?;
        repository.delete_head_if_version(source,successor).await?;
        let interrupted=ImmutableObject::new(b"native Azure interrupted blocks".to_vec())?;
        let plan=UploadPlan::new(interrupted.id(),interrupted.bytes().len() as u64)?;
        let state=repository.begin_upload(plan).await?;
        inject("PUT","/backups/owned/m-".into(),Action::DropAfter);
        assert_eq!(repository.resume_upload(UploadPart::new(state,interrupted.bytes().to_vec())?).await,Err(RepositoryFailure::OutcomeUnknown));
        assert!(repository.begin_upload(plan).await?.complete());
        assert!(repository.inspect_upload(plan.id()).await?.is_none());
        repository.delete(interrupted.id()).await?;
        inject("GET","/backups/?restype=container&comp=list".into(),Action::Status(200,String::new(),format!("<EnumerationResults><Blobs><Blob><Name>owned/o-{}</Name><Deleted>true</Deleted></Blob></Blobs><NextMarker/></EnumerationResults>",object.id().checksum().iter().map(|b|format!("{b:02x}")).collect::<String>()).into_bytes()));
        assert_eq!(repository.delete(object.id()).await,Err(RepositoryFailure::OutcomeUnknown));
        assert!(repository.head(object.id()).await.is_ok());
        inject("DELETE",name(object.id()),Action::DropAfter);
        assert_eq!(repository.delete(object.id()).await,Err(RepositoryFailure::OutcomeUnknown));
        assert_eq!(repository.delete(object.id()).await?,DeleteOutcome::AlreadyAbsent);
        assert_eq!(repository.head(object.id()).await,Err(RepositoryFailure::NotFound));
            Ok(())
        },
    )
    .await
}

/// Optional independent qualification. Ordinary implementation acceptance uses
/// the native protocol simulator above and does not require cloud credentials.
#[tokio::test]
#[ignore = "requires explicitly authorized disposable native Azure target and managed identity"]
async fn azure_real_service_conformance() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("POSITRON_AZURE_QUALIFICATION_AUTHORIZATION")
        .ok()
        .as_deref()
        != Some("explicitly-authorized-disposable-prefix")
    {
        return Err(
            "native Azure qualification requires explicit disposable target authorization".into(),
        );
    }
    let target = AzureBlobTarget::new(
        &std::env::var("POSITRON_AZURE_QUALIFICATION_ACCOUNT")?,
        &std::env::var("POSITRON_AZURE_QUALIFICATION_CONTAINER")?,
        &std::env::var("POSITRON_AZURE_QUALIFICATION_PREFIX")?,
    )?;
    azure_admission::admitted(
        AzureBlobRepository::required_resources(),
        move |resources| async move {
            let identity = RepositoryIdentity::azure_blob([205; 16], [2; 16], [206; 32], &target)?;
            let custody = RepositoryUploadAuthenticator::new(
                CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
                InstanceId::new([2; 16])?,
            );
            let repository = AzureBlobRepository::from_admitted_resources(
                target,
                identity.clone(),
                resources,
                custody,
            )
            .await?;
            repository.initialize().await?;
            provider_behavior::conformance(
                &repository,
                identity,
                std::time::Duration::from_secs(60),
            )
            .await
        },
    )
    .await
}

#[tokio::test]
async fn azure_head_deletion_preserves_successor_created_after_absence()
-> Result<(), Box<dyn std::error::Error>> {
    let server = azure_simulator::Server::start()?;
    azure_admission::admitted(
        AzureBlobRepository::required_resources(),
        move |resources| async move {
            let target = AzureBlobTarget::new("positronbackup", "backups", "owned/")?;
            let identity = RepositoryIdentity::azure_blob([1; 16], [2; 16], [3; 32], &target)?;
            let custody = RepositoryUploadAuthenticator::new(
                CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
                InstanceId::new([2; 16])?,
            );
            let repository = AzureBlobRepository::from_local_simulator(
                target,
                identity,
                resources,
                custody,
                server.address,
            )?;
            repository.initialize().await?;
            let target = HeadSlot::from_checksum([83; 32]);
            let source = HeadSlot::from_checksum([84; 32]);
            let old = match repository
                .compare_and_swap_head_at(
                    target,
                    RegistryHeadChange::new(None, b"original head A".to_vec())?,
                )
                .await?
            {
                CasOutcome::Published(version) => version,
                _ => return Err("head A publication".into()),
            };
            repository.delete_head_if_version(target, old).await?;
            let successor = match repository
                .compare_and_swap_head_at(
                    source,
                    RegistryHeadChange::new(None, b"independent successor B".to_vec())?,
                )
                .await?
            {
                CasOutcome::Published(version) => version,
                _ => return Err("head B publication".into()),
            };
            server.rules.lock().expect("fixture rule").push_back((
                "HEAD".into(),
                format!("/backups/owned/h-{}", "53".repeat(32)),
                azure_simulator::Action::Race(format!("owned/h-{}", "54".repeat(32))),
            ));
            let outcome = repository.delete_head_if_version(target, old).await;
            let visible = repository
                .registry_head_at(target)
                .await?
                .map(|head| head.version());
            assert_eq!(
                visible,
                Some(successor),
                "an absent current head grants no authority to delete its concurrent successor"
            );
            assert_eq!(outcome, Err(RepositoryFailure::PreconditionFailed));
            Ok(())
        },
    )
    .await
}

#[tokio::test]
async fn native_azure_tenant_key_purge_retains_permanent_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let server = azure_simulator::Server::start()?;
    azure_admission::admitted(
        AzureBlobRepository::required_resources(),
        move |resources| async move {
            use std::os::unix::fs::PermissionsExt;
            let directory = tempfile::tempdir()?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            let custody = BootstrapKeyCustody::initialize(directory.path())?;
            let instance = InstanceId::new([2; 16])?;
            let protected =
                custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
            let signer = custody.backup_control_signer(instance, &protected)?;
            let target = AzureBlobTarget::new("positronbackup", "backups", "owned/")?;
            let identity = RepositoryIdentity::azure_blob(
                [1; 16],
                [2; 16],
                signer.identity().fingerprint(),
                &target,
            )?;
            let make = || {
                AzureBlobRepository::from_local_simulator(
                    target.clone(),
                    identity.clone(),
                    resources.clone(),
                    RepositoryUploadAuthenticator::new(
                        CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
                        instance,
                    ),
                    server.address,
                )
            };
            let repository = make()?;
            repository.initialize().await?;
            let ordinary =
                ImmutableObject::new(b"POSBKF01ordinary checksum-addressed content".to_vec())?;
            repository.put_if_absent(ordinary.clone()).await?;
            assert_eq!(
                repository.head(ordinary.id()).await?.size(),
                ordinary.bytes().len() as u64
            );
            repository.delete(ordinary.id()).await?;
            let object = ImmutableObject::new(vec![45; 64])?;
            let key = format!(
                "owned/o-{}",
                object
                    .id()
                    .checksum()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            *server.delayed.target.lock().map_err(|_| "delay lock")? =
                Some(format!("/backups/{key}"));
            let late_repository = make()?;
            let late_object = object.clone();
            let late =
                tokio::spawn(async move { late_repository.put_if_absent(late_object).await });
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !server
                    .delayed
                    .waiting
                    .load(std::sync::atomic::Ordering::Acquire)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            repository.put_if_absent(object.clone()).await?;
            let tombstone = BackupPurgeTombstone::new([3; 16], "default", [9; 16], 10)?;
            let fence = TenantKeyPurgeFence::new(object.id(), &tombstone, &identity, &signer)?;
            server.rules.lock().map_err(|_| "rules lock")?.push_back((
                "PUT".into(),
                format!("/backups/{key}"),
                azure_simulator::Action::Status(503, String::new(), Vec::new()),
            ));
            assert!(
                Repository::delete_tenant_key(&repository, object.id(), &fence)
                    .await
                    .is_err()
            );
            {
                let mut rules = server.rules.lock().map_err(|_| "rules lock")?;
                rules.push_back((
                    "PUT".into(),
                    format!("/backups/{key}"),
                    azure_simulator::Action::DropAfter,
                ));
                rules.push_back((
                    "DELETE".into(),
                    format!("/backups/{key}?"),
                    azure_simulator::Action::Status(503, String::new(), Vec::new()),
                ));
            }
            assert!(
                Repository::delete_tenant_key(&repository, object.id(), &fence)
                    .await
                    .is_err()
            );
            assert_eq!(
                repository.head(object.id()).await,
                Err(RepositoryFailure::NotFound)
            );
            assert_eq!(
                Repository::delete_tenant_key(&repository, object.id(), &fence).await?,
                DeleteOutcome::AlreadyAbsent
            );
            server
                .delayed
                .release
                .store(true, std::sync::atomic::Ordering::Release);
            assert!(late.await?.is_err());
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while server.delayed.status.load(std::sync::atomic::Ordering::Acquire) == 0 {
                    tokio::task::yield_now().await;
                }
            }).await?;
            assert_eq!(
                server
                    .delayed
                    .status
                    .load(std::sync::atomic::Ordering::Acquire),
                412
            );
            assert_eq!(
                repository.head(object.id()).await,
                Err(RepositoryFailure::NotFound)
            );
            assert_eq!(repository.read_range(ObjectRange::new(object.id(), 0, 1)?).await?.bytes(), b"P");
            assert_eq!(repository.read_range(ObjectRange::new(object.id(), 0, fence.bytes().len() as u64)?).await, Err(RepositoryFailure::NotFound));
            assert!(repository.put_if_absent(object.clone()).await.is_err());
            assert!(repository.delete(object.id()).await.is_err());
            assert_eq!(
                Repository::delete_tenant_key(&repository, object.id(), &fence).await?,
                DeleteOutcome::AlreadyAbsent
            );
            // Inspect the independent native inventory after the delayed request;
        // only the permanent nonsecret current value may remain reachable.
        use std::io::{Read, Write};
        let mut inventory=std::net::TcpStream::connect(server.address)?;
        inventory.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        write!(inventory,"GET /backups/?restype=container&comp=list&prefix={key}&maxresults=64&include=versions%2Csnapshots%2Cdeleted%2Cdeletedwithversions%2Cuncommittedblobs HTTP/1.1\r\nHost: localhost\r\nx-ms-version: 2023-11-03\r\nConnection: close\r\n\r\n")?;
        let mut raw=String::new();
        inventory.read_to_string(&mut raw)?;
        assert!(raw.starts_with("HTTP/1.1 200 "));
        assert_eq!(raw.matches("<Blob>").count(),1);
        assert!(!raw.contains("<VersionId>"));
        assert!(!raw.contains("<Snapshot>"));
        let other_tombstone=BackupPurgeTombstone::new([3;16],"default",[10;16],11)?;
        let other_fence=TenantKeyPurgeFence::new(object.id(),&other_tombstone,&identity,&signer)?;
        assert!(Repository::delete_tenant_key(&repository,object.id(),&other_fence).await.is_err());
        assert_eq!(Repository::delete_tenant_key(&repository,object.id(),&fence).await?,DeleteOutcome::AlreadyAbsent);
        let absent = ImmutableObject::new(vec![46; 64])?;
            let absent_fence =
                TenantKeyPurgeFence::new(absent.id(), &tombstone, &identity, &signer)?;
            assert!(
                Repository::delete_tenant_key(&repository, absent.id(), &fence)
                    .await
                    .is_err()
            );
            assert_eq!(
                Repository::delete_tenant_key(&repository, absent.id(), &absent_fence).await?,
                DeleteOutcome::Deleted
            );
            assert_eq!(
                repository.object_size_hint(absent.id()).await?,
                absent_fence.bytes().len() as u64
            );
            assert!(repository.put_if_absent(absent.clone()).await.is_err());
            assert!(repository.delete(absent.id()).await.is_err());
            assert_eq!(
                Repository::delete_tenant_key(&repository, absent.id(), &absent_fence).await?,
                DeleteOutcome::AlreadyAbsent
            );
            Ok(())
        },
    )
    .await
}
