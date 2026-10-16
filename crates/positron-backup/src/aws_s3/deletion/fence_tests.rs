use super::*;
use crate::*;
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
use std::{
    io::{Read, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
#[path = "../../../tests/support/snapshot_resources.rs"]
mod resources;
#[tokio::test]
async fn occupied_signed_fence_rejects_delayed_conditional_put_and_generic_delete()
-> Result<(), Box<dyn std::error::Error>> {
    resources::admitted_with_peak(positron_kernel::ResourceAmounts::new([268_435_456, 1, 4, 0, 1, 1, 2, 4, 1, 8, 16384]), |resources| async move {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets)?;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
        let custody = BootstrapKeyCustody::initialize(&secrets)?;
        let instance = InstanceId::new([2;16])?;
        let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7;32])?;
        let signer = custody.backup_control_signer(instance, &protected)?;
        let target = AwsS3Target::new("positron-test", "us-east-1", "https://s3.us-east-1.amazonaws.com", "123456789012", "owned/")?;
        let identity = RepositoryIdentity::aws_s3([1;16], [2;16], signer.identity().fingerprint(), &target)?;
        let object = ImmutableObject::new(b"encrypted tenant key envelope fixture".to_vec())?;
        let tombstone = BackupPurgeTombstone::new([9;16], "excluded", [10;16], 11)?;
        let fence = TenantKeyPurgeFence::new(object.id(), &tombstone, &identity, &signer)?;
        assert_eq!(TenantKeyPurgeFence::verify(fence.bytes(), &identity, object.id())?, fence);
        let mut corrupt = fence.bytes().to_vec();
        *corrupt.last_mut().ok_or("signature")? ^= 1;
        assert!(TenantKeyPurgeFence::verify(&corrupt, &identity, object.id()).is_err());
        assert!(TenantKeyPurgeFence::verify(fence.bytes(), &identity, ObjectId::from_checksum([44;32])).is_err());
        let foreign_repository = RepositoryIdentity::aws_s3([45;16], [2;16], signer.identity().fingerprint(), &target)?;
        assert!(TenantKeyPurgeFence::verify(fence.bytes(), &foreign_repository, object.id()).is_err());
        for length in [0, 7, 39, 75, fence.bytes().len() - 1] {
            assert!(TenantKeyPurgeFence::verify(fence.bytes().get(..length).ok_or("prefix")?, &identity, object.id()).is_err());
        }
        // The outer signature binds tenant, original operation and acceptance
        // time inside the independently signed permanent tombstone.
        for offset in [192, 208, 224] {
            let mut altered = fence.bytes().to_vec();
            *altered.get_mut(offset).ok_or("authorization field")? ^= 1;
            assert!(TenantKeyPurgeFence::verify(&altered, &identity, object.id()).is_err());
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let versions = Arc::new(Mutex::new(vec![("v1".to_owned(), object.bytes().to_vec())]));
        let (started, ready) = std::sync::mpsc::channel();
        let identity_bytes = identity.encode();
        let object_name = object.id().name();
        let server_stop = stopped.clone();
        let server_release = release.clone();
        let server_versions = versions.clone();
        let server = std::thread::spawn(move || {
            let mut handlers = vec![];
            while !server_stop.load(Ordering::Acquire) {
                let Ok((mut stream,_)) = listener.accept() else { std::thread::sleep(std::time::Duration::from_millis(1)); continue; };
                let release = server_release.clone(); let versions = server_versions.clone(); let started = started.clone(); let identity_bytes = identity_bytes.clone(); let object_name = object_name.clone();
                handlers.push(std::thread::spawn(move || {
                    stream.set_nonblocking(false).expect("blocking");
                    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
                    let mut bytes = vec![]; let mut block = [0;4096];
                    let split = loop { let n=stream.read(&mut block).expect("request"); if n==0 {return;} bytes.extend_from_slice(&block[..n]); if let Some(i)=bytes.windows(4).position(|s|s==b"\r\n\r\n") {break i+4;} };
                    let header = String::from_utf8_lossy(&bytes[..split]).to_ascii_lowercase();
                    let length = header.lines().find_map(|l|l.strip_prefix("content-length:").and_then(|v|v.trim().parse::<usize>().ok())).unwrap_or(0);
                    while bytes.len()-split < length { let n=stream.read(&mut block).expect("body"); if n==0{return;} bytes.extend_from_slice(&block[..n]); }
                    let first=header.lines().next().expect("line");
                    let conditional_create=first.starts_with("put ") && header.contains("if-none-match: *");
                    if conditional_create { started.send(()).expect("started"); while !release.load(Ordering::Acquire) {std::thread::sleep(std::time::Duration::from_millis(1));} }
                    let mut state=versions.lock().expect("state");
                    let (status, body, extra) = if first.contains("/owned/identity") { (200, identity_bytes.to_vec(), String::new()) }
                    else if first.contains("?versions") {
                        let mut xml="<ListVersionsResult><IsTruncated>false</IsTruncated>".to_owned();
                        for (id,_) in state.iter() { xml.push_str(&format!("<Version><Key>owned/{object_name}</Key><VersionId>{id}</VersionId></Version>")); }
                        xml.push_str("</ListVersionsResult>"); (200,xml.into_bytes(),String::new())
                    } else if conditional_create {
                        if state.is_empty() {
                            state.push(("late".to_owned(),bytes[split..split+length].to_vec()));
                            (200,vec![],String::new())
                        } else { (412, b"<Error><Code>PreconditionFailed</Code></Error>".to_vec(), String::new()) }
                    }
                    else if first.starts_with("put ") { state.push(("v2".to_owned(),bytes[split..split+length].to_vec())); (200,vec![],"ETag: \"fence\"\r\nx-amz-version-id: v2\r\n".to_owned()) }
                    else if first.starts_with("delete ") { state.retain(|(id,_)| !first.contains(&format!("versionid={id}"))); (204,vec![],String::new()) }
                    else {
                        let selected=if first.contains("versionid=v1") {state.iter().find(|(id,_)|id=="v1")} else {state.last()};
                        match selected { Some((id,body)) => (200, if first.starts_with("head "){vec![]}else{body.clone()},format!("ETag: \"fence\"\r\nx-amz-version-id: {id}\r\n")), None=>(404,b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),String::new()) }
                    };
                    let reply=format!("HTTP/1.1 {status} Result\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",body.len());
                    let _=stream.write_all(reply.as_bytes()); let _=stream.write_all(&body);
                }));
            }
            for handler in handlers {handler.join().expect("handler");}
        });
        let native = Arc::new(AwsS3Repository::from_local_simulator(target, identity, resources, address)?);
        let writer = native.clone(); let late_object = object.clone();
        // A separate provider client represents a PUT accepted before purge.
        let delayed = tokio::spawn(async move { writer.put_if_absent(late_object).await });
        while ready.try_recv().is_err() {tokio::task::yield_now().await;}
        // The same instance refuses concurrent calls; use the actual native
        // typed fence through a second independently opened provider handle.
        let cleanup = AwsS3Repository::from_local_simulator(native.target.clone(), native.identity.clone(), native.resources.clone(), address)?;
        let result = cleanup.delete_tenant_key(object.id(), &fence).await;
        release.store(true, Ordering::Release);
        let delayed_result = delayed.await?;
        assert_eq!(result?, DeleteOutcome::Deleted);
        assert_eq!(delayed_result, Err(RepositoryFailure::NotFound));
        assert_eq!(cleanup.head(object.id()).await, Err(RepositoryFailure::NotFound));
        assert_eq!(cleanup.delete(object.id()).await, Err(RepositoryFailure::PreconditionFailed));
        assert_eq!(cleanup.delete_tenant_key(object.id(), &fence).await?, DeleteOutcome::AlreadyAbsent);
        for changed in [
            BackupPurgeTombstone::new([12;16], "excluded", [10;16], 11)?,
            BackupPurgeTombstone::new([9;16], "excluded", [12;16], 11)?,
            BackupPurgeTombstone::new([9;16], "excluded", [10;16], 12)?,
        ] {
            let changed_fence = TenantKeyPurgeFence::new(object.id(), &changed, &cleanup.identity, &signer)?;
            assert_eq!(cleanup.delete_tenant_key(object.id(), &changed_fence).await, Err(RepositoryFailure::ChecksumMismatch));
        }
        let state=versions.lock().map_err(|_|"state")?;
        assert_eq!(state.len(),1); assert_eq!(state.first().ok_or("fence")?.1,fence.bytes());
        drop(state);
        stopped.store(true,Ordering::Release); server.join().map_err(|_|"server")?;
        Ok(())
    }).await
}
