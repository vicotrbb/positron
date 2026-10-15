use positron_backup::*;
fn object_name(id: ObjectId) -> String {
    format!(
        "o-{}",
        id.checksum()
            .into_iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
#[tokio::test]
async fn local_size_hint_does_not_authenticate_or_read_object_contents()
-> Result<(), Box<dyn std::error::Error>> {
    use std::{fs, os::unix::fs::PermissionsExt};
    let path = std::env::temp_dir().join(format!("positron-size-hint-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    let object = ImmutableObject::new(vec![7; 1024])?;
    let id = object.id();
    repository.put_if_absent(object).await?;
    assert!(matches!(
        ObjectRange::new(id, 0, 1024)?.with_expected_size(1023),
        Err(RepositoryFailure::InvalidInput)
    ));
    assert!(matches!(
        ObjectRange::new(id, 0, 1024)?.with_expected_size(MAX_OBJECT_BYTES + 1),
        Err(RepositoryFailure::InvalidInput)
    ));
    let hint = repository.object_size_hint(id).await?;
    assert_eq!(
        repository
            .read_range(ObjectRange::new(id, 0, hint)?.with_expected_size(hint)?)
            .await?
            .bytes(),
        &[7; 1024]
    );
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(path.join(object_name(id)))?
        .write_all(&[9])?;
    assert_eq!(
        repository
            .read_range(ObjectRange::new(id, 0, hint)?.with_expected_size(hint)?)
            .await,
        Err(RepositoryFailure::PreconditionFailed)
    );
    fs::write(path.join(object_name(id)), [8; 1024])?;
    assert_eq!(repository.object_size_hint(id).await?, 1024);
    assert_eq!(
        repository.head(id).await,
        Err(RepositoryFailure::ChecksumMismatch)
    );
    assert_eq!(
        repository
            .object_size_hint(ObjectId::from_checksum([9; 32]))
            .await,
        Err(RepositoryFailure::NotFound)
    );
    fs::remove_file(path.join("identity"))?;
    assert!(repository.object_size_hint(id).await.is_err());
    drop(repository);
    fs::remove_dir_all(path)?;
    Ok(())
}

#[cfg(feature = "test-support")]
#[path = "shared/azure_admission.rs"]
mod admission;
#[cfg(feature = "test-support")]
#[path = "shared/native_authority.rs"]
mod native_authority;
#[cfg(feature = "test-support")]
mod native {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use positron_kernel::*;
    use sha2::Digest;
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpListener, TcpStream},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    #[derive(Clone, Copy)]
    enum Provider {
        Aws,
        Google,
        Azure,
    }
    struct Server {
        address: SocketAddr,
        mode: Arc<AtomicU8>,
        object_gets: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<std::result::Result<(), String>>>,
    }
    impl Server {
        fn start(
            provider: Provider,
            identity: RepositoryIdentity,
            object: ObjectId,
        ) -> Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let mode = Arc::new(AtomicU8::new(0));
            let mode2 = mode.clone();
            let object_gets = Arc::new(AtomicUsize::new(0));
            let gets = object_gets.clone();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let observed = requests.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let worker = thread::spawn(move || {
                let mut count = 0;
                while !stopping.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            count += 1;
                            if count > 128 {
                                return Err("request bound".into());
                            }
                            serve(
                                stream, provider, &identity, object, &mode2, &gets, &observed,
                            )
                            .map_err(|e| e.to_string())?;
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1))
                        },
                        Err(e) => return Err(e.to_string()),
                    }
                }
                Ok(())
            });
            Ok(Self {
                address,
                mode,
                object_gets,
                requests,
                stop,
                worker: Some(worker),
            })
        }
    }
    impl Server {
        fn finish(&mut self) -> Result {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                worker
                    .join()
                    .map_err(|_| "scripted provider thread panicked")?
                    .map_err(|error| format!("scripted provider: {error}"))?;
            }
            Ok(())
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            if let Err(error) = self.finish() {
                eprintln!("scripted provider cleanup: {error}");
            }
        }
    }
    fn identity_bytes(identity: &RepositoryIdentity) -> Vec<u8> {
        let mut bytes = match identity.provider_kind() {
            "awsS3" => b"POSS3I01".to_vec(),
            "googleCloudStorage" => b"POSGCI01".to_vec(),
            _ => b"POSAZI01".to_vec(),
        };
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&identity.repository_id());
        bytes.extend_from_slice(&identity.instance_id());
        bytes.extend_from_slice(&identity.integrity_fingerprint());
        bytes.extend_from_slice(&identity.prefix_commitment());
        bytes
    }
    fn serve(
        mut stream: TcpStream,
        provider: Provider,
        identity: &RepositoryIdentity,
        object: ObjectId,
        mode: &AtomicU8,
        gets: &AtomicUsize,
        requests: &Mutex<Vec<String>>,
    ) -> Result {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut request = Vec::new();
        while !request.windows(4).any(|v| v == b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read(&mut byte)? == 0 {
                return Err("early request end".into());
            }
            request.extend_from_slice(&byte);
            if request.len() > 16384 {
                return Err("header bound".into());
            }
        }
        let request = std::str::from_utf8(&request)?;
        let first = request.lines().next().ok_or("request")?;
        requests
            .lock()
            .map_err(|_| "requests")?
            .push(first.to_owned());
        let mut parts = first.split_whitespace();
        let method = parts.next().ok_or("method")?;
        let path = parts.next().ok_or("path")?;
        let is_identity = path.contains("identity");
        let bucket = (matches!(provider, Provider::Google) && !path.contains("/o/"))
            || (matches!(provider, Provider::Azure) && path.contains("restype="));
        let media = path.contains("alt=media");
        let object_body = !is_identity
            && !bucket
            && method == "GET"
            && (!matches!(provider, Provider::Google) || media);
        if object_body {
            gets.fetch_add(1, Ordering::Relaxed);
        }
        let mode = mode.load(Ordering::Acquire);
        let mut status = if mode == 3 && is_identity || mode == 2 && !is_identity && !bucket {
            404
        } else if mode == 1 && !is_identity && !bucket {
            403
        } else {
            200
        };
        let ranged = object_body && request.to_ascii_lowercase().contains("\r\nrange:");
        if status == 200 && ranged {
            status = 206;
        }
        let bytes = identity_bytes(identity);
        let size = if is_identity {
            bytes.len() as u64
        } else if mode == 5 {
            7
        } else if mode == 6 {
            8
        } else {
            16 * 1024 * 1024
        };
        let mut extra =
            "ETag: \"one\"\r\nx-ms-account-kind: StorageV2\r\nx-ms-is-hns-enabled: false\r\n"
                .to_owned();
        if mode == 6 {
            extra = extra.replace("\"one\"", "\"two\"");
        }
        let body = if (status != 200 && status != 206)
            || (bucket && matches!(provider, Provider::Azure))
        {
            Vec::new()
        } else if bucket {
            serde_json::to_vec(
                &serde_json::json!({"name":"positron-backup","projectNumber":"123456789012","location":"US"}),
            )?
        } else if matches!(provider, Provider::Google) && !media {
            let key = if is_identity {
                "owned/identity".to_owned()
            } else {
                format!("owned/{}", object_name(object))
            };
            serde_json::to_vec(
                &serde_json::json!({"name":key,"generation":if mode==6&&!is_identity {"2"}else{"1"},"metageneration":"1","size":if mode==4&&!is_identity {"bad".to_owned()}else{size.to_string()},"crc32c":STANDARD.encode(crc32c::crc32c(if is_identity {&bytes}else{&[0;7]}).to_be_bytes())}),
            )?
        } else if is_identity {
            bytes.clone()
        } else if mode == 5 || mode == 6 {
            vec![0; 7]
        } else {
            vec![1; 7]
        };
        if matches!(provider, Provider::Azure) {
            use md5::{Digest, Md5};
            extra.push_str(&format!(
                "Content-MD5: {}\r\n",
                STANDARD.encode(Md5::digest(if is_identity { &bytes } else { &body }))
            ));
        }
        if ranged {
            extra.push_str(&format!("Content-Range: bytes 0-6/{size}\r\n"));
        }
        let length = if method == "HEAD" {
            size.to_string()
        } else {
            body.len().to_string()
        };
        let length = if mode == 4 && !is_identity && method == "HEAD" {
            "bad".to_owned()
        } else {
            length
        };
        write!(
            stream,
            "HTTP/1.1 {status} Result\r\nContent-Length: {length}\r\n{extra}Connection: close\r\n\r\n"
        )?;
        if method != "HEAD" {
            stream.write_all(&body)?;
        }
        Ok(())
    }
    async fn exercise(repository: &dyn Repository, server: &Server, id: ObjectId) -> Result {
        assert_eq!(repository.object_size_hint(id).await?, 16 * 1024 * 1024);
        assert_eq!(
            server.object_gets.load(Ordering::Relaxed),
            0,
            "hint fetched encrypted object body"
        );
        assert!(!server.requests.lock().map_err(|_| "requests")?.is_empty());
        assert!(repository.head(id).await.is_err());
        assert_eq!(
            server.object_gets.load(Ordering::Relaxed),
            1,
            "existing head must still verify body"
        );
        for (mode, expected) in [
            (1, RepositoryFailure::PermissionDenied),
            (2, RepositoryFailure::NotFound),
            (3, RepositoryFailure::NotFound),
        ] {
            server.mode.store(mode, Ordering::Release);
            assert_eq!(repository.object_size_hint(id).await, Err(expected));
        }
        server.mode.store(4, Ordering::Release);
        assert!(repository.object_size_hint(id).await.is_err());
        assert_eq!(server.object_gets.load(Ordering::Relaxed), 1);
        server.mode.store(5, Ordering::Release);
        let hint = repository.object_size_hint(id).await?;
        assert_eq!(hint, 7);
        assert_eq!(
            repository
                .read_range(ObjectRange::new(id, 0, hint)?.with_expected_size(hint)?)
                .await?
                .bytes(),
            &[0; 7]
        );
        // The old content hash is valid for this prefix, but the native object
        // has grown since the hint. Reject before fetching any body bytes.
        server.mode.store(6, Ordering::Release);
        let prefix = repository
            .read_range(ObjectRange::new(id, 0, hint)?)
            .await?;
        assert_eq!(
            <[u8; 32]>::from(sha2::Sha256::digest(prefix.bytes())),
            id.checksum()
        );
        let reads = server.object_gets.load(Ordering::Relaxed);
        assert_eq!(
            repository
                .read_range(ObjectRange::new(id, 0, hint)?.with_expected_size(hint)?)
                .await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        assert_eq!(server.object_gets.load(Ordering::Relaxed), reads);
        Ok(())
    }
    async fn exercise_and_finish(
        repository: &dyn Repository,
        mut server: Server,
        id: ObjectId,
    ) -> Result {
        let primary = exercise(repository, &server, id).await;
        let worker = server.finish();
        match (primary, worker) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(primary), Err(worker)) => Err(format!("{primary}; {worker}").into()),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
    #[tokio::test]
    async fn native_size_hints_only_read_metadata_and_keep_identity_checks() -> Result {
        super::admission::admitted(
            ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| {
                AwsS3Repository::required_resources()
                    .get(dimension)
                    .max(GoogleCloudStorageRepository::required_resources().get(dimension))
                    .max(AzureBlobRepository::required_resources().get(dimension))
            })),
            |resources| async move {
                let id = ObjectId::from_checksum(sha2::Sha256::digest([0; 7]).into());
                let aws = AwsS3Target::new(
                    "positron-backup",
                    "us-east-1",
                    "https://s3.us-east-1.amazonaws.com",
                    "123456789012",
                    "owned/",
                )?;
                let identity = RepositoryIdentity::aws_s3([1; 16], [2; 16], [3; 32], &aws)?;
                let server = Server::start(Provider::Aws, identity.clone(), id)?;
                let repository = AwsS3Repository::from_local_simulator(
                    aws,
                    identity,
                    resources.clone(),
                    server.address,
                )?;
                exercise_and_finish(&repository, server, id)
                    .await
                    .map_err(|error| format!("aws: {error}"))?;
                drop(repository);
                let google = GoogleCloudStorageTarget::new(
                    "positron-backup",
                    "123456789012",
                    "US",
                    "owned/",
                )?;
                let identity =
                    RepositoryIdentity::google_cloud_storage([1; 16], [2; 16], [3; 32], &google)?;
                let server = Server::start(Provider::Google, identity.clone(), id)?;
                let custody = || {
                    RepositoryUploadAuthenticator::new(
                        CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
                        InstanceId::new([2; 16]).expect("instance"),
                    )
                };
                let repository = GoogleCloudStorageRepository::from_local_simulator(
                    google,
                    identity,
                    resources.clone(),
                    custody(),
                    server.address,
                )?;
                exercise_and_finish(&repository, server, id)
                    .await
                    .map_err(|error| format!("google: {error}"))?;
                drop(repository);
                let azure = AzureBlobTarget::new("positronbackup", "backups", "owned/")?;
                let identity = RepositoryIdentity::azure_blob([1; 16], [2; 16], [3; 32], &azure)?;
                let server = Server::start(Provider::Azure, identity.clone(), id)?;
                let repository = AzureBlobRepository::from_local_simulator(
                    azure,
                    identity,
                    resources,
                    custody(),
                    server.address,
                )?;
                exercise_and_finish(&repository, server, id)
                    .await
                    .map_err(|error| format!("azure: {error}"))?;
                Ok(())
            },
        )
        .await
    }
}
