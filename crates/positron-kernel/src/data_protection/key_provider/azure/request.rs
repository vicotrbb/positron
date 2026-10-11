use super::*;

impl AzureKeyVaultKeyProvider {
    pub(super) fn begin(&self) -> Result<ActiveOperation<'_>, KeyProviderFailure> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        Ok(ActiveOperation {
            active: &self.active,
            deadline: tokio::time::Instant::now() + Duration::from_secs(15),
        })
    }
    pub(super) async fn request(
        &self,
        operation: protocol::Operation,
        body: Zeroizing<Vec<u8>>,
        deadline: tokio::time::Instant,
    ) -> Result<Zeroizing<Vec<u8>>, KeyProviderFailure> {
        let endpoint = operation.endpoint(&self.identity);
        let scope = protocol::scope(&self.identity);
        let mut submitted = false;
        let request = async {
            let token = self
                .credentials
                .get_token(&[scope], None)
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .map_err(credential_failure)?;
            if token.token.secret().is_empty() || token.token.secret().len() > 8192 {
                return Err(KeyProviderFailure::LimitExceeded);
            }
            let authorization = Zeroizing::new(format!("Bearer {}", token.token.secret()));
            let mut value = http::HeaderValue::from_str(&authorization)
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
            value.set_sensitive(true);
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::AUTHORIZATION, value);
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            for attempt in 0..2 {
                submitted = true;
                let reply = self
                    .runtime
                    .http(Request {
                        method: if matches!(operation, protocol::Operation::Metadata) {
                            http::Method::GET
                        } else {
                            http::Method::POST
                        },
                        url: endpoint.clone(),
                        headers: headers.clone(),
                        body: Zeroizing::new(body.to_vec()),
                    })
                    .with_subscriber(tracing::subscriber::NoSubscriber::default())
                    .await
                    .map_err(|e| {
                        if e == google_cloud_auth::native::Error::Unavailable {
                            operation.transport_failure()
                        } else {
                            super::google::native_failure(e)
                        }
                    })?;
                if reply.status.is_success() {
                    return Ok(reply.body);
                }
                let failure = protocol::classify(operation, reply.status.as_u16());
                if failure == KeyProviderFailure::Unavailable && attempt == 0 {
                    tokio::time::sleep(protocol::retry_delay(&reply.headers)?).await;
                } else {
                    return Err(failure);
                }
            }
            Err(KeyProviderFailure::Unavailable)
        };
        tokio::time::timeout_at(deadline, request)
            .await
            .map_err(|_| {
                if submitted {
                    operation.transport_failure()
                } else {
                    KeyProviderFailure::Unavailable
                }
            })?
    }
    pub(super) async fn metadata(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<usize, KeyProviderFailure> {
        let bytes = self
            .request(
                protocol::Operation::Metadata,
                Zeroizing::new(Vec::new()),
                deadline,
            )
            .await?;
        protocol::verify_metadata(&bytes, &self.identity)
    }
}

pub(super) struct ActiveOperation<'a> {
    active: &'a AtomicBool,
    pub(super) deadline: tokio::time::Instant,
}
impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}
pub(super) fn credential_failure(error: azure_core::Error) -> KeyProviderFailure {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(current) = source {
        if let Some(failure) = current.downcast_ref::<KeyProviderFailure>() {
            return *failure;
        }
        if let Some(io) = current.downcast_ref::<std::io::Error>()
            && let Some(failure) = io
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<KeyProviderFailure>())
        {
            return *failure;
        }
        if let Some(sdk) = current.downcast_ref::<azure_core::Error>()
            && let azure_core::error::ErrorKind::HttpResponse { status, .. } = sdk.kind()
        {
            return protocol::classify(protocol::Operation::Metadata, u16::from(*status));
        }
        source = current.source();
    }
    match error.kind() {
        azure_core::error::ErrorKind::Io => KeyProviderFailure::Unavailable,
        _ => KeyProviderFailure::InvalidConfiguration,
    }
}
