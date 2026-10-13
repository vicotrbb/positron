use super::*;
use crate::TransferredResourceReservation;

pub(super) fn start(
    key: NativeRootKey,
    grant: TransferredResourceReservation,
) -> Result<Worker, KeyProviderFailure> {
    start_with_runtime(key, grant, None)
}
pub(super) fn start_with_runtime(
    key: NativeRootKey,
    grant: TransferredResourceReservation,
    runtime: Option<tokio::runtime::Runtime>,
) -> Result<Worker, KeyProviderFailure> {
    let (requests, pending) = mpsc::sync_channel::<Request>(1);
    let (ready, initialization) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new().name("positron-key-provider".to_owned())
        .stack_size(1_048_576).spawn(move || {
            let _grant = grant;
            let runtime = match runtime.map(Ok).unwrap_or_else(|| tokio::runtime::Builder::new_current_thread().enable_all().build()) {
                Ok(runtime) => runtime,
                Err(_) => {
                    if ready.send(Err(KeyProviderFailure::Unavailable)).is_err() {
                        return;
                    }
                    return;
                }
            };
            if ready.send(Ok(())).is_err() { return; }
            while let Ok(request) = pending.recv() {
                runtime.block_on(async {
                    let operation = tokio::time::timeout(Duration::from_secs(15), execute(&key, request.operation));
                    match request.response {
                        ResponseChannel::Blocking(response) => {
                            let outcome = operation.await.map_err(|_| KeyProviderFailure::Unavailable).and_then(|outcome| outcome);
                            // The caller's deadline or shutdown may revoke its receipt.
                            if let Err(undelivered) = response.send(outcome) { drop(undelivered); }
                        },
                        ResponseChannel::Async(mut response) => {
                            tokio::select! {
                                _ = response.closed() => {},
                                outcome = operation => {
                                    let outcome = outcome.map_err(|_| KeyProviderFailure::Unavailable).and_then(|outcome| outcome);
                                    if let Err(undelivered) = response.send(outcome) { drop(undelivered); }
                                },
                            }
                        },
                    }
                });
            }
        }).map_err(|_| KeyProviderFailure::Unavailable)?;
    let worker = Worker {
        requests: Some(requests),
        thread: Some(thread),
    };
    initialization
        .recv()
        .map_err(|_| KeyProviderFailure::Unavailable)??;
    Ok(worker)
}
async fn execute(
    key: &NativeRootKey,
    operation: Operation,
) -> Result<Response, KeyProviderFailure> {
    match operation {
        Operation::Probe(context) => {
            dispatch!(key, provider => provider.probe(context).await).map(Response::Capabilities)
        },
        Operation::Wrap(context, mut bytes) => {
            let payload =
                SecretWrappedKeyPayload::from_provider_plaintext(std::mem::take(&mut *bytes))?;
            dispatch!(key, provider => provider.wrap(payload, context).await)
                .map(Response::Envelope)
        },
        Operation::Unwrap(context, envelope) => {
            let payload = dispatch!(key, provider => provider.unwrap(&envelope, context).await)?;
            Ok(Response::Payload(Zeroizing::new(
                payload.as_provider_plaintext().to_vec(),
            )))
        },
    }
}
