//! Real owner-authenticated Control responses survive a descriptor handoff.

use super::*;
use crate::{BootstrapPaths, InitializationPlan, InstanceBootstrap, RuntimeConfiguration};
use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_kernel::MountQualification;
use std::io::{Read, Write};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AcceptPoint {
    BeforeAccept,
    AfterAccept,
    BeforeIdleWait,
}

#[test]
fn idle_control_polling_does_not_hold_generation_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = Owner::new()?;
    let host = owner.host()?;
    let profile = host
        .profile_for(ListenerRole::Control)
        .ok_or("control profile")?;
    let mut listener = host.bind(crate::ListenerRequest::for_profile(
        profile,
        owner.state.health(),
    ))?;
    let admission = current_admission(&host.admissions, ListenerRole::Control)
        .map_err(|_| "control admission")?;
    let (entered, release) = pause(&admission, AcceptPoint::BeforeIdleWait);
    let serving = worker(Arc::clone(&admission), owner.state.health());
    entered.recv_timeout(Duration::from_secs(5))?;
    let (closed, stopped) = sync_channel(1);
    let retiring = std::thread::spawn(move || {
        admission.stop();
        closed.send(()).expect("test observes retirement");
    });
    let completed = stopped.recv_timeout(Duration::from_secs(1));
    release.send(())?;
    retiring.join().map_err(|_| "retirement panic")?;
    serving
        .join()
        .map_err(|_| "worker panic")?
        .map_err(|_| "worker failure")?;
    completed?;
    assert!(listener.drain_within(Duration::from_secs(1))?);
    drop((listener, host));
    let root = owner.root.clone();
    drop(owner);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) struct AcceptBarrier {
    pub(super) point: AcceptPoint,
    pub(super) entered: SyncSender<()>,
    pub(super) release: Receiver<()>,
}

struct Owner {
    root: PathBuf,
    state: crate::health::ProcessState,
    administrator: String,
    _services: ServiceHandle,
}

impl Owner {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root = std::path::Path::new("/tmp").join(format!("p-control-{nonce}"));
        let data = root.join("data");
        let secrets = root.join("secrets");
        std::fs::create_dir_all(&data)?;
        std::fs::create_dir_all(&secrets)?;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
        let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let instance = Arc::new(InstanceBootstrap::reopen(&paths)?);
        let configuration = format!(
            "schema_version=1\n[storage]\ndata_directory='{}'\nsecrets_directory='{}'\n[security]\nlocal_key_file='{}'\n",
            data.display(),
            secrets.display(),
            secrets.join("local-root-key.v1").display()
        );
        let effective = Arc::new(resolve(ConfigurationInputs::try_new(
            Some(&configuration),
            EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?)?);
        let generation = crate::CatalogConfigurationPublication::new(Arc::clone(&instance))
            .establish(&effective)?;
        let state = crate::health::ProcessState::starting();
        state.set_configuration_runtime(Arc::new(RuntimeConfiguration::new_at_generation(
            effective, generation,
        )))?;
        state.set_inspection_authority(Arc::clone(&instance))?;
        let services = ServiceHandle::new(instance)?;
        state.set_catalog_operation(services.catalog_operation_gate())?;
        state.transition(crate::ProcessPhase::Serving);
        Ok(Self {
            root,
            state,
            administrator: claim.secret().to_owned(),
            _services: services,
        })
    }

    fn host(&self) -> Result<NativeHost, NativeHostFailure> {
        let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        Ok(NativeHost::new(NativeBindings::new(
            self.root.join("control.sock"),
            endpoint,
            endpoint,
            endpoint,
            endpoint,
            endpoint,
        )?))
    }

    fn request(&self) -> std::io::Result<UnixStream> {
        let mut client = UnixStream::connect(self.root.join("control.sock"))?;
        client.set_read_timeout(Some(Duration::from_secs(3)))?;
        client.set_write_timeout(Some(Duration::from_secs(3)))?;
        write!(
            client,
            "POST /control/configuration/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n\r\n",
            self.administrator
        )?;
        Ok(client)
    }
}

fn pause(admission: &Admission, point: AcceptPoint) -> (Receiver<()>, SyncSender<()>) {
    let (entered, observed) = sync_channel(1);
    let (release, resume) = sync_channel(1);
    *admission.accept_barrier.lock().expect("owned test barrier") = Some(AcceptBarrier {
        point,
        entered,
        release: resume,
    });
    (observed, release)
}

fn worker(
    admission: Arc<Admission>,
    health: HealthState,
) -> std::thread::JoinHandle<Result<(), TaskFailure>> {
    std::thread::spawn(move || {
        serve_http(
            admission,
            TaskCancellation::new(),
            TaskCancellation::new(),
            health,
            None,
        )
    })
}

#[test]
fn stopped_control_generation_does_not_steal_its_successors_queued_reload()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = Owner::new()?;
    let host = owner.host()?;
    let profile = host
        .profile_for(ListenerRole::Control)
        .ok_or("control profile")?;
    let mut old = host.bind(crate::ListenerRequest::for_profile(
        profile.clone(),
        owner.state.health(),
    ))?;
    let old_admission =
        current_admission(&host.admissions, ListenerRole::Control).map_err(|_| "old admission")?;
    let mut successor = host.bind(crate::ListenerRequest::for_profile(
        profile.clone(),
        owner.state.health(),
    ))?;
    let new_admission =
        current_admission(&host.admissions, ListenerRole::Control).map_err(|_| "new admission")?;
    let (entered, release) = pause(&old_admission, AcceptPoint::BeforeAccept);
    let old_worker = worker(old_admission, owner.state.health());
    entered.recv_timeout(Duration::from_secs(5))?;
    old.close()?;
    let mut client = owner.request()?;
    release.send(())?;
    old_worker
        .join()
        .map_err(|_| "old worker panic")?
        .map_err(|_| "old worker failure")?;
    let new_worker = worker(new_admission, owner.state.health());
    let mut response = String::new();
    let outcome = client.read_to_string(&mut response);
    successor.close()?;
    new_worker
        .join()
        .map_err(|_| "successor worker panic")?
        .map_err(|_| "successor worker failure")?;
    outcome?;
    assert!(
        response.starts_with("HTTP/1.1 202 Accepted\r\n"),
        "queued reload must survive the retired worker: {response}"
    );
    assert!(owner.state.health().take_configuration_reload_request());
    drop((old, successor, host));
    let root = owner.root.clone();
    drop(owner);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn control_request_dequeued_before_stop_completes_and_releases_its_drain_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = Owner::new()?;
    let host = owner.host()?;
    let profile = host
        .profile_for(ListenerRole::Control)
        .ok_or("control profile")?;
    let mut listener = host.bind(crate::ListenerRequest::for_profile(
        profile,
        owner.state.health(),
    ))?;
    let admission = current_admission(&host.admissions, ListenerRole::Control)
        .map_err(|_| "control admission")?;
    let (entered, release) = pause(&admission, AcceptPoint::AfterAccept);
    let serving = worker(Arc::clone(&admission), owner.state.health());
    let mut client = owner.request()?;
    entered.recv_timeout(Duration::from_secs(5))?;
    let (closing, started) = sync_channel(1);
    let (closed, stopped) = sync_channel(1);
    let retiring = std::thread::spawn(move || {
        closing.send(()).expect("test observes retirement");
        admission.stop();
        closed.send(()).expect("test observes retired admission");
    });
    started.recv_timeout(Duration::from_secs(5))?;
    // Let retirement run while the dequeued connection is paused. It may finish
    // or wait for the admission decision; neither ordering may lose the request.
    match stopped.recv_timeout(Duration::from_millis(100)) {
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
        Err(error) => return Err(error.into()),
    }
    release.send(())?;
    let mut response = String::new();
    let outcome = client.read_to_string(&mut response);
    retiring.join().map_err(|_| "retirement panic")?;
    serving
        .join()
        .map_err(|_| "worker panic")?
        .map_err(|_| "worker failure")?;
    assert!(listener.drain_within(Duration::from_secs(1))?);
    outcome?;
    assert!(
        response.starts_with("HTTP/1.1 202 Accepted\r\n"),
        "accepted reload must complete during retirement: {response}"
    );
    assert!(owner.state.health().take_configuration_reload_request());
    drop((listener, host));
    let root = owner.root.clone();
    drop(owner);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
