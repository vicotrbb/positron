//! A not-ready reply cannot prove that the child has acquired its Fenced owner.
#![cfg(unix)]
use super::support::*;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
const FENCED: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";

#[test]
fn fenced_barrier_waits_for_control_phase_after_unready() {
    let (result, requests) = probe(
        vec![NOT_FOUND, FENCED],
        Instant::now() + STARTUP_PROBE_BUDGET,
    );
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        requests, 2,
        "Recovering 503 is not the Fenced ownership barrier"
    );
}

#[test]
fn fenced_barrier_never_fenced_exhausts_the_same_passed_deadline() {
    let (result, _) = probe(vec![NOT_FOUND], Instant::now() + Duration::from_millis(100));
    assert!(
        result.is_err(),
        "a permanent Recovering state cannot satisfy the barrier"
    );
    assert!(result.unwrap_err().contains("deadline"));
}

#[test]
fn fenced_barrier_rejects_unexpected_and_truncated_control_replies() {
    for reply in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0".as_slice(),
    ] {
        let (result, _) = probe(vec![reply], Instant::now() + STARTUP_PROBE_BUDGET);
        assert!(
            result.is_err(),
            "only a complete phase-specific reply is a barrier"
        );
    }
}

#[test]
fn fenced_barrier_expired_deadline_never_contacts_control() {
    let (result, requests) = probe(vec![FENCED], Instant::now());
    assert!(result.is_err());
    assert_eq!(requests, 0);
}

fn probe(replies: Vec<&'static [u8]>, deadline: Instant) -> (Result<(), String>, usize) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new("/tmp").join(format!(
        "p120-fenced-{}-{nonce}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("control.sock");
    let control = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let readiness = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = readiness.local_addr().unwrap().port();
    let stopped = Arc::new(AtomicBool::new(false));
    let ready_stop = Arc::clone(&stopped);
    let ready_server = std::thread::spawn(move || {
        let (mut stream, _) = readiness.accept().unwrap();
        if ready_stop.load(Ordering::Acquire) {
            return;
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&requests);
    let control_stop = Arc::clone(&stopped);
    let control_server = std::thread::spawn(move || {
        loop {
            let (mut stream, _) = control.accept().unwrap();
            if control_stop.load(Ordering::Acquire) {
                return;
            }
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let request = read_request(&mut stream);
            assert!(request.starts_with(b"GET /control/fenced/inspection HTTP/1.1\r\n"));
            assert!(!request.windows(14).any(|bytes| bytes == b"Authorization:"));
            let index = observed
                .fetch_add(1, Ordering::AcqRel)
                .min(replies.len() - 1);
            stream.write_all(replies[index]).unwrap();
        }
    });
    let result = wait_for_fenced_startup(port, &path, deadline).map_err(|error| error.to_string());
    stopped.store(true, Ordering::Release);
    drop(TcpStream::connect(("127.0.0.1", port)));
    drop(UnixStream::connect(&path));
    ready_server.join().unwrap();
    control_server.join().unwrap();
    let count = requests.load(Ordering::Acquire);
    fs::remove_dir_all(root).unwrap();
    (result, count)
}

fn read_request(stream: &mut impl Read) -> Vec<u8> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        assert!(request.len() <= 1024);
    }
    request
}
