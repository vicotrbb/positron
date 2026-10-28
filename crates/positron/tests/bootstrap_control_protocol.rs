//! Bounded native Control transport refuses malformed or failed one-time deliveries.
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::Command,
    sync::mpsc,
};

#[test]
fn claim_transport_never_retries_or_reflects_failed_delivery_bytes() {
    let base = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    let root = std::path::Path::new(base).join(format!("p120-protocol-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let secret = format!("pos_{}", "e".repeat(64));
    let valid = format!("administrator_secret={secret}\n");
    let variants = [
        (302, valid.clone(), valid.len()),
        (503, valid.clone(), valid.len()),
        (200, format!("{valid}{valid}"), valid.len() * 2),
        (200, format!("unknown_secret={secret}\n"), valid.len() - 6),
        (200, valid.clone(), valid.len() + 1),
        (200, "x".repeat(4097), 4097),
        (200, "administrator_secret=invalid\n".into(), 29),
    ];
    for (index, (status, body, length)) in variants.into_iter().enumerate() {
        let path = root.join(format!("control{index}.sock"));
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (finished, done) = mpsc::sync_channel(1);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 512);
            }
            assert!(request.starts_with(b"POST /control/bootstrap/claim HTTP/1.1\r\n"));
            assert!(
                !String::from_utf8_lossy(&request)
                    .to_ascii_lowercase()
                    .contains("authorization:")
            );
            let reason = if status == 200 { "OK" } else { "Unavailable" };
            let _outcome = write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}"
            );
            drop(stream);
            done.recv().unwrap();
            listener.set_nonblocking(true).unwrap();
            assert!(
                matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
            );
        });
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["bootstrap", "claim", "--control-path"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&secret));
        finished.send(()).unwrap();
        server.join().unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}
