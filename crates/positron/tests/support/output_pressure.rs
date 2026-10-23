use std::process::{Child, Command, Stdio};

pub fn child() -> std::io::Result<Child> {
    let chunk = "x".repeat(1024);
    let script = format!(
        "i=0; while [ $i -lt 256 ]; do printf '%s' '{chunk}'; printf '%s' '{chunk}' >&2; i=$((i+1)); done"
    );
    Command::new("/bin/sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}
