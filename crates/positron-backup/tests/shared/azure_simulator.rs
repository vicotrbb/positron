//! Independent bounded native Azure Blob protocol simulator.
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::Digest;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Clone)]
struct Object {
    etag: u64,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct State {
    next: u64,
    objects: BTreeMap<String, Object>,
    history: BTreeMap<String, Vec<Object>>,
    blocks: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}
pub enum Action {
    Status(u16, String, Vec<u8>),
    DropAfter,
    CorruptMd5,
    CorruptBody,
    Race(String),
}
type Rules = Arc<Mutex<VecDeque<(String, String, Action)>>>;
pub struct Server {
    pub address: SocketAddr,
    pub rules: Rules,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<()>>>,
}
impl Server {
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let rules: Rules = Default::default();
        let injected = rules.clone();
        let worker = thread::spawn(move || {
            let mut state = State::default();
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, &mut state, &injected)?,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    },
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            rules,
            stop,
            worker: Some(worker),
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .expect("fixture worker")
                .expect("fixture protocol")
        }
    }
}
fn decode(input: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut iter = input.bytes();
    while let Some(byte) = iter.next() {
        if byte == b'%' {
            let a = iter.next().ok_or("escape")?;
            let b = iter.next().ok_or("escape")?;
            let hex = std::str::from_utf8(&[a, b])?.to_owned();
            bytes.push(u8::from_str_radix(&hex, 16)?);
        } else {
            bytes.push(byte);
        }
    }
    Ok(String::from_utf8(bytes)?)
}
fn md5(bytes: &[u8]) -> String {
    STANDARD.encode(md5::Md5::digest(bytes))
}
fn serve(mut stream: TcpStream, state: &mut State, rules: &Rules) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut raw = Vec::new();
    let end;
    loop {
        let mut chunk = [0; 8192];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("incomplete request".into());
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            end = pos + 4;
            break;
        }
        if raw.len() > 131072 {
            return Err("header bound".into());
        }
    }
    let text = std::str::from_utf8(&raw[..end])?.to_owned();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().ok_or("request")?.split_whitespace();
    let method = first.next().ok_or("method")?;
    let url = first.next().ok_or("url")?;
    let headers: BTreeMap<_, _> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    if headers.contains_key("authorization") {
        return Err("simulator must not receive credentials".into());
    }
    let length: usize = headers
        .get("content-length")
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(0);
    if length > 64 * 1024 * 1024 + 65536 {
        return Err("body bound".into());
    }
    while raw.len() - end < length {
        let mut chunk = [0; 8192];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("incomplete body".into());
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let query: BTreeMap<_, _> = query
        .split('&')
        .filter_map(|v| v.split_once('='))
        .map(|(k, v)| Ok((k.to_owned(), decode(v)?)))
        .collect::<Result<_>>()?;
    let body = raw.get(end..end + length).ok_or("body")?;
    if headers.get("x-ms-version").map(String::as_str) != Some("2023-11-03") {
        return Err("service pin".into());
    }

    let action = {
        let mut rules = rules.lock().map_err(|_| "fixture rules")?;
        if rules
            .front()
            .is_some_and(|(m, p, _)| m == method && url.starts_with(p))
        {
            rules.pop_front().map(|(_, _, a)| a)
        } else {
            None
        }
    };
    let (status, mut extra, mut reply, length) =
        if let Some(Action::Status(status, extra, body)) = &action {
            (*status, extra.clone(), body.clone(), body.len())
        } else {
            dispatch(state, method, path, &query, &headers, body)?
        };
    match action {
        Some(Action::DropAfter) => return Ok(()),
        Some(Action::CorruptMd5) => {
            extra = extra
                .lines()
                .filter(|line| !line.to_ascii_lowercase().starts_with("content-md5:"))
                .map(|line| format!("{line}\r\n"))
                .collect::<String>();
            extra.push_str("Content-MD5: AAAAAAAAAAAAAAAAAAAAAA==\r\n");
        },
        Some(Action::CorruptBody) => {
            if let Some(byte) = reply.first_mut() {
                *byte ^= 1;
            }
        },
        Some(Action::Race(source)) => {
            let object = state.objects.get(&source).ok_or("race source")?.clone();
            state.next += 1;
            if let Some(previous) = state.objects.get(key_from_path(path)?).cloned() {
                state
                    .history
                    .entry(key_from_path(path)?.into())
                    .or_default()
                    .push(previous);
            }
            state.objects.insert(
                key_from_path(path)?.into(),
                Object {
                    etag: state.next,
                    bytes: object.bytes,
                },
            );
        },
        _ => {},
    }

    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {length}\r\nConnection: close\r\n{extra}\r\n"
    )?;
    stream.write_all(&reply)?;
    Ok(())
}
type Reply = (u16, String, Vec<u8>, usize);
fn response(status: u16, extra: String, body: Vec<u8>) -> Result<Reply> {
    let length = body.len();
    Ok((status, extra, body, length))
}
fn dispatch(
    state: &mut State,
    method: &str,
    path: &str,
    q: &BTreeMap<String, String>,
    h: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<Reply> {
    if path == "/backups/" && q.get("restype").map(String::as_str) == Some("account") {
        return response(
            200,
            "x-ms-account-kind: StorageV2\r\nx-ms-is-hns-enabled: false\r\n".into(),
            Vec::new(),
        );
    }
    if path == "/backups/"
        && q.get("restype").map(String::as_str) == Some("container")
        && method == "HEAD"
    {
        return response(
            200,
            "x-ms-has-immutability-policy: false\r\nx-ms-has-legal-hold: false\r\n".into(),
            Vec::new(),
        );
    }
    if path == "/" && q.get("restype").map(String::as_str) == Some("service") {
        return response(200,String::new(),b"<StorageServiceProperties><DeleteRetentionPolicy><Enabled>false</Enabled></DeleteRetentionPolicy></StorageServiceProperties>".to_vec());
    }
    let key = path.strip_prefix("/backups/").ok_or("container path")?;
    if q.get("comp").map(String::as_str) == Some("list") {
        let prefix = q.get("prefix").ok_or("prefix")?;
        let marker = q.get("marker").map(String::as_str).unwrap_or("");
        let limit = q.get("maxresults").ok_or("limit")?.parse::<usize>()?;
        let mut entries = Vec::new();
        for (key, object) in &state.objects {
            if key.starts_with(prefix) {
                entries.push((key.clone(), None, object.bytes.len()));
            }
        }
        if q.contains_key("include") {
            for (key, versions) in &state.history {
                if key.starts_with(prefix) {
                    for object in versions {
                        entries.push((key.clone(), Some(object.etag), object.bytes.len()));
                    }
                }
            }
        }
        entries.sort();
        let entries = entries
            .into_iter()
            .enumerate()
            .filter(|(index, _)| {
                marker.is_empty() || marker.parse::<usize>().is_ok_and(|offset| *index > offset)
            })
            .collect::<Vec<_>>();
        let mut xml = String::from("<?xml version=\"1.0\"?><EnumerationResults><Blobs>");
        for (_, (key, version, size)) in entries.iter().take(limit) {
            xml.push_str(&format!("<Blob><Name>{key}</Name>"));
            if let Some(version) = version {
                xml.push_str(&if version % 2 == 0 {
                    format!("<VersionId>{version}</VersionId>")
                } else {
                    format!("<Snapshot>{version}</Snapshot>")
                });
            }
            xml.push_str(&format!(
                "<Properties><Content-Length>{size}</Content-Length></Properties></Blob>"
            ));
        }
        xml.push_str("</Blobs><NextMarker>");
        if entries.len() > limit {
            xml.push_str(&entries.get(limit - 1).ok_or("marker")?.0.to_string());
        }
        xml.push_str("</NextMarker></EnumerationResults>");
        return response(200, String::new(), xml.into_bytes());
    }
    let current = if let Some(version) = q.get("versionid").or_else(|| q.get("snapshot")) {
        state
            .history
            .get(key)
            .and_then(|v| v.iter().find(|o| o.etag.to_string() == *version))
            .cloned()
    } else {
        state.objects.get(key).cloned()
    };
    if h.get("if-none-match").map(String::as_str) == Some("*") && current.is_some() {
        return response(412, String::new(), Vec::new());
    }
    if let Some(expected) = h.get("if-match")
        && current
            .as_ref()
            .is_none_or(|o| format!("\"{}\"", o.etag) != *expected)
    {
        return response(412, String::new(), Vec::new());
    }
    if q.get("comp").map(String::as_str) == Some("block") && method == "PUT" {
        if h.get("content-md5").map(String::as_str) != Some(md5(body).as_str()) {
            return response(400, "x-ms-error-code: Md5Mismatch\r\n".into(), Vec::new());
        }
        state
            .blocks
            .entry(key.into())
            .or_default()
            .insert(q.get("blockid").ok_or("block id")?.clone(), body.to_vec());
        return response(201, format!("Content-MD5: {}\r\n", md5(body)), Vec::new());
    }
    if q.get("comp").map(String::as_str) == Some("blocklist") {
        if method == "GET" {
            if !state.blocks.contains_key(key) && !state.objects.contains_key(key) {
                return response(404, String::new(), Vec::new());
            }
            let mut xml = String::from("<BlockList><CommittedBlocks/><UncommittedBlocks>");
            for (id, bytes) in state.blocks.get(key).into_iter().flatten() {
                xml.push_str(&format!(
                    "<Block><Name>{id}</Name><Size>{}</Size></Block>",
                    bytes.len()
                ));
            }
            xml.push_str("</UncommittedBlocks></BlockList>");
            return response(200, String::new(), xml.into_bytes());
        }
        let xml = std::str::from_utf8(body)?;
        let mut bytes = Vec::new();
        for part in xml.split("<Latest>").skip(1) {
            let id = part.split("</Latest>").next().ok_or("latest")?;
            bytes.extend_from_slice(
                state
                    .blocks
                    .get(key)
                    .and_then(|b| b.get(id))
                    .ok_or("missing native block")?,
            );
        }
        if h.get("x-ms-blob-content-md5").map(String::as_str) != Some(md5(&bytes).as_str()) {
            return Err("committed native MD5".into());
        }
        state.next += 1;
        if let Some(previous) = state.objects.insert(
            key.into(),
            Object {
                etag: state.next,
                bytes,
            },
        ) {
            state.history.entry(key.into()).or_default().push(previous);
        }
        state.blocks.remove(key);
        return response(201, format!("ETag: \"{}\"\r\n", state.next), Vec::new());
    }
    if method == "PUT" {
        if h.get("content-md5").map(String::as_str) != Some(md5(body).as_str()) {
            return response(400, "x-ms-error-code: Md5Mismatch\r\n".into(), Vec::new());
        }
        state.next += 1;
        if let Some(previous) = state.objects.insert(
            key.into(),
            Object {
                etag: state.next,
                bytes: body.to_vec(),
            },
        ) {
            state.history.entry(key.into()).or_default().push(previous);
        }
        return response(201, format!("ETag: \"{}\"\r\n", state.next), Vec::new());
    }
    if method == "DELETE" && current.is_none() && state.blocks.remove(key).is_some() {
        return response(202, String::new(), Vec::new());
    }
    let Some(object) = current else {
        return response(404, String::new(), Vec::new());
    };
    if method == "DELETE" {
        if let Some(version) = q.get("versionid").or_else(|| q.get("snapshot")) {
            if let Some(versions) = state.history.get_mut(key) {
                versions.retain(|o| o.etag.to_string() != *version);
            }
        } else {
            state.objects.remove(key);
            state.blocks.remove(key);
        }
        return response(202, String::new(), Vec::new());
    }
    if !matches!(method, "GET" | "HEAD") {
        return Err("unexpected method".into());
    }
    let mut extra = format!(
        "ETag: \"{}\"\r\nContent-MD5: {}\r\nx-ms-legal-hold: false\r\n",
        object.etag,
        md5(&object.bytes)
    );
    if method == "HEAD" {
        return Ok((200, extra, Vec::new(), object.bytes.len()));
    }
    if let Some(range) = h.get("range") {
        let (start, end) = range
            .strip_prefix("bytes=")
            .ok_or("range")?
            .split_once('-')
            .ok_or("extent")?;
        let start = start.parse::<usize>()?;
        let end = end.parse::<usize>()?;
        let bytes = object
            .bytes
            .get(start..=end)
            .ok_or("range bounds")?
            .to_vec();
        extra = format!(
            "ETag: \"{}\"\r\nContent-MD5: {}\r\nContent-Range: bytes {start}-{end}/{}\r\n",
            object.etag,
            md5(&bytes),
            object.bytes.len()
        );
        return response(206, extra, bytes);
    }
    response(200, extra, object.bytes)
}

fn key_from_path(path: &str) -> Result<&str> {
    path.strip_prefix("/backups/")
        .ok_or_else(|| "fixture path".into())
}
