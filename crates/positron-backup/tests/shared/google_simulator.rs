//! Bounded independent JSON API fixture; no provider qualification is implied.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
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
    generation: u64,
    live: bool,
    bytes: Vec<u8>,
}
struct Session {
    key: String,
    total: usize,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct State {
    generation: u64,
    objects: BTreeMap<String, Vec<Object>>,
    sessions: BTreeMap<String, Session>,
}
pub type Race = Arc<Mutex<Option<(String, String)>>>;
pub type Replies = Arc<Mutex<VecDeque<(String, u16, String, Value)>>>;
pub struct Server {
    pub replies: Replies,
    pub race: Race,
    pub address: SocketAddr,
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
        let replies: Replies = Default::default();
        let injected = replies.clone();
        let race: Race = Default::default();
        let interleaving = race.clone();
        let worker = thread::spawn(move || {
            let mut state = State::default();
            let mut count = 0;
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        count += 1;
                        if count > 10000 {
                            return Err("request bound".into());
                        }
                        serve(stream, &mut state, &injected, &interleaving)?;
                    },
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
            replies,
            race,
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
                .expect("fixture protocol failure");
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
fn metadata(key: &str, object: &Object) -> Value {
    json!({"name":key, "generation":object.generation.to_string(), "metageneration":"1", "size":object.bytes.len().to_string(), "crc32c":STANDARD.encode(crc32c::crc32c(&object.bytes).to_be_bytes())})
}
fn serve(mut stream: TcpStream, state: &mut State, injected: &Replies, race: &Race) -> Result<()> {
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
    let overridden = {
        let mut replies = injected.lock().map_err(|_| "fixture reply lock")?;
        if replies
            .front()
            .is_some_and(|(target, _, _, _)| target == &format!("{method} {path}"))
        {
            replies.pop_front()
        } else {
            None
        }
    };
    let (status, extra, reply) = if let Some((_, status, headers, value)) = overridden {
        (status, headers, serde_json::to_vec(&value)?)
    } else {
        dispatch(state, method, path, &query, &headers, body)?
    };
    // An independent native writer conditionally publishes after an absence
    // observation, before the cleanup client can request another inventory.
    if status == 404 && method == "GET" {
        let pending = {
            let mut pending = race.lock().map_err(|_| "fixture race lock")?;
            if pending.as_ref().is_some_and(|(target, _)| target == path) {
                pending.take()
            } else {
                None
            }
        };
        if let Some((target, source)) = pending {
            let target = decode(
                target
                    .strip_prefix("/storage/v1/b/simulation-bucket/o/")
                    .ok_or("race target")?,
            )?;
            let bytes = state
                .objects
                .get(&source)
                .and_then(|objects| objects.iter().find(|o| o.live))
                .ok_or("race source")?
                .bytes
                .clone();
            let query = BTreeMap::from([
                ("name".into(), target),
                ("ifGenerationMatch".into(), "0".into()),
            ]);
            let published = dispatch(
                state,
                "POST",
                "/upload/storage/v1/b/simulation-bucket/o",
                &query,
                &BTreeMap::new(),
                &bytes,
            )?;
            if published.0 != 200 {
                return Err("independent conditional publication failed".into());
            }
        }
    }
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
        reply.len(),
        extra
    )?;
    stream.write_all(&reply)?;
    Ok(())
}
type Reply = (u16, String, Vec<u8>);
fn reply(status: u16, value: Value) -> Result<Reply> {
    Ok((status, String::new(), serde_json::to_vec(&value)?))
}
fn dispatch(
    state: &mut State,
    method: &str,
    path: &str,
    q: &BTreeMap<String, String>,
    h: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<Reply> {
    let base = "/storage/v1/b/simulation-bucket";
    if path == base {
        return reply(
            200,
            json!({"name":"simulation-bucket","projectNumber":"123","location":"US","versioning":{"enabled":true},"softDeletePolicy":{"retentionDurationSeconds":"0"}}),
        );
    }
    if let Some(id) = q.get("upload_id") {
        if method == "DELETE" {
            state.sessions.remove(id);
            return reply(499, json!({}));
        }
        let session = state.sessions.get_mut(id).ok_or("unknown session")?;
        let range = h.get("content-range").ok_or("session range")?;
        if !range.starts_with("bytes */") {
            let extent = range
                .strip_prefix("bytes ")
                .ok_or("range")?
                .split('/')
                .next()
                .ok_or("extent")?;
            let (start, _) = extent.split_once('-').ok_or("extent")?;
            if start.parse::<usize>()? != session.bytes.len() {
                return reply(400, json!({}));
            }
            session.bytes.extend_from_slice(body);
        }
        if session.bytes.len() == session.total {
            state.generation += 1;
            let object = Object {
                generation: state.generation,
                live: true,
                bytes: session.bytes.clone(),
            };
            let value = metadata(&session.key, &object);
            let objects = state.objects.entry(session.key.clone()).or_default();
            for old in objects.iter_mut() {
                old.live = false;
            }
            objects.push(object);
            return reply(200, value);
        }
        let extra = if session.bytes.is_empty() {
            String::new()
        } else {
            format!("Range: bytes=0-{}\r\n", session.bytes.len() - 1)
        };
        return Ok((308, extra, Vec::new()));
    }
    if path == "/upload/storage/v1/b/simulation-bucket/o" {
        if q.get("uploadType").is_some_and(|v| v == "resumable") {
            let value: Value = serde_json::from_slice(body)?;
            let key = value
                .get("name")
                .and_then(Value::as_str)
                .ok_or("session name")?
                .to_owned();
            let total = h
                .get("x-upload-content-length")
                .ok_or("session length")?
                .parse()?;
            let id = format!("session-{}", state.sessions.len());
            state.sessions.insert(
                id.clone(),
                Session {
                    key,
                    total,
                    bytes: Vec::new(),
                },
            );
            return Ok((
                200,
                format!(
                    "Location: https://storage.googleapis.com/upload/storage/v1/b/simulation-bucket/o?upload_id={id}\r\n"
                ),
                Vec::new(),
            ));
        }
        let key = q.get("name").ok_or("object name")?;
        let expected = q
            .get("ifGenerationMatch")
            .ok_or("conditional mutation")?
            .parse::<u64>()?;
        let current = state
            .objects
            .get(key)
            .and_then(|v| v.iter().find(|o| o.live))
            .map(|o| o.generation)
            .unwrap_or(0);
        if expected != current {
            return reply(412, json!({}));
        }
        state.generation += 1;
        let object = Object {
            generation: state.generation,
            live: true,
            bytes: body.to_vec(),
        };
        let value = metadata(key, &object);
        let objects = state.objects.entry(key.clone()).or_default();
        for old in objects.iter_mut() {
            old.live = false;
        }
        objects.push(object);
        return reply(200, value);
    }
    if path == format!("{base}/o") {
        if q.get("softDeleted").is_some_and(|v| v == "true") {
            return reply(200, json!({"items":[]}));
        }
        let prefix = q.get("prefix").ok_or("prefix")?;
        let versions = q.get("versions").is_some_and(|v| v == "true");
        let mut items = Vec::new();
        for (key, objects) in &state.objects {
            if key.starts_with(prefix) {
                for object in objects
                    .iter()
                    .rev()
                    .filter(|object| versions || object.live)
                {
                    items.push(metadata(key, object));
                }
            }
        }
        let offset = q
            .get("pageToken")
            .map(|v| v.parse::<usize>())
            .transpose()?
            .unwrap_or(0);
        let limit = q.get("maxResults").ok_or("limit")?.parse::<usize>()?;
        let more = items.len() > offset + limit;
        let page: Vec<_> = items.into_iter().skip(offset).take(limit).collect();
        let mut value = json!({"items":page});
        if more {
            value["nextPageToken"] = json!((offset + limit).to_string());
        }
        return reply(200, value);
    }
    let Some(encoded) = path.strip_prefix(&format!("{base}/o/")) else {
        return reply(404, json!({}));
    };
    let key = decode(encoded)?;
    let Some(objects) = state.objects.get_mut(&key) else {
        return reply(404, json!({}));
    };
    let generation = q.get("generation").map(|v| v.parse::<u64>()).transpose()?;
    let index = match generation {
        Some(g) => objects.iter().position(|o| o.generation == g),
        None => objects.iter().position(|o| o.live),
    };
    let Some(index) = index else {
        return reply(404, json!({}));
    };
    let object = objects.get(index).ok_or("object index")?;
    if q.get("ifGenerationMatch")
        .is_some_and(|v| v != &object.generation.to_string())
        || q.get("ifMetagenerationMatch").is_some_and(|v| v != "1")
    {
        return reply(412, json!({}));
    }
    if method == "DELETE" {
        if generation.is_some() {
            objects.remove(index);
        } else {
            objects.get_mut(index).ok_or("live generation")?.live = false;
        }
        if objects.is_empty() {
            state.objects.remove(&key);
        }
        return Ok((204, String::new(), Vec::new()));
    }
    if q.get("alt").is_some_and(|v| v == "media") {
        if let Some(range) = h.get("range") {
            let (start, end) = range
                .strip_prefix("bytes=")
                .ok_or("range")?
                .split_once('-')
                .ok_or("range")?;
            let start = start.parse::<usize>()?;
            let end = end.parse::<usize>()?;
            return Ok((
                206,
                format!(
                    "Content-Range: bytes {start}-{end}/{}\r\n",
                    object.bytes.len()
                ),
                object
                    .bytes
                    .get(start..=end)
                    .ok_or("range bounds")?
                    .to_vec(),
            ));
        }
        return Ok((200, String::new(), object.bytes.clone()));
    }
    reply(200, metadata(&key, object))
}
