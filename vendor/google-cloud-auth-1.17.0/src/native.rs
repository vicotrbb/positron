// Copyright 2026 Google LLC
// Licensed under the Apache License, Version 2.0.
//! Caller-owned boundaries for the official native credential chain.

use std::{future::Future, path::Path, pin::Pin, time::Duration};
pub use zeroize::Zeroizing;
use zeroize::Zeroize;

/// A stable failure which never carries credential material or native output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("native identity input exceeds admission")]
    LimitExceeded,
    #[error("native identity service unavailable")]
    Unavailable,
    #[error("native identity configuration invalid")]
    InvalidConfiguration,
    #[error("native identity permission denied")]
    PermissionDenied,
    #[error("native identity file absent")]
    NotFound,
}

/// The result of an admitted native operation.
pub type Result<T> = std::result::Result<T, Error>;
/// A native operation borrowing its admitted owner.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// The native HTTP operation, with an owned zeroizing body.
pub struct Request {
    pub method: http::Method,
    pub url: String,
    pub headers: http::HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl Drop for Request {
    fn drop(&mut self) { self.url.zeroize(); }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Request { redacted native identity operation }")
    }
}

/// The fully collected, bounded native HTTP response.
pub struct Response {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Response { redacted native identity response }")
    }
}

/// Explicit admission, I/O, and cryptography owned by the embedding caller.
///
/// The owner must remain alive until spawned work and child cleanup finish.
pub trait Runtime: std::fmt::Debug + Send + Sync {
    fn read_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>>;
    fn http(&self, request: Request) -> BoxFuture<'_, Response>;
    fn execute<'a>(
        &'a self,
        command: &'a str,
        args: &'a [String],
        timeout: Duration,
    ) -> BoxFuture<'a, Zeroizing<Vec<u8>>>;
    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32]>;
    fn hmac_sha256(&self, key: &[u8], bytes: &[u8]) -> Result<[u8; 32]>;
    fn rsa_sign(&self, pem: &[u8], bytes: &[u8]) -> Result<Vec<u8>>;
    fn spawn(
        &self,
        work: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<tokio::task::JoinHandle<()>>;
}


pub(crate) const MAXIMUM_BYTES: usize = 131_072;

// Validate without constructing an owned value tree. This prevents malformed
// input or replacement of duplicate keys from dropping an unguarded partial tree.
#[derive(Default)]
struct JsonBounds { nodes: usize, strings: usize, limited: bool }
struct JsonValidator<'a> { bounds: &'a mut JsonBounds, depth: usize }
impl JsonBounds {
    fn strings<E: serde::de::Error>(&mut self, size: usize) -> std::result::Result<(), E> {
        self.strings = self.strings.saturating_add(size);
        if self.strings > MAXIMUM_BYTES { self.limited = true; return Err(E::custom("native JSON limit")); }
        Ok(())
    }
}
impl<'de> serde::de::DeserializeSeed<'de> for JsonValidator<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> std::result::Result<(), D::Error> {
        self.bounds.nodes = self.bounds.nodes.saturating_add(1);
        if self.depth > 32 || self.bounds.nodes > 2048 {
            self.bounds.limited = true;
            return Err(serde::de::Error::custom("native JSON limit"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for JsonValidator<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("native JSON") }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> { Ok(()) }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> { Ok(()) }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> { Ok(()) }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<(), E> {
        if value.is_finite() { Ok(()) } else { Err(E::custom("native JSON number invalid")) }
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<(), E> { self.bounds.strings(value.len()) }
    fn visit_string<E: serde::de::Error>(self, mut value: String) -> std::result::Result<(), E> {
        let result = self.bounds.strings(value.len()); value.zeroize(); result
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<(), A::Error> {
        while sequence.next_element_seed(JsonValidator { bounds: self.bounds, depth: self.depth + 1 })?.is_some() {}
        Ok(())
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        struct Keys(std::collections::BTreeSet<String>);
        impl Drop for Keys {
            fn drop(&mut self) { while let Some(mut key) = self.0.pop_first() { key.zeroize(); } }
        }
        let mut keys = Keys(std::collections::BTreeSet::new());
        while let Some(key) = map.next_key::<String>()? {
            let mut key = Zeroizing::new(key);
            self.bounds.strings::<A::Error>(key.len())?;
            if keys.0.contains(key.as_str()) { return Err(serde::de::Error::custom("native JSON duplicate key")); }
            keys.0.insert(std::mem::take(&mut *key));
            map.next_value_seed(JsonValidator { bounds: self.bounds, depth: self.depth + 1 })?;
        }
        Ok(())
    }
}

/// Owns parsed native secrets while bounding their allocation amplification.
pub(crate) struct SecretJson(serde_json::Value);
impl SecretJson {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM_BYTES { return Err(Error::LimitExceeded); }
        let mut bounds = JsonBounds::default();
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        use serde::de::DeserializeSeed as _;
        JsonValidator { bounds: &mut bounds, depth: 0 }.deserialize(&mut decoder)
            .and_then(|_| decoder.end())
            .map_err(|_| if bounds.limited { Error::LimitExceeded } else { Error::InvalidConfiguration })?;
        let value = serde_json::from_slice(bytes).map_err(|_| Error::InvalidConfiguration)?;
        Self::bounded(value)
    }
    pub(crate) fn bounded(value: serde_json::Value) -> Result<Self> {
        let guard = Self(value);
        let mut nodes = 0usize;
        let mut strings = 0usize;
        fn check(value: &serde_json::Value, depth: usize, nodes: &mut usize, strings: &mut usize) -> Result<()> {
            *nodes = nodes.saturating_add(1);
            if depth > 32 || *nodes > 2048 { return Err(Error::LimitExceeded); }
            match value {
                serde_json::Value::String(s) => *strings = strings.saturating_add(s.len()),
                serde_json::Value::Array(values) => for value in values { check(value, depth + 1, nodes, strings)?; },
                serde_json::Value::Object(values) => for (key, value) in values {
                    *strings = strings.saturating_add(key.len());
                    check(value, depth + 1, nodes, strings)?;
                },
                _ => {},
            }
            if *strings > MAXIMUM_BYTES { return Err(Error::LimitExceeded); }
            Ok(())
        }
        check(&guard.0, 0, &mut nodes, &mut strings)?;
        Ok(guard)
    }
    pub(crate) fn as_value(&self) -> &serde_json::Value { &self.0 }
    pub(crate) fn take_field(&mut self, field: &str) -> Option<Self> {
        self.0.get_mut(field).map(|value| Self(std::mem::take(value)))
    }
    pub(crate) fn into_value(mut self) -> serde_json::Value { std::mem::take(&mut self.0) }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn erase(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(s) => s.zeroize(),
                serde_json::Value::Array(values) => for value in values { erase(value); },
                serde_json::Value::Object(values) => for (mut key, mut value) in std::mem::take(values) {
                    key.zeroize(); erase(&mut value);
                },
                _ => {},
            }
            *value = serde_json::Value::Null;
        }
        erase(&mut self.0);
    }
}

pub(crate) fn redact_build_error(error: crate::build_errors::Error) -> crate::build_errors::Error {
    let mut native = Error::InvalidConfiguration;
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(current) = source {
        if let Some(value) = current.downcast_ref::<Error>() { native = *value; break; }
        source = current.source();
    }
    if error.is_loading() { crate::build_errors::Error::loading(native) }
    else if error.is_unknown_type() { crate::build_errors::Error::unknown_type(native) }
    else if error.is_not_supported() { crate::build_errors::Error::not_supported(native) }
    else { crate::build_errors::Error::parsing(native) }
}


#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpError {
    #[error("{0}")]
    Upstream(#[from] reqwest::Error),
    #[error("{0}")]
    Native(#[from] Error),
}
impl HttpError {
    pub(crate) fn is_decode(&self) -> bool {
        match self { Self::Upstream(e) => e.is_decode(), Self::Native(_) => false }
    }
    pub(crate) fn is_body(&self) -> bool {
        match self { Self::Upstream(e) => e.is_body(), Self::Native(_) => false }
    }
    pub(crate) fn retryable(&self) -> bool {
        match self {
            Self::Upstream(e) => e.is_connect() || e.is_request()
                || e.status().is_some_and(|s| s.is_server_error() || matches!(s.as_u16(), 408 | 429)),
            Self::Native(Error::Unavailable) => true,
            _ => false,
        }
    }
}

/// The private adapter keeps official request construction in its existing providers.
#[derive(Clone, Debug)]
pub(crate) enum HttpClient { Native(std::sync::Arc<dyn Runtime>), Upstream(reqwest::Client) }
impl HttpClient {
    pub(crate) fn new(runtime: Option<std::sync::Arc<dyn Runtime>>) -> Self {
        match runtime { Some(runtime) => Self::Native(runtime), None => Self::Upstream(reqwest::Client::new()) }
    }
    pub(crate) fn from_upstream(upstream: reqwest::Client) -> Self {
        Self::Upstream(upstream)
    }
    pub(crate) fn request(&self, method: http::Method, url: &str) -> RequestBuilder {
        match self {
            Self::Native(runtime) => RequestBuilder::Native {
                runtime: runtime.clone(),
                request: if url.len() > 4096 { Err(HttpError::Native(Error::LimitExceeded)) } else {
                    Ok(Request { method, url: url.to_owned(), headers: http::HeaderMap::new(), body: Zeroizing::new(Vec::new()) })
                },
            },
            Self::Upstream(client) => RequestBuilder::Upstream(client.request(method, url)),
        }
    }
    pub(crate) fn get(&self, url: &str) -> RequestBuilder { self.request(http::Method::GET, url) }
    pub(crate) fn post(&self, url: &str) -> RequestBuilder { self.request(http::Method::POST, url) }
    pub(crate) fn put(&self, url: &str) -> RequestBuilder { self.request(http::Method::PUT, url) }
}

pub(crate) enum RequestBuilder {
    Upstream(reqwest::RequestBuilder),
    Native { runtime: std::sync::Arc<dyn Runtime>, request: std::result::Result<Request, HttpError> },
}
impl RequestBuilder {
    pub(crate) fn header<K, V>(self, key: K, value: V) -> Self
    where http::header::HeaderName: TryFrom<K>, http::HeaderValue: TryFrom<V>,
          <http::header::HeaderName as TryFrom<K>>::Error: Into<http::Error>,
          <http::HeaderValue as TryFrom<V>>::Error: Into<http::Error> {
        match self {
            Self::Upstream(builder) => Self::Upstream(builder.header(key, value)),
            Self::Native { runtime, request } => {
                let request = request.and_then(|mut request| {
                    let key = http::header::HeaderName::try_from(key).map_err(|_| HttpError::Native(Error::InvalidConfiguration))?;
                    let mut value = http::HeaderValue::try_from(value).map_err(|_| HttpError::Native(Error::InvalidConfiguration))?;
                    value.set_sensitive(true);
                    request.headers.insert(key, value);
                    Ok(request)
                });
                Self::Native { runtime, request }
            }
        }
    }
    pub(crate) fn headers(self, headers: http::HeaderMap) -> Self {
        match self {
            Self::Upstream(builder) => Self::Upstream(builder.headers(headers)),
            Self::Native { runtime, request } => Self::Native { runtime, request: request.map(|mut request| {
                request.headers.extend(headers);
                for value in request.headers.values_mut() { value.set_sensitive(true); }
                request
            }) },
        }
    }
    pub(crate) fn json<T: serde::Serialize + ?Sized>(self, value: &T) -> Self {
        match self {
            Self::Upstream(builder) => Self::Upstream(builder.json(value)),
            Self::Native { runtime, request } => Self::Native { runtime, request: request.and_then(|mut request| {
                let body = Zeroizing::new(serde_json::to_vec(value).map_err(|_| HttpError::Native(Error::InvalidConfiguration))?);
                if body.len() > MAXIMUM_BYTES { return Err(Error::LimitExceeded.into()); }
                request.body = body;
                request.headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
                Ok(request)
            }) },
        }
    }
    pub(crate) fn form<T: serde::Serialize + ?Sized>(self, value: &T) -> Self {
        match self {
            Self::Upstream(builder) => Self::Upstream(builder.form(value)),
            Self::Native { runtime, request } => Self::Native { runtime, request: request.and_then(|mut request| {
                let body = Zeroizing::new(serde_urlencoded::to_string(value).map_err(|_| HttpError::Native(Error::InvalidConfiguration))?);
                if body.len() > MAXIMUM_BYTES { return Err(Error::LimitExceeded.into()); }
                request.body = Zeroizing::new(body.as_bytes().to_vec());
                request.headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/x-www-form-urlencoded"));
                Ok(request)
            }) },
        }
    }
    pub(crate) fn query<T: serde::Serialize + ?Sized>(self, value: &T) -> Self {
        match self {
            Self::Upstream(builder) => Self::Upstream(builder.query(value)),
            Self::Native { runtime, request } => Self::Native { runtime, request: request.and_then(|mut request| {
                let query = Zeroizing::new(serde_urlencoded::to_string(value).map_err(|_| HttpError::Native(Error::InvalidConfiguration))?);
                if request.url.len().saturating_add(query.len()).saturating_add(1) > 4096 { return Err(Error::LimitExceeded.into()); }
                let mut url = reqwest::Url::parse(&request.url).map_err(|_| HttpError::Native(Error::InvalidConfiguration))?;
                url.query_pairs_mut().extend_pairs(url::form_urlencoded::parse(query.as_bytes()));
                request.url.zeroize();
                request.url = url.to_string();
                Ok(request)
            }) },
        }
    }
    pub(crate) fn try_clone(&self) -> Option<Self> {
        match self {
            Self::Upstream(builder) => builder.try_clone().map(Self::Upstream),
            Self::Native { runtime, request } => Some(Self::Native { runtime: runtime.clone(), request: match request {
                Ok(request) => Ok(Request { method: request.method.clone(), url: request.url.clone(), headers: request.headers.clone(), body: Zeroizing::new(request.body.to_vec()) }),
                Err(HttpError::Native(error)) => Err((*error).into()),
                Err(_) => Err(Error::InvalidConfiguration.into()),
            } }),
        }
    }
    pub(crate) async fn send(self) -> std::result::Result<HttpResponse, HttpError> {
        match self {
            Self::Upstream(builder) => Ok(HttpResponse::Upstream(builder.send().await?)),
            Self::Native { runtime, request } => {
                let request = request?;
                let headers = request.headers.iter().try_fold(0usize, |n, (k,v)| n.checked_add(k.as_str().len()).and_then(|n| n.checked_add(v.len())))
                    .ok_or(Error::LimitExceeded)?;
                if headers > MAXIMUM_BYTES { return Err(Error::LimitExceeded.into()); }
                let response = runtime.http(request).await?;
                if response.body.len() > MAXIMUM_BYTES { return Err(Error::LimitExceeded.into()); }
                Ok(HttpResponse::Native(response))
            }
        }
    }
}

pub(crate) enum HttpResponse { Upstream(reqwest::Response), Native(Response) }
impl From<reqwest::Response> for HttpResponse { fn from(response: reqwest::Response) -> Self { Self::Upstream(response) } }
impl HttpResponse {
    pub(crate) fn status(&self) -> http::StatusCode { match self { Self::Upstream(r) => r.status(), Self::Native(r) => r.status } }
    pub(crate) fn headers(&self) -> &http::HeaderMap { match self { Self::Upstream(r) => r.headers(), Self::Native(r) => &r.headers } }
    pub(crate) async fn json<T: serde::de::DeserializeOwned>(self) -> std::result::Result<T, HttpError> {
        match self { Self::Upstream(r) => Ok(r.json().await?), Self::Native(r) => {
            let guard = SecretJson::parse(&r.body)?;
            T::deserialize(guard.as_value()).map_err(|_| HttpError::Native(Error::InvalidConfiguration))
        } }
    }
    pub(crate) async fn text(self) -> std::result::Result<Zeroizing<String>, HttpError> {
        match self { Self::Upstream(r) => Ok(Zeroizing::new(r.text().await?)), Self::Native(r) => std::str::from_utf8(&r.body).map(|text| Zeroizing::new(text.to_owned())).map_err(|_| HttpError::Native(Error::InvalidConfiguration)) }
    }
    pub(crate) async fn bytes(self) -> std::result::Result<bytes::Bytes, HttpError> {
        match self { Self::Upstream(r) => Ok(r.bytes().await?), Self::Native(r) => Ok(bytes::Bytes::from_owner(r.body)) }
    }
}


pub(crate) fn credential_error(error: Error) -> crate::errors::CredentialsError {
    crate::errors::CredentialsError::from_source(matches!(error, Error::Unavailable), error)
}

pub(crate) fn expires_after(seconds: u64) -> crate::Result<tokio::time::Instant> {
    tokio::time::Instant::now().checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| credential_error(Error::InvalidConfiguration))
}
