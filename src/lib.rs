#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all, clippy::result_unwrap_used, clippy::option_unwrap_used)]
#![warn(clippy::restriction)]
#![allow(
    clippy::implicit_return,
    clippy::missing_docs_in_private_items,
    clippy::missing_inline_in_public_items
)]
//! A wee HTTPS request library powered by rustls.
//!
//! `weeqwest` is inspired by and a reaction to `reqwest`, which is a
//! wonderfully powerful library, but has a dismaying large dependency tree,
//! which can significantly impact the compile time and code size of projects.
//! `weeqwest` aims to be good enough for common uses with a small dependency
//! tree and at least as good performance. This library does not aim to be
//! a total replacement, but an alternative for some use cases.
//!
//! ```rust
//! let request = weeqwest::get("https://httpbin.org/get/");
//! let response = tokio::runtime::Runtime::new()
//!    .unwrap()
//!    .block_on(request)
//!    .unwrap();
//! // Response body may not be UTF-8
//! println!("body = {}", std::str::from_utf8(response.body()).unwrap());
//! ```

use crate::dns::DnsCache;
use std::convert::TryFrom;
use std::sync::{Arc};
use futures_util::lock::Mutex;

lazy_static::lazy_static! {
    static ref DNS_CACHE: Arc<Mutex<DnsCache>> = Arc::new(Mutex::new(DnsCache::new()));
}

lazy_static::lazy_static! {
    static ref TLS_CONFIG: Arc<rustls::ClientConfig> = {
        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        Arc::new(config)
    };
}

mod dns;
mod error;
mod parse;

pub use crate::error::Error;

/// An HTTP Request
pub struct Request {
    uri: http::Uri,
    method: http::Method,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Request {
    /// Creates a default HTTP GET request
    pub fn get(uri: &str) -> Result<Self, Error> {
        let mut headers = http::HeaderMap::with_capacity(1);
        headers.insert("Accept-Encoding", http::HeaderValue::from_static("gzip"));
        Ok(Self {
            uri: http::Uri::try_from(uri)?,
            method: http::Method::GET,
            headers,
            body: Vec::new(),
        })
    }

    /// Creates a default HTTP POST request
    pub fn post(uri: &str) -> Result<Self, Error> {
        Ok(Self {
            uri: http::Uri::try_from(uri)?,
            method: http::Method::POST,
            headers: http::HeaderMap::new(),
            body: Vec::new(),
        })
    }

    /// Adds a multipart/form-data body to an HTTP request, replacing the current body if one
    /// exists
    pub fn file_form(mut self, filename: &str, contents: &[u8]) -> Self {
        use std::io::Write;
        let boundary = "BOUNDARYBOUNDARYBOUNDARY";

        // Write the contents of form into self.body
        self.body.clear();

        let _ = write!(
            self.body,
            "\r\n--{}\r\nContent-Disposition: form-data; name=\"file\"; filename={:?}\r\n\
             Content-Type: multipart/form-data\r\n\r\n",
            boundary, filename
        );
        self.body.extend_from_slice(&contents);
        self.body.extend_from_slice(b"\r\n");
        let _ = write!(self.body, "--{}--", boundary);

        self.headers.insert(
            "Content-Length",
            http::header::HeaderValue::from_str(&self.body.len().to_string()).unwrap(),
        );

        let content_type = format!("multipart/form-data; boundary={}", boundary);
        self.headers.insert(
            "Content-Type",
            http::header::HeaderValue::from_str(&content_type)
                .expect("Tried to construct an invalid Content-Type"),
        );

        self.headers.insert(
            "Content-Transfer-Encoding",
            http::header::HeaderValue::from_static("binary"),
        );

        self
    }

    /// Adds a text body to an HTTP request, replacing the current body if one exists
    pub fn json(mut self, text: String) -> Self {
        self.headers.insert(
            "Content-Length",
            http::header::HeaderValue::from_str(&text.len().to_string()).unwrap(),
        );
        self.headers.insert(
            "Content-Type",
            http::header::HeaderValue::from_static("application/json"),
        );
        self.body = text.into_bytes();
        self
    }

    /// Adds an HTTP header to a request
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.append(
            http::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
            http::header::HeaderValue::from_str(value).unwrap(),
        );
        self
    }

    fn uri(&self) -> &http::Uri {
        &self.uri
    }

    fn method(&self) -> &http::Method {
        &self.method
    }

    fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        &self.body
    }

    async fn write_to(
        &self,
        stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    ) -> Result<(), Error> {
        use tokio::io::AsyncWriteExt;

        let host = self.uri().host().ok_or(Error::InvalidUrl)?;
        let path = self
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            .unwrap_or("/");

        // Write the HTTP header
        let buf = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n",
            self.method().as_str(),
            path,
            host
        );
        stream.write_all(buf.as_bytes()).await?;

        for (key, value) in self.headers() {
            stream.write_all(key.as_str().as_bytes()).await?;
            stream.write_all(b": ").await?;
            stream.write_all(value.as_bytes()).await?;
            stream.write_all(b"\r\n").await?;
        }
        stream.write_all(b"\r\n").await?;

        // Write the HTTP body
        stream.write_all(self.body()).await?;

        Ok(())
    }
}

/// Send an HTTPS request by creating a rustls ClientSession and driving it with blocking I/O on
/// the current thread
pub async fn send(req: &Request) -> Result<Response, Error> {
    use tokio::io::AsyncWriteExt;
    use tokio::io::AsyncReadExt;

    let host = req.uri().host().ok_or(Error::InvalidUrl)?;
    let addr = match DNS_CACHE.try_lock() {
        Some(mut cache) => cache.lookup(host).await?,
        None => DnsCache::new().lookup(host).await?,
    };

    let scheme = req.uri().scheme().unwrap_or(&http::uri::Scheme::HTTPS);
    if scheme != &http::uri::Scheme::HTTPS {
        return Err(Error::UnsupportedScheme);
    }

    let port = req.uri().port_u16().unwrap_or(443);
    let stream = tokio::net::TcpStream::connect((addr, port)).await?;
    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;
    let connector = tokio_rustls::TlsConnector::from(TLS_CONFIG.clone());
    let mut tls = connector.connect(dns_name, stream).await?;

    req.write_to(&mut tls).await?;
    tls.flush().await?;

    let mut raw = Vec::new();
    if let Err(e) = tls.read_to_end(&mut raw).await {
        if &e.to_string() != "CloseNotify alert received" {
            return Err(e.into());
        }
    }

    parse_response(&raw)
}

/// Send an HTTPS GET request
///
/// ```rust
/// let request = weeqwest::get("https://api.slack.com/api/api.test?foo=bar");
/// let response = tokio::runtime::Runtime::new()
///    .unwrap()
///    .block_on(request)
///    .unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.body());
/// ```
pub async fn get(url: &str) -> Result<Response, Error> {
    send(&Request::get(url)?).await
}

/// Send an HTTPS POST request
///
/// ```rust
/// let request = weeqwest::post("https://api.slack.com/api/api.test?foo=bar");
/// let response = tokio::runtime::Runtime::new()
///    .unwrap()
///    .block_on(request)
///    .unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.body());
/// ```
pub async fn post(url: &str) -> Result<Response, Error> {
    send(&Request::post(url)?).await
}

/// Parses a response from bytes
fn parse_response(raw: &[u8]) -> Result<Response, Error> {
    // Read the headers, increasing storage if needed
    let mut n_headers = 256;
    let (builder, mut body) = loop {
        let mut headers = vec![httparse::EMPTY_HEADER; n_headers];
        let mut response = httparse::Response::new(&mut headers);

        match response.parse(&raw) {
            Err(httparse::Error::TooManyHeaders) => n_headers *= 2,
            Ok(httparse::Status::Partial) => panic!(
                "Entire response should have been read already but wasn't. \
                 This failure indicates a bug in this library."
            ),
            Ok(httparse::Status::Complete(len)) => {
                let mut remaining = &raw[len..];
                // Reserve enough space to hold all the incoming bytes so no reallocation occurs
                let mut body: Vec<u8> = Vec::with_capacity(remaining.len());

                // Parse the entire body
                if !remaining.is_empty() {
                    match httparse::parse_chunk_size(remaining) {
                        Err(httparse::InvalidChunkSize) => body.extend_from_slice(remaining),
                        Ok(httparse::Status::Complete((stopped, chunksize))) => {
                            let end = chunksize as usize + stopped;
                            body.extend(&remaining[stopped..chunksize as usize + stopped]);
                            remaining = &remaining[end..];

                            // Keep parsing until we run out of chunks, or have a parse error
                            while let Ok(httparse::Status::Complete((stopped, chunksize))) =
                                httparse::parse_chunk_size(remaining)
                            {
                                let end = chunksize as usize + stopped;
                                body.extend(&remaining[stopped..chunksize as usize + stopped]);
                                remaining = &remaining[end..];
                            }
                        }
                        error => panic!("{:#?}", error),
                    }
                }

                let status = if let Some(s) = response.code {
                    s
                } else {
                    return Err(Error::Parse(httparse::Error::Status));
                };

                let version = match response.version {
                    Some(0) => http::Version::HTTP_10,
                    Some(1) => http::Version::HTTP_11,
                    _ => unimplemented!("This library does not support HTTP/2 responses"),
                };

                let mut builder = http::response::Builder::new()
                    .status(status)
                    .version(version);

                for h in headers.iter().filter(|h| !h.name.is_empty()) {
                    builder = builder.header(h.name, h.value);
                }

                break (builder, body);
            }
            Err(e) => panic!("{:#?}", e),
        }
    };
    if builder
        .headers_ref()
        .map(|h| h.get_all("Content-Encoding").iter().any(|v| v == "gzip"))
        .unwrap_or(false)
    {
        use std::io::Read;
        let mut decoder = libflate::gzip::Decoder::new(&body[..])?;
        let mut decoded_body = Vec::new();
        decoder.read_to_end(&mut decoded_body)?;
        body = decoded_body;
    }

    Ok(Response::new(builder.body(body)?))
}

/// A parsed HTTP response
pub struct Response {
    inner: http::Response<Vec<u8>>,
}

impl Response {
    fn new(inner: http::Response<Vec<u8>>) -> Self {
        Self { inner }
    }

    /// The body of an HTTP Response, may not be UTF-8
    pub fn body(&self) -> &[u8] {
        &self.inner.body()
    }

    /// The HTTP status code of a Response
    pub fn status(&self) -> http::StatusCode {
        self.inner.status()
    }
}
