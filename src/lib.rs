#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all, clippy::result_unwrap_used, clippy::option_unwrap_used)]
//#![warn(clippy::restriction)]
//#![allow(clippy::implicit_return, clippy::missing_docs_in_private_items)]
//! A wee HTTPS request library powered by mio and rustls; no tokio and no openssl.
//!
//! `weeqwest` is inspired by and a reaction to `reqwest`, which is a
//! wonderfully powerful library, but a user would be rightfully dismayed to
//! learn they've pulled in 126 dependencies to send a single HTTP request.
//! `weeqwest` aims to be good enough for common uses with a small dependency
//! tree (currently 37 total dependencies) and at least as good performance.
//! This library does not aim to be a total replacement, but an alternative for
//! some use cases.
//!
//! If you don't mind blocking, `weeqwest` provides free functions that will do
//! blocking I/O on the current thread:
//! ```rust
//! let response = weeqwest::get("https://httpbin.org/get/").unwrap();
//! // Response body may not be UTF-8
//! println!("body = {}", std::str::from_utf8(response.bytes()).unwrap());
//! ```
//!
//! This crate also provides a `Client` for running multiple requests in
//! parallel on a background thread.

use crate::dns::DnsCache;
use std::io::Write;
use std::sync::{Arc, Mutex};

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

#[cfg(feature = "client")]
#[allow(missing_docs)]
pub mod client;
mod dns;
mod error;
mod parse;
#[cfg(feature = "client")]
mod tls;

#[cfg(feature = "client")]
pub use crate::client::Client;
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
    #[inline]
    pub fn get(uri: &str) -> Result<Self, Error> {
        Ok(Self {
            uri: http::HttpTryFrom::try_from(uri)?,
            method: http::Method::GET,
            headers: http::HeaderMap::new(),
            body: Vec::new(),
        })
    }

    /// Creates a default HTTP POST request
    #[inline]
    pub fn post(uri: &str) -> Result<Self, Error> {
        Ok(Self {
            uri: http::HttpTryFrom::try_from(uri)?,
            method: http::Method::POST,
            headers: http::HeaderMap::new(),
            body: Vec::new(),
        })
    }

    /// Adds a multipart/form-data body to an HTTP request, replacing the current body if one
    /// exists
    #[inline]
    pub fn file_form(mut self, filename: &str, contents: &[u8]) -> Self {
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
    #[inline]
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
    #[inline]
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.append(
            http::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
            http::header::HeaderValue::from_str(value).unwrap(),
        );
        self
    }

    #[inline]
    fn uri(&self) -> &http::Uri {
        &self.uri
    }

    #[inline]
    fn method(&self) -> &http::Method {
        &self.method
    }

    #[inline]
    fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    #[inline]
    fn body(&self) -> &[u8] {
        &self.body
    }

    #[inline]
    fn write_to<W: std::io::Write>(&self, stream: &mut W) -> Result<(), Error> {
        let host = self.uri().host().ok_or(Error::InvalidUrl)?;
        let path = self
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            .unwrap_or("/");

        // Write the HTTP header
        write!(
            stream,
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n",
            self.method().as_str(),
            path,
            host
        )?;

        for (key, value) in self.headers() {
            write!(stream, "{}: ", key)?;
            stream.write_all(value.as_bytes())?;
            stream.write_all(b"\r\n")?;
        }

        stream.write_all(b"\r\n")?;

        // Write the HTTP body
        stream.write_all(self.body())?;

        Ok(())
    }
}

/// Send an HTTPS request by creating a rustls ClientSession and driving it with blocking I/O on
/// the current thread
#[inline]
pub fn send(req: &Request) -> Result<Response, Error> {
    use std::io::Read;

    let host = req.uri().host().ok_or(Error::InvalidUrl)?;
    let addr = match DNS_CACHE.lock() {
        Ok(mut cache) => cache.lookup(host)?,
        Err(_) => DnsCache::new().lookup(host)?,
    };

    let scheme = req.uri().scheme_part().unwrap_or(&http::uri::Scheme::HTTPS);

    let mut raw = Vec::new();
    if scheme == &http::uri::Scheme::HTTPS {
        let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(443);
        let dns_name =
            webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;

        let mut sock = std::net::TcpStream::connect((addr, port))?;
        let mut sess = rustls::ClientSession::new(&TLS_CONFIG, dns_name);
        let mut tls = rustls::Stream::new(&mut sess, &mut sock);

        req.write_to(&mut tls)?;

        if let Err(e) = tls.read_to_end(&mut raw) {
            use std::error::Error;
            if e.description() != "CloseNotify alert received" {
                return Err(e.into());
            }
        }
    } else if scheme == &http::uri::Scheme::HTTP {
        let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(80);
        let mut stream = std::net::TcpStream::connect((addr, port))?;

        req.write_to(&mut stream)?;

        stream.read_to_end(&mut raw)?;
    } else {
        return Err(Error::UnsupportedScheme);
    }

    parse_response(&raw)
}

/// Send an HTTPS GET request
///
/// ```rust
/// let response = weeqwest::get("https://api.slack.com/api/api.test?foo=bar").unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.bytes());
/// ```
#[inline]
pub fn get(url: &str) -> Result<Response, Error> {
    send(&Request::get(url)?)
}

/// Send an HTTPS POST request
///
/// ```rust
/// let response = weeqwest::post("https://api.slack.com/api/api.test?foo=bar").unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.bytes());
/// ```
#[inline]
pub fn post(url: &str) -> Result<Response, Error> {
    send(&Request::post(url)?)
}

/// Parses a response from bytes
fn parse_response(raw: &[u8]) -> Result<Response, Error> {
    // Read the headers, increasing storage if needed
    let mut n_headers = 256;
    loop {
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

                let mut builder = http::response::Builder::new();

                builder.status(status).version(version);

                for h in headers.iter().filter(|h| !h.name.is_empty()) {
                    builder.header(h.name, h.value);
                }

                break Ok(Response::new(builder.body(body)?));
            }
            Err(e) => panic!("{:#?}", e),
        }
    }
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
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.inner.body()
    }

    /// The HTTP status code of a Response
    #[inline]
    pub fn status(&self) -> http::StatusCode {
        self.inner.status()
    }
}
