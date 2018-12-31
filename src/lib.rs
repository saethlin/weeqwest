//! # weeqwest
//!
//! This crate is an 80% solution for making HTTP requests. It provides a minimal set of
//! features that can be implemented with high performance and a small dependency tree.
//! Wheras `reqwest` provides a super-powered `Client` that does all the things, `weeqwest`
//! provides more ways to send requests, so you can do the fastest thing for your workload.
//!
//! If you just need to make a single GET
//! ```rust
//! # fn run() -> Result<(), weeqwest::Error> {
//! let response = weeqwest::get("https://www.rust-lang.org")?;
//! println!("body = {:?}", response.text()?); // Response body may not be UTF-8
//! # Ok(())
//! # }
//! ```
//!
//! Unlike `reqwest`, the free functions are faster than constructing and using a [`Client`][Client].
//!
//! This crate also provides a [`Client`][Client] for doing asynchronous requests, and a `Session` which uses
//! HTTP keep-alive to make consecutive requests to the same domain much faster, though not in
//! parallel.

use crate::dns::DnsCache;
use std::io::Write;
use std::sync::{Arc, Mutex};

lazy_static::lazy_static! {
    pub static ref DNS_CACHE: Arc<Mutex<DnsCache>> = Arc::new(Mutex::new(DnsCache::new()));
}

mod client;
mod dns;
mod error;
mod session;
mod tls;

pub use crate::client::Client;
pub use crate::error::Error;
pub use crate::session::Session;

pub struct Request {
    uri: http::Uri,
    method: http::Method,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Request {
    pub fn get(uri: &str) -> Result<Self, Error> {
        Ok(Self {
            uri: http::HttpTryFrom::try_from(uri)?,
            method: http::Method::GET,
            headers: http::HeaderMap::new(),
            body: Vec::new(),
        })
    }

    pub fn post(uri: &str) -> Result<Self, Error> {
        Ok(Self {
            uri: http::HttpTryFrom::try_from(uri)?,
            method: http::Method::POST,
            headers: http::HeaderMap::new(),
            body: Vec::new(),
        })
    }

    pub fn form(mut self, form: &[(&str, &[u8])]) -> Self {
        use rand_core::{RngCore, SeedableRng};
        let mut boundary = [0u8; 70];
        let mut rng = ::rand_hc::Hc128Rng::seed_from_u64(0);
        // Cross our fingers and hope we don't have a collision
        // TODO: Use more range in here. Possibly all of it?
        rng.fill_bytes(&mut boundary);
        for b in boundary.iter_mut() {
            *b = (*b % 26) + 97;
        }
        let boundary = std::str::from_utf8(&boundary).unwrap();

        // Write the contents of form into self.body
        self.body.clear();

        for (name, item) in form {
            write!(
                self.body,
                "\r\n--{}\r\nContent-Disposition: form-data; name={:?}\r\n\r\n",
                boundary, name
            )
            .unwrap();
            self.body.extend_from_slice(&item);
            self.body.extend_from_slice(b"\r\n");
        }
        write!(self.body, "--{}--", boundary).unwrap();

        self.headers.insert(
            "Content-Length",
            http::header::HeaderValue::from_str(&self.body.len().to_string()).unwrap(),
        );

        let content_type = format!("multipart/form-data; boundary={}", boundary);
        self.headers.insert(
            "Content-Type",
            http::header::HeaderValue::from_str(&content_type).unwrap(),
        );

        self
    }

    pub fn text(mut self, text: String) -> Self {
        self.headers.insert(
            "Content-Length",
            http::header::HeaderValue::from_str(&text.len().to_string()).unwrap(),
        );
        self.headers.insert(
            "Content-Type",
            http::header::HeaderValue::from_static("text"),
        );
        self.body = text.into_bytes();
        self
    }

    pub fn uri(&self) -> &http::Uri {
        &self.uri
    }

    pub fn method(&self) -> &http::Method {
        &self.method
    }

    pub fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    fn write_to(&self, tls: &mut std::io::Write) -> Result<(), Error> {
        let host = self.uri().host().ok_or(Error::InvalidUrl)?;
        let path = self
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");

        // Write the HTTP header
        write!(
            tls,
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n",
            self.method().as_str(),
            path,
            host
        )?;

        for (key, value) in self.headers() {
            write!(tls, "{}: ", key)?;
            tls.write_all(value.as_bytes())?;
            tls.write_all(b"\r\n")?;
        }

        tls.write_all(b"\r\n")?;

        // Write the HTTP body
        tls.write_all(self.body())?;

        Ok(())
    }
}

pub fn send(req: &Request) -> Result<Response, Error> {
    use std::io::Read;

    let host = req.uri().host().ok_or(Error::InvalidUrl)?;
    let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(443);

    let addr = DNS_CACHE.lock().unwrap().lookup(host.to_string(), port)?;

    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;
    let mut sock = std::net::TcpStream::connect(&addr)?;
    let mut sess = rustls::ClientSession::new(&tls::CONFIG, dns_name);
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    // Send the request
    req.write_to(&mut tls)?;

    let mut raw = Vec::new();
    if let Err(e) = tls.read_to_end(&mut raw) {
        use std::error::Error;
        if e.description() != "CloseNotify alert received" {
            return Err(e.into());
        }
    }

    parse_response(&raw)
}

/// Send an HTTP GET request
///
/// ```rust
/// let response = weeqwest::get("https://api.slack.com/api/api.test?foo=bar").unwrap();
/// assert_eq!("{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.text().unwrap());
/// ```
pub fn get(url: &str) -> Result<Response, Error> {
    send(&Request::get(url)?)
}

pub fn post(url: &str) -> Result<Response, Error> {
    send(&Request::post(url)?)
}

fn parse_response(raw: &[u8]) -> Result<Response, Error> {
    // Read the headers, increasing storage if needed
    let mut headers = vec![httparse::EMPTY_HEADER; 256];
    let mut response = httparse::Response::new(&mut headers);
    while let Err(httparse::Error::TooManyHeaders) = response.parse(&raw) {
        headers = vec![httparse::EMPTY_HEADER; headers.len() + 256];
        response = httparse::Response::new(&mut headers);
    }

    // Initial parse fills out the response struct and jumps to the beginning of the chunks
    let body = match response.parse(&raw)? {
        httparse::Status::Complete(len) => {
            let mut remaining = &raw[len..];
            // Reserve enough space to hold all the incoming bytes so no reallocation occurs
            let mut body = Vec::with_capacity(remaining.len());

            // Keep parsing until we run out of chunks, or have a parse error
            while let Ok(httparse::Status::Complete((stopped, chunksize))) =
                httparse::parse_chunk_size(remaining)
            {
                let end = chunksize as usize + stopped;
                body.extend(&remaining[stopped..chunksize as usize + stopped]);
                remaining = &remaining[end..];
            }

            body
        }

        httparse::Status::Partial => panic!(
            "Entire response should have been read already but wasn't. This failure indicates a bug in this library."
        ),
    };

    let status = response.code.unwrap();

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

    Ok(Response::new(builder.body(body)?))
}

pub struct Response {
    inner: http::Response<Vec<u8>>,
}

impl Response {
    fn new(inner: http::Response<Vec<u8>>) -> Self {
        Self { inner }
    }

    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.inner.body())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.inner.body()
    }

    pub fn status(&self) -> http::StatusCode {
        self.inner.status()
    }
}
