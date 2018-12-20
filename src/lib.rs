use std::io::Write;
use std::net::ToSocketAddrs;

mod client;
mod error;
mod session;
mod tls;

pub use crate::client::Client;
pub use crate::error::Error;
pub use crate::session::Session;

pub fn send(req: &http::Request<()>) -> Result<http::Response<Vec<u8>>, Error> {
    use std::io::Read;
    assert!(
        req.version() == http::Version::HTTP_11,
        "only supports HTTP/1.1"
    );

    let host = req.uri().host().ok_or(Error::InvalidUrl)?;
    let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(443);
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    let addr = (host, port)
        .to_socket_addrs()
        .map(|mut addrs| addrs.next())?
        .ok_or(Error::IpLookupFailed)?;

    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;
    let mut sock = std::net::TcpStream::connect(&addr)?;
    let mut sess = rustls::ClientSession::new(&tls::CONFIG, dns_name);
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    write!(
        tls,
        "{} {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\r\n",
        req.method().as_str(),
        path,
        host
    )?;

    let mut raw = Vec::new();
    if let Err(e) = tls.read_to_end(&mut raw) {
        use std::error::Error;
        if e.description() != "CloseNotify alert received" {
            return Err(e.into());
        }
    }

    Ok(parse_response(raw)?)
}

/// Send an HTTP GET request
///
/// ```rust
/// let response = tiny_reqwest::get("api.slack.com", "/api/api.test?foo=bar").unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.body());
/// ```
pub fn get(hostname: &str, path: &str) -> Result<http::Response<Vec<u8>>, Error> {
    use std::io::Read;
    let addr = (hostname, 443)
        .to_socket_addrs()
        .map(|mut addrs| addrs.next())?
        .ok_or(Error::IpLookupFailed)?;

    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str(hostname).map_err(|_| Error::InvalidHostname)?;
    let mut sock = std::net::TcpStream::connect(&addr)?;
    let mut sess = rustls::ClientSession::new(&tls::CONFIG, dns_name);
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    write!(
        tls,
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\r\n",
        path, hostname
    )?;

    let mut raw = Vec::new();
    if let Err(e) = tls.read_to_end(&mut raw) {
        use std::error::Error;
        if e.description() != "CloseNotify alert received" {
            return Err(e.into());
        }
    }

    Ok(parse_response(raw)?)
}

fn parse_response(raw: Vec<u8>) -> Result<http::Response<Vec<u8>>, Error> {
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

        httparse::Status::Partial => {
            panic!("Entire response should have been read already but wasn't")
        }
    };

    let status = response.code.unwrap();

    let version = match response.version {
        Some(0) => http::Version::HTTP_10,
        Some(1) => http::Version::HTTP_11,
        _ => unreachable!(),
    };

    let mut builder = http::response::Builder::new();

    builder.status(status).version(version);

    for h in headers.iter().filter(|h| !h.name.is_empty()) {
        builder.header(h.name, h.value);
    }

    Ok(builder.body(body)?)
}
