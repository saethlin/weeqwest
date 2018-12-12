use futures::sync::oneshot;
use mio::net::TcpStream;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::sync::mpsc;

mod error;
mod tls;
pub use crate::error::Error;
use crate::tls::TlsClient;

const NEW_CLIENT: mio::Token = mio::Token(0);

pub fn get(hostname: &str, path: &str) -> Result<Response, Error> {
    let addr = (hostname, 443)
        .to_socket_addrs()
        .map(|mut addrs| addrs.next())?
        .ok_or(Error::IpLookupFailed)?;

    let sock = TcpStream::connect(&addr)?;
    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str(hostname).map_err(|_| Error::InvalidHostname)?;
    let mut tlsclient = TlsClient::new(sock, dns_name);
    write!(
        tlsclient,
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: \
         close\r\nAccept-Encoding: identity\r\n\r\n",
        path, hostname
    )?;

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(4);
    tlsclient.register(&mut poll)?;
    loop {
        poll.poll(&mut events, None)?;
        for ev in events.iter() {
            tlsclient.ready(&mut poll, &ev)?;
        }
        if tlsclient.is_closed() {
            break;
        }
    }

    let raw = tlsclient.take_bytes();
    let body = parse_body_from(&raw)?;
    Ok(Response { raw, body })
}

/// A `Client` to make HTTP requests with.
///
/// A `Client` is a handle to a background thread that manages a mio Poll, and can be used to
/// make multiple requests asynchronously. If you only need to make one request or don't need
/// asynchronicity, consider using the free functions which will run a rustls session on the
/// current thread.
///
/// ```rust
/// let client = tiny_reqwest::Client::new().unwrap();
/// let handle = client.get("api.slack.com", "/api/api.test?foo=bar").unwrap();
/// // Some time later
/// let body = handle.wait().body().unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", body.as_slice());
/// ```
pub struct Client {
    sender: mpsc::Sender<(TlsClient, oneshot::Sender<Vec<u8>>)>,
    readiness: mio::SetReadiness,
}

impl Client {
    pub fn get(&self, hostname: &str, path: &str) -> Result<PendingRequest, Error> {
        let addr = (hostname, 443)
            .to_socket_addrs()
            .map(|mut addrs| addrs.next())?
            .ok_or(Error::IpLookupFailed)?;

        let sock = TcpStream::connect(&addr)?;
        let dns_name =
            webpki::DNSNameRef::try_from_ascii_str(hostname).map_err(|_| Error::InvalidHostname)?;
        let mut tlsclient = TlsClient::new(sock, dns_name);

        write!(
            tlsclient,
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: \
             close\r\nAccept-Encoding: identity\r\n\r\n",
            path, hostname
        )?;

        let (sender, receiver) = oneshot::channel();

        self.sender.send((tlsclient, sender)).unwrap();
        self.readiness.set_readiness(mio::Ready::readable())?;

        Ok(PendingRequest { receiver })
    }

    pub fn new() -> Self {
        let (registration, readiness) = mio::Registration::new2();
        let (sender, receiver) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let mut clients: Vec<(TlsClient, oneshot::Sender<Vec<u8>>)> = Vec::new();

            let mut poll = mio::Poll::new().unwrap();
            let mut events = mio::Events::with_capacity(4);
            poll.register(
                &registration,
                NEW_CLIENT,
                mio::Ready::readable(),
                mio::PollOpt::edge(),
            )
            .unwrap();

            loop {
                poll.poll(&mut events, None).unwrap();

                for ev in events.iter() {
                    if ev.token() == NEW_CLIENT {
                        // A new client has been attached to the poll loop
                        let (mut client, output): (TlsClient, _) = receiver.recv().unwrap();
                        // Pick an unused token value for the new client
                        for v in 1..usize::max_value() {
                            if !clients.iter().any(|c| c.0.token == mio::Token(v)) {
                                client.token = mio::Token(v);
                                break;
                            }
                        }
                        client.register(&mut poll).unwrap();
                        clients.push((client, output));
                    } else {
                        // Else, we got an event for a currently running client. Find and handle it
                        clients
                            .iter_mut()
                            .find(|(c, _)| c.token == ev.token())
                            .unwrap()
                            .0
                            .ready(&mut poll, &ev)
                            .unwrap();
                    }
                }

                // Events have been handled, see if any clients are done
                // This operation is a drain_filter
                let mut i = 0;
                while i != clients.len() {
                    if clients[i].0.is_closed() {
                        let (client, output_channel) = clients.remove(i);
                        output_channel.send(client.take_bytes()).unwrap();
                    } else {
                        i += 1;
                    }
                }
            }
        });

        Self { sender, readiness }
    }
}

pub struct PendingRequest {
    receiver: oneshot::Receiver<Vec<u8>>,
}

fn parse_body_from(raw: &[u8]) -> Result<Vec<u8>, httparse::Error> {
    // Reserve enough space to hold all the incoming bytes so no reallocation occurs
    let mut body = Vec::with_capacity(raw.len());

    // Read the headers, increasing storage if needed
    let mut headers = vec![httparse::EMPTY_HEADER; 256];
    let mut req = httparse::Response::new(&mut headers);
    while let Err(httparse::Error::TooManyHeaders) = req.parse(&raw) {
        headers.extend_from_slice(&[httparse::EMPTY_HEADER; 256]);
        req = httparse::Response::new(&mut headers);
    }

    // Initial parse fills out the request struct and jumps to the beginning of the chunks
    let body = match req.parse(&raw)? {
        httparse::Status::Complete(len) => {
            let mut remaining = &raw[len..];

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
            panic!("Entire request should have been read already but wasn't")
        }
    };

    Ok(body)
}

impl PendingRequest {
    pub fn wait(self) -> Result<Response, httparse::Error> {
        use futures::Future;
        let raw = self.receiver.wait().unwrap();
        let body = parse_body_from(&raw)?;
        Ok(Response { raw, body })
    }
}

pub struct Response {
    raw: Vec<u8>,
    body: Vec<u8>,
}

impl Response {
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn headers(&self) -> Vec<httparse::Header> {
        let mut headers = vec![httparse::EMPTY_HEADER; 256];
        let mut req = httparse::Response::new(&mut headers);
        while let Err(httparse::Error::TooManyHeaders) = req.parse(&self.raw) {
            headers.extend_from_slice(&[httparse::EMPTY_HEADER; 256]);
            req = httparse::Response::new(&mut headers);
        }

        headers
    }
}
