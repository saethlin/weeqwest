use crate::error::Error;
use crate::parse_response;
use crate::Response;
use futures::sync::oneshot;
use mio::net::TcpStream;
use std::collections::HashMap;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::sync::mpsc;

use crate::tls::TlsClient;

const NEW_CLIENT: mio::Token = mio::Token(0);

/// A `Client` to make HTTP requests with.
///
/// A `Client` is a handle to a background thread that manages a mio Poll, and can be used to
/// make multiple requests asynchronously. If you only need to make one request or don't need
/// asynchronicity, consider using the free functions which will run a rustls session on the
/// current thread.
///
/// ```rust
/// let mut client = weeqwest::Client::new();
/// let handle = client.get("https://api.slack.com/api/api.test?foo=bar").unwrap();
/// // Some time later
/// let response = handle.wait().unwrap();
/// assert_eq!("{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.text().unwrap());
/// ```
pub struct Client {
    sender: mpsc::Sender<(TlsClient, oneshot::Sender<Vec<u8>>)>,
    readiness: mio::SetReadiness,
    addrs: HashMap<(String, u16), std::net::SocketAddr>,
}

impl Client {
    pub fn send(&mut self, req: &http::Request<()>) -> Result<PendingRequest, Error> {
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

        let addr = match self.addrs.get(&(host.to_string(), port)) {
            Some(a) => *a,
            None => (host, port)
                .to_socket_addrs()
                .map(|mut addrs| addrs.next())?
                .ok_or(Error::IpLookupFailed)?,
        };

        let dns_name =
            webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;
        let sock = TcpStream::connect(&addr)?;
        let mut tlsclient = TlsClient::new(sock, dns_name);

        write!(
            tlsclient,
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n\r\n",
            req.method().as_str(),
            path,
            host
        )?;

        let (sender, receiver) = oneshot::channel();

        self.sender.send((tlsclient, sender)).unwrap();
        self.readiness.set_readiness(mio::Ready::readable())?;

        Ok(PendingRequest { receiver })
    }

    pub fn get(&mut self, url: &str) -> Result<PendingRequest, Error> {
        self.send(&http::Request::get(url).body(())?)
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
                        let (mut client, output_channel) = clients.remove(i);
                        output_channel.send(client.take_bytes()).unwrap();
                    } else {
                        i += 1;
                    }
                }
            }
        });

        Self {
            sender,
            readiness,
            addrs: HashMap::new(),
        }
    }
}

pub struct PendingRequest {
    receiver: oneshot::Receiver<Vec<u8>>,
}

impl PendingRequest {
    pub fn wait(self) -> Result<Response, Error> {
        use futures::Future;
        let raw = self.receiver.wait().unwrap();
        parse_response(&raw)
    }
}
