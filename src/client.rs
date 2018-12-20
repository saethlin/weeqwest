use crate::error::Error;
use crate::parse_response;
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
/// let client = tiny_reqwest::Client::new();
/// let handle = client.get("api.slack.com", "/api/api.test?foo=bar").unwrap();
/// // Some time later
/// let response = handle.wait().unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.body());
/// ```
pub struct Client {
    sender: mpsc::Sender<(TlsClient, oneshot::Sender<Vec<u8>>)>,
    readiness: mio::SetReadiness,
    addrs: HashMap<String, std::net::SocketAddr>,
}

impl Client {
    pub fn get(&mut self, hostname: &str, path: &str) -> Result<PendingRequest, Error> {
        let addr = self.addrs.entry(hostname.to_string()).or_insert_with(|| {
            (hostname, 443)
                .to_socket_addrs()
                .map(|mut addrs| addrs.next())
                .unwrap()
                .ok_or(Error::IpLookupFailed)
                .unwrap()
        }); // TODO: Remove the unwraps

        let sock = TcpStream::connect(&addr)?;
        let dns_name =
            webpki::DNSNameRef::try_from_ascii_str(hostname).map_err(|_| Error::InvalidHostname)?;
        let mut tlsclient = TlsClient::new(sock, dns_name);

        write!(
            tlsclient,
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Accept-Encoding: identity\r\n\r\n",
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
    pub fn wait(self) -> Result<http::Response<Vec<u8>>, Error> {
        use futures::Future;
        let raw = self.receiver.wait().unwrap();
        parse_response(raw)
    }
}
