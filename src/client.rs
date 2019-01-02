use crate::tls::TlsClient;
use crate::{parse_response, Error, Request, Response};
use futures::sync::oneshot;
use mio::net::TcpStream;
use std::net::SocketAddr;
use std::sync::mpsc;

const NEW_CLIENT: mio::Token = mio::Token(0);

/// A `Client` to make concurrent HTTP requests with.
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
    sender: mpsc::SyncSender<(TlsClient, oneshot::Sender<Vec<u8>>)>,
    readiness: mio::SetReadiness,
}

impl Client {
    pub fn send(&mut self, req: &Request) -> Result<PendingRequest, Error> {
        let host = req.uri().host().ok_or(Error::InvalidUrl)?;
        let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(443);

        let addr = crate::DNS_CACHE.lock().unwrap().lookup(host)?;

        let dns_name =
            webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;

        let sock = TcpStream::connect(&SocketAddr::new(addr, port))?;
        let mut tlsclient = TlsClient::new(sock, dns_name);

        req.write_to(&mut tlsclient)?;

        let (sender, receiver) = oneshot::channel();

        // TODO: If the background thread panics, the receiver will have hung up, which will cause
        // this call to return Err. Unclear if this is something we should try to notify the user
        // about more gracefully
        self.sender.send((tlsclient, sender)).unwrap();
        self.readiness.set_readiness(mio::Ready::readable())?;

        Ok(PendingRequest { receiver })
    }

    pub fn get(&mut self, url: &str) -> Result<PendingRequest, Error> {
        self.send(&Request::get(url)?)
    }

    pub fn new() -> Self {
        let (registration, readiness) = mio::Registration::new2();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

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
                        // TODO: If a user has dropped the receiver, this returns an error
                        // If they're doing that, they should probably get a helpful log!, since
                        // it's possible they don't care about the result of a side-effecty request
                        let _ = output_channel.send(client.take_bytes());
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

impl PendingRequest {
    pub fn wait(self) -> Result<Response, Error> {
        use futures::Future;
        let raw = self.receiver.wait().unwrap();
        parse_response(&raw)
    }
}
