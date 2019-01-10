#[cfg(feature = "tls")]
use crate::tls::TlsClient;
use crate::{parse_response, Error, Request, Response};
use futures::sync::oneshot;
use std::net::SocketAddr;
use std::sync::mpsc;

const NEW_CLIENT: mio::Token = mio::Token(0);

/// A `Client` to make concurrent HTTP requests with.
///
/// A `Client` is a handle to a background thread that manages a mio Poll, and can be used to
/// make multiple requests asynchronously. If you only need to make one request or don't need
/// asynchronicity, consider using the free functions which will send a request on the
/// current thread.
///
/// ```rust
/// let mut client = weeqwest::Client::new();
/// let handle = client.get("https://api.slack.com/api/api.test?foo=bar").unwrap();
/// // Some time later
/// let response = handle.wait().unwrap();
/// assert_eq!(b"{\"ok\":true,\"args\":{\"foo\":\"bar\"}}", response.bytes());
/// ```
pub struct Client {
    sender: mpsc::SyncSender<(Request, oneshot::Sender<Result<Vec<u8>, Error>>)>,
    readiness: mio::SetReadiness,
}

enum Session {
    Http {
        // Gonna be some raw mio stuff in this
        stream: mio::net::TcpStream,
        token: mio::Token,
        buf: Vec<u8>,
        is_closed: bool,
    },
    #[cfg(feature = "tls")]
    Tls {
        stream: TlsClient, // All the mio stuff is handled by this
    },
}

impl Session {
    // Needs to be called inside the background thread so that we can pick a valid token
    #[cfg(feature = "tls")]
    fn init(req: &crate::Request, token: mio::Token) -> Result<Self, Error> {
        let host = req.uri().host().ok_or(Error::InvalidUrl)?;
        let addr = crate::DNS_CACHE.lock().unwrap().lookup(host)?;

        let scheme = req.uri().scheme_part().unwrap_or(&http::uri::Scheme::HTTPS);

        if scheme == &http::uri::Scheme::HTTPS {
            let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(443);
            let addr = SocketAddr::new(addr, port);
            let dns_name =
                webpki::DNSNameRef::try_from_ascii_str(host).map_err(|_| Error::InvalidHostname)?;

            let sock = mio::net::TcpStream::connect(&addr)?;
            let mut stream = TlsClient::new(sock, dns_name, token);

            req.write_to(&mut stream)?;
            Ok(Session::Tls { stream })
        } else if scheme == &http::uri::Scheme::HTTP {
            let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(80);
            let addr = SocketAddr::new(addr, port);
            let mut stream = mio::net::TcpStream::connect(&addr)?;
            req.write_to(&mut stream)?;
            Ok(Session::Http {
                stream,
                token,
                buf: Vec::new(),
                is_closed: false,
            })
        } else {
            Err(Error::UnsupportedScheme)
        }
    }

    #[cfg(not(feature = "tls"))]
    fn init(req: &crate::Request, token: mio::Token) -> Result<Self, Error> {
        let host = req.uri().host().ok_or(Error::InvalidUrl)?;
        let addr = crate::DNS_CACHE.lock().unwrap().lookup(host)?;

        let scheme = req.uri().scheme_part().unwrap_or(&http::uri::Scheme::HTTPS);

        if scheme == &http::uri::Scheme::HTTP {
            let port = req.uri().port_part().map(|p| p.as_u16()).unwrap_or(80);
            let addr = SocketAddr::new(addr, port);
            let mut stream = mio::net::TcpStream::connect(&addr)?;
            req.write_to(&mut stream)?;
            Ok(Session::Http {
                stream,
                token,
                buf: Vec::new(),
                is_closed: false,
            })
        } else {
            Err(Error::UnsupportedScheme)
        }
    }

    fn token(&self) -> mio::Token {
        match self {
            Session::Http { token, .. } => *token,
            #[cfg(feature = "tls")]
            Session::Tls { stream, .. } => stream.token(),
        }
    }

    fn send_output(self, output: oneshot::Sender<Result<Vec<u8>, Error>>) {
        match self {
            Session::Http { buf, .. } => {
                let _ = output.send(Ok(buf));
            }
            #[cfg(feature = "tls")]
            Session::Tls { mut stream, .. } => {
                let _ = output.send(Ok(stream.take_bytes()));
            }
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Session::Http { is_closed, .. } => *is_closed,
            #[cfg(feature = "tls")]
            Session::Tls { stream, .. } => stream.is_closed(),
        }
    }

    fn register(&self, poll: &mut mio::Poll) -> std::io::Result<()> {
        match self {
            Session::Http { stream, token, .. } => poll.register(
                stream,
                *token,
                mio::Ready::readable(),
                mio::PollOpt::level() | mio::PollOpt::oneshot(),
            ),
            #[cfg(feature = "tls")]
            Session::Tls { stream, .. } => stream.register(poll),
        }
    }

    fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::event::Event) -> Result<(), Error> {
        match self {
            Session::Http {
                stream, token, buf, ..
            } => {
                if ev.readiness().is_readable() {
                    use std::io::Read;
                    stream.read_to_end(buf)?;
                }
                poll.reregister(
                    stream,
                    *token,
                    mio::Ready::readable(),
                    mio::PollOpt::level() | mio::PollOpt::oneshot(),
                )?;

                Ok(())
            }
            #[cfg(feature = "tls")]
            Session::Tls { stream, .. } => stream.ready(poll, ev),
        }
    }
}

impl Client {
    /// Send a Request by creating a connection and sending it to the background thread to be
    /// polled
    pub fn send(&mut self, req: Request) -> PendingRequest {
        let (sender, receiver) = oneshot::channel();

        // TODO: If the background thread panics, the receiver will have hung up, which will cause
        // this call to return Err. Unclear if this is something we should try to notify the user
        // about more gracefully
        self.sender.send((req, sender)).unwrap();
        self.readiness
            .set_readiness(mio::Ready::readable())
            .unwrap();

        PendingRequest { receiver }
    }

    /// Convienence method to send a GET request without a body
    pub fn get(&mut self, url: &str) -> Result<PendingRequest, Error> {
        Ok(self.send(Request::get(url)?))
    }

    /// Create a client: Launches a background thread and starts a mio Poll on it
    pub fn new() -> Self {
        let (registration, readiness) = mio::Registration::new2();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

        std::thread::spawn(move || {
            let mut sessions: Vec<(Session, oneshot::Sender<Result<Vec<u8>, Error>>)> = Vec::new();

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
                        // A new session has been attached to the poll loop
                        let (request, output): (Request, _) = receiver.recv().unwrap();

                        // Pick an unused token value for the new session
                        // Token 0 indicates a new client, do not use for running clients
                        let mut token = mio::Token(0);
                        for v in 1..usize::max_value() {
                            if !sessions.iter().any(|s| s.0.token() == mio::Token(v)) {
                                token = mio::Token(v);
                                break;
                            }
                        }
                        assert!(token != mio::Token(0));

                        match Session::init(&request, token) {
                            Ok(session) => {
                                session.register(&mut poll).unwrap();
                                sessions.push((session, output));
                            }
                            Err(e) => {
                                let _ = output.send(Err(e));
                            }
                        }
                    } else {
                        // Else, we got an event for a currently running session. Find and handle it
                        sessions
                            .iter_mut()
                            .find(|c| c.0.token() == ev.token())
                            .unwrap()
                            .0
                            .ready(&mut poll, &ev)
                            .unwrap();
                    }
                }

                // Events have been handled, see if any clients are done
                // This operation is a drain_filter
                let mut i = 0;
                while i != sessions.len() {
                    if sessions[i].0.is_closed() {
                        let (session, output) = sessions.remove(i);
                        // TODO: If a user has dropped the receiver, this returns an error
                        // If they're doing that, they should probably get a helpful log!, since
                        // it's possible they don't care about the result of a side-effecty request
                        session.send_output(output);
                    } else {
                        i += 1;
                    }
                }
            }
        });

        Self { sender, readiness }
    }
}

/// Represents a request that may not be completed yet
pub struct PendingRequest {
    receiver: oneshot::Receiver<Result<Vec<u8>, Error>>,
}

impl PendingRequest {
    /// Block the current thread until the corresponding Request has recieved a Response
    pub fn wait(self) -> Result<Response, Error> {
        use futures::Future;
        // unwrap channel errors, bubble up erors from the request sending
        let raw = self.receiver.wait().unwrap()?;
        parse_response(&raw)
    }
}
