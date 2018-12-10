use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use mio::event::Event;
use mio::net::TcpStream;

use rustls::Session;

const CLIENT: mio::Token = mio::Token(0);

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(rustls::TLSError),
    Parse(httparse::Error),
    InvalidHostname,
    IpLookupFailed,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<rustls::TLSError> for Error {
    fn from(e: rustls::TLSError) -> Error {
        Error::Tls(e)
    }
}

impl From<httparse::Error> for Error {
    fn from(e: httparse::Error) -> Error {
        Error::Parse(e)
    }
}

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_session: rustls::ClientSession,
}

impl TlsClient {
    fn ready(&mut self, poll: &mut mio::Poll, ev: &Event, buf: &mut Vec<u8>) -> Result<(), Error> {
        assert_eq!(ev.token(), CLIENT);

        if ev.readiness().is_readable() {
            self.do_read(buf)?;
        }

        if ev.readiness().is_writable() {
            self.do_write()?;
        }

        self.reregister(poll)?;

        Ok(())
    }
}

/// We implement `io::Write` and pass through to the TLS session
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_session.read(bytes)
    }
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        hostname: webpki::DNSNameRef,
        cfg: &Arc<rustls::ClientConfig>,
    ) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_session: rustls::ClientSession::new(cfg, hostname),
        }
    }

    /// We're ready to do a read.
    fn do_read(&mut self, buf: &mut Vec<u8>) -> Result<(), Error> {
        let bytes_read = self.tls_session.read_tls(&mut self.socket);
        match bytes_read {
            // Ready but no data
            Ok(0) => {
                self.closing = true;
                self.clean_closure = true;
                return Ok(());
            }
            // Underlying TCP connection is broken
            Err(e) => {
                self.closing = true;
                return Err(Error::Io(e));
            }
            _ => {}
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.tls_session.process_new_packets();
        if let Err(e) = processed {
            self.closing = true;
            return Err(Error::Tls(e));
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        // Read it.
        let bytes_read = self.tls_session.read_to_end(buf);

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if let Err(e) = bytes_read {
            self.clean_closure = e.kind() == io::ErrorKind::ConnectionAborted;
            self.closing = true;
            if self.clean_closure {
                Ok(())
            } else {
                Err(Error::Io(e))
            }
        } else {
            Ok(())
        }
    }

    // Discards the usize that tells us how many bytes were written
    fn do_write(&mut self) -> io::Result<()> {
        while self.tls_session.wants_write() {
            self.tls_session.write_tls(&mut self.socket)?;
        }
        Ok(())
    }

    fn register(&self, poll: &mut mio::Poll) -> io::Result<()> {
        poll.register(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
    }

    fn reregister(&self, poll: &mut mio::Poll) -> io::Result<()> {
        poll.reregister(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
    }

    // Use wants_read/wants_write to register for different mio-level
    // IO readiness events.
    fn ready_interest(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }
}

fn lookup_ipv4(host: &str, port: u16) -> io::Result<Option<SocketAddr>> {
    use std::net::ToSocketAddrs;
    (host, port).to_socket_addrs().map(|mut addrs| addrs.next())
}

/// Parse some arguments, then make a TLS client connection
/// somewhere.
pub fn get(hostname: &str, path: &str) -> Result<Vec<u8>, Error> {
    let port = 443;
    let addr = lookup_ipv4(hostname, port)?.ok_or(Error::IpLookupFailed)?;

    let config = {
        let mut config = rustls::ClientConfig::new();

        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        Arc::new(config)
    };

    let sock = TcpStream::connect(&addr)?;
    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str(hostname).map_err(|_| Error::InvalidHostname)?;
    let mut tlsclient = TlsClient::new(sock, dns_name, &config);

    write!(
        tlsclient,
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: \
         close\r\nAccept-Encoding: identity\r\n\r\n",
        path, hostname
    )?;

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(4);
    tlsclient.register(&mut poll)?;

    let mut incoming_bytes = Vec::new();
    loop {
        poll.poll(&mut events, None)?;

        for ev in events.iter() {
            tlsclient.ready(&mut poll, &ev, &mut incoming_bytes)?;
        }

        if tlsclient.is_closed() {
            break;
        }
    }

    // Parse the response
    // Reserve enough space to hold all the incoming bytes so no reallocation occurs
    let mut body = Vec::with_capacity(incoming_bytes.len());

    // Read the headers, increasing storage if needed
    let mut headers = vec![httparse::EMPTY_HEADER; 256];
    let mut req = httparse::Response::new(&mut headers);
    while let Err(httparse::Error::TooManyHeaders) = req.parse(&incoming_bytes) {
        headers.extend_from_slice(&[httparse::EMPTY_HEADER; 256]);
        req = httparse::Response::new(&mut headers);
    }

    // Initial parse fills out the request struct and jumps to the beginning of the chunks
    match req.parse(&incoming_bytes)? {
        httparse::Status::Complete(len) => {
            let mut remaining = &incoming_bytes[len..];

            // Keep parsing until we run out of chunks, or have a parse error
            while let Ok(httparse::Status::Complete((stopped, chunksize))) =
                httparse::parse_chunk_size(remaining)
            {
                let end = chunksize as usize + stopped;
                body.extend(&remaining[stopped..chunksize as usize + stopped]);
                remaining = &remaining[end..];
            }

            Ok(body)
        }

        httparse::Status::Partial => {
            panic!("Entire request should have been read already but wasn't")
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn main() {
        let bytes = get("api.slack.com", "/api/api.test").unwrap();
        let json = String::from_utf8(bytes).unwrap();
        println!("{}", json.len());
    }
}
