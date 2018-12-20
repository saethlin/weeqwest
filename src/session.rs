use crate::parse_response;
use crate::tls::TlsClient;
use crate::Error;
use crate::Response;
use mio::net::TcpStream;
use std::io::Write;
use std::net::ToSocketAddrs;

pub struct Session {
    hostname: String,
    tlsclient: TlsClient,
    poll: mio::Poll,
    events: mio::Events,
}

impl Session {
    pub fn new(hostname: &str) -> Result<Self, Error> {
        let addr = (hostname, 443)
            .to_socket_addrs()
            .map(|mut addrs| addrs.next())?
            .ok_or(Error::IpLookupFailed)?;

        let dns_name =
            webpki::DNSNameRef::try_from_ascii_str(hostname).map_err(|_| Error::InvalidHostname)?;
        let socket = TcpStream::connect(&addr)?;
        let tlsclient = TlsClient::new(socket, dns_name);

        let mut poll = mio::Poll::new()?;
        tlsclient.register(&mut poll)?;

        Ok(Self {
            hostname: hostname.to_string(),
            tlsclient,
            poll,
            events: mio::Events::with_capacity(4),
        })
    }

    pub fn get(&mut self, path: &str) -> Result<Response, Error> {
        write!(
            self.tlsclient,
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             Accept-Encoding: identity\r\n\r\n",
            path, self.hostname
        )?;

        // TODO: Why do we need to reregister here? I did not expect that
        self.tlsclient.reregister(&mut self.poll)?;

        loop {
            self.poll.poll(&mut self.events, None)?;
            for ev in self.events.iter() {
                self.tlsclient.ready(&mut self.poll, &ev)?;
            }
            if self.tlsclient.is_closed() {
                break;
            }
            if self.tlsclient.response_done() {
                break;
            }
        }

        let raw = self.tlsclient.take_bytes();
        parse_response(&raw)
    }
}
