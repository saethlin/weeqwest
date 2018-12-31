use crate::tls::TlsClient;
use crate::{parse_response, Error, Request, Response};
use mio::net::TcpStream;

pub struct Session {
    hostname: String,
    tlsclient: TlsClient,
    poll: mio::Poll,
    events: mio::Events,
}

impl Session {
    pub fn new(hostname: &str) -> Result<Self, Error> {
        let addr = crate::DNS_CACHE
            .lock()
            .unwrap()
            .lookup(hostname.to_string(), 443)?;

        let dns_name = webpki::DNSNameRef::try_from_ascii_str(&hostname)
            .map_err(|_| Error::InvalidHostname)?;
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
        let url = format!("{}/{}", self.hostname, path);
        Request::get(&url)?.write_to(&mut self.tlsclient)?;

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
