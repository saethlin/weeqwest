use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(rustls::TLSError),
    Parse(httparse::Error),
    Http(http::Error),
    InvalidHostname,
    IpLookupFailed,
    InvalidUrl,
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

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Error {
        Error::Http(e)
    }
}
