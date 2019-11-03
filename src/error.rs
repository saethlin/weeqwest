use std::io;

#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(rustls::TLSError),
    Parse(httparse::Error),
    Http(http::Error),
    Decode(std::str::Utf8Error),
    InvalidHostname,
    IpLookupFailed,
    InvalidUrl,
    UnsupportedScheme,
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

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Decode(e)
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(_: http::uri::InvalidUri) -> Error {
        Error::InvalidUrl
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}
