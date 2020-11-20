use std::fmt;

use didkit::Error as DIDKitError;
use hyper::header::ToStrError as HeaderToStrError;
use hyper::http::Error as HttpError;
use hyper::Error as HyperError;
use serde_json::Error as JSONError;
use std::error::Error as StdError;
use std::num::ParseFloatError;

#[derive(Debug)]
pub enum Error {
    DIDKit(DIDKitError),
    JSON(JSONError),
    Hyper(HyperError),
    Http(HttpError),
    HeaderToStr(HeaderToStrError),
    ParseFloat(ParseFloatError),
    InvalidAccept,
    #[doc(hidden)]
    __Nonexhaustive,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            // Error::DIDKit(e) => Some(e),
            Error::Hyper(e) => Some(e),
            Error::Http(e) => Some(e),
            Error::ParseFloat(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DIDKit(e) => e.fmt(f),
            Error::JSON(e) => e.fmt(f),
            Error::Hyper(e) => e.fmt(f),
            Error::Http(e) => e.fmt(f),
            Error::HeaderToStr(e) => e.fmt(f),
            Error::ParseFloat(e) => e.fmt(f),
            Error::InvalidAccept => write!(f, "Invalid Accept header value"),
            _ => unreachable!(),
        }
    }
}

impl From<DIDKitError> for Error {
    fn from(err: DIDKitError) -> Error {
        Error::DIDKit(err)
    }
}

impl From<JSONError> for Error {
    fn from(err: JSONError) -> Error {
        Error::JSON(err)
    }
}

impl From<HyperError> for Error {
    fn from(err: HyperError) -> Error {
        Error::Hyper(err)
    }
}

impl From<HttpError> for Error {
    fn from(err: HttpError) -> Error {
        Error::Http(err)
    }
}

impl From<HeaderToStrError> for Error {
    fn from(err: HeaderToStrError) -> Error {
        Error::HeaderToStr(err)
    }
}

impl From<ParseFloatError> for Error {
    fn from(err: ParseFloatError) -> Error {
        Error::ParseFloat(err)
    }
}

/*
impl From<dyn StdError + Sized> for Error {
    fn from(err: StdError) -> Error {
        Error::Std(err)
    }
}
*/
