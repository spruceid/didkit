use didkit::error::Error as DIDKitError;
use neon_serde::errors::Error as NeonSerdeError;
use ssi::error::Error as SsiError;
use std::io::Error as IOError;

pub struct Error(pub String);

impl From<SsiError> for self::Error {
    fn from(err: SsiError) -> Error {
        self::Error(err.into())
    }
}

impl From<DIDKitError> for self::Error {
    fn from(err: DIDKitError) -> Error {
        self::Error(err.to_string())
    }
}

impl From<NeonSerdeError> for self::Error {
    fn from(err: NeonSerdeError) -> self::Error {
        self::Error(err.to_string())
    }
}

impl From<IOError> for self::Error {
    fn from(err: IOError) -> self::Error {
        self::Error(err.to_string())
    }
}
