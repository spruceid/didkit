use neon_serde::errors::Error as NeonSerdeError;
use ssi::error::Error as SsiError;

pub struct Error(pub String);

impl From<SsiError> for self::Error {
    fn from(err: SsiError) -> Error {
        self::Error(err.into())
    }
}

impl From<NeonSerdeError> for self::Error {
    fn from(err: NeonSerdeError) -> self::Error {
        self::Error(err.to_string())
    }
}
