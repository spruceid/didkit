use tokio::runtime::{Builder, Runtime};

use crate::error::Error;

/// Get a [Tokio runtime] for the current thread.
/// [Tokio runtime]: https://docs.rs/tokio/1.2.0/tokio/runtime/struct.Runtime.html
pub fn get() -> Result<Runtime, Error> {
    let rt = Builder::new_current_thread().enable_all().build()?;
    Ok(rt)
}
