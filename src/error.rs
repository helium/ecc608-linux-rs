use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("timeout/retry error")]
    Timeout,
    #[error("ecc error {:?}", .0)]
    Ecc(crate::command::EccError),

    #[error("invalid ecc address")]
    InvalidAddress,
}

impl Error {
    pub(crate) fn timeout() -> Self {
        Self::Timeout
    }

    pub(crate) fn ecc(err: crate::command::EccError) -> Self {
        Self::Ecc(err)
    }

    pub(crate) fn invalid_address() -> Self {
        Self::InvalidAddress
    }
}
