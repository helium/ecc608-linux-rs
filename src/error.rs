use std::io::Error as IoError;
use serialport::Error as SerialPortError;
use ecc608_linux::error::Error as Ecc608LinuxError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    IoError(#[from] IoError),
    #[error("timeout/retry error")]
    Timeout,
    #[error("ecc error {:?}", .0)]
    Ecc(crate::command::EccError),
    #[error("serial port error")]
    SerialPort(#[from] SerialPortError),
    #[error("invalid ecc address")]
    InvalidAddress,
    #[error("ecc608 linux error {:?}", .0)]
    Ecc608LinuxError(#[from] Ecc608LinuxError),
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
