mod command;
mod constants;
mod error;
mod transport;

pub mod address;
pub mod ecc;
pub mod key_config;
pub mod slot_config;

pub use error::Error;
pub type Result<T = ()> = std::result::Result<T, Error>;
pub use address::*;
pub use ecc::{Ecc, EccConfig, KeyType, MAX_SLOT};
pub use key_config::*;
pub use slot_config::*;
