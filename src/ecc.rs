use crate::{
    constants::ATCA_CMD_SIZE_MAX,
    transport,
    {
        command::{EccCommand, EccResponse},
        Address, DataBuffer, Error, KeyConfig, Result, SlotConfig, Zone,
    },
};
use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub use crate::command::KeyType;

pub struct Ecc {
    transport: transport::TransportProtocol,
    config: EccConfig,
}

pub const MAX_SLOT: u8 = 15;
pub const DEFAULT_WAKE_DELAY: Duration = Duration::from_micros(1500);

pub(crate) const CMD_RETRIES: u8 = 10;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct EccConfig {
    pub wake_delay: Duration,
    pub command_duration: EccCommandDuration,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct EccCommandDuration {
    pub info: u32,
    pub read: u32,
    pub write: u32,
    pub lock: u32,
    pub nonce: u32,
    pub random: u32,
    pub genkey: u32,
    pub sign: u32,
    pub ecdh: u32,
}

impl EccConfig {
    pub fn for_swi() -> Self {
        Self {
            wake_delay: DEFAULT_WAKE_DELAY,
            command_duration: EccCommandDuration {
                info: 500,
                read: 800,
                write: 8_000,
                lock: 19_500,
                nonce: 17_000,
                random: 15_000,
                genkey: 85_000,
                sign: 80_000,
                ecdh: 42_000,
            },
        }
    }

    pub fn for_i2c() -> Self {
        Self {
            wake_delay: DEFAULT_WAKE_DELAY,
            command_duration: EccCommandDuration {
                info: 500,
                read: 800,
                write: 8_000,
                lock: 19_500,
                nonce: 7_000,
                random: 15_000,
                genkey: 59_000,
                sign: 68_000,
                ecdh: 28_000,
            },
        }
    }

    pub fn command_duration(&self, command: &EccCommand) -> Duration {
        let micros = match command {
            EccCommand::Info => self.command_duration.info,
            EccCommand::Read { .. } => self.command_duration.read,
            EccCommand::Write { .. } => self.command_duration.write,
            EccCommand::Lock { .. } => self.command_duration.lock,
            EccCommand::Nonce { .. } => self.command_duration.nonce,
            EccCommand::Random => self.command_duration.random,
            EccCommand::GenKey { .. } => self.command_duration.genkey,
            EccCommand::Sign { .. } => self.command_duration.sign,
            EccCommand::Ecdh { .. } => self.command_duration.ecdh,
        };
        Duration::from_micros(micros as u64)
    }
}

impl Ecc {
    pub fn from_path(path: &str, address: u16, config: Option<EccConfig>) -> Result<Self> {
        let (transport, default_config) = if path.starts_with("/dev/tty") {
            let swi_handle = transport::SwiTransport::new(path)?;
            (swi_handle.into(), EccConfig::for_swi())
        } else if path.starts_with("/dev/i2c") {
            let i2c_handle = transport::I2cTransport::new(path, address)?;
            (i2c_handle.into(), EccConfig::for_i2c())
        } else {
            return Err(Error::invalid_address());
        };

        Ok(Self {
            transport,
            config: config.unwrap_or(default_config),
        })
    }

    pub fn get_info(&mut self) -> Result<Bytes> {
        self.send_command(&EccCommand::info())
    }

    /// Returns the 9 bytes that represent the serial number of the ECC. Per
    /// section 2.2.6 of the Data Sheet the first two, and last byte of the
    /// returned binary will always be `[0x01, 0x23]` and `0xEE`
    pub fn get_serial(&mut self) -> Result<Bytes> {
        let bytes = self.read(true, Address::config(0, 0)?)?;
        let mut result = BytesMut::with_capacity(9);
        result.extend_from_slice(&bytes.slice(0..=3));
        result.extend_from_slice(&bytes.slice(8..=12));
        Ok(result.freeze())
    }

    pub fn genkey(&mut self, key_type: KeyType, slot: u8) -> Result<Bytes> {
        self.send_command(&EccCommand::genkey(key_type, slot))
    }

    pub fn get_slot_config(&mut self, slot: u8) -> Result<SlotConfig> {
        let bytes = self.read(false, Address::slot_config(slot)?)?;
        let (s0, s1) = bytes.split_at(2);
        match slot & 1 == 0 {
            true => Ok(SlotConfig::from(s0)),
            false => Ok(SlotConfig::from(s1)),
        }
    }

    pub fn set_slot_config(&mut self, slot: u8, config: &SlotConfig) -> Result {
        let slot_address = Address::slot_config(slot)?;
        let bytes = self.read(false, slot_address)?;
        let (s0, s1) = bytes.split_at(2);
        let mut new_bytes = BytesMut::with_capacity(4);
        match slot & 1 == 0 {
            true => {
                new_bytes.put_u16(config.into());
                new_bytes.extend_from_slice(s1);
            }
            false => {
                new_bytes.extend_from_slice(s0);
                new_bytes.put_u16(config.into());
            }
        }
        self.write(slot_address, &new_bytes.freeze())
    }

    pub fn get_key_config(&mut self, slot: u8) -> Result<KeyConfig> {
        let bytes = self.read(false, Address::key_config(slot)?)?;
        let (s0, s1) = bytes.split_at(2);
        match slot & 1 == 0 {
            true => Ok(KeyConfig::from(s0)),
            false => Ok(KeyConfig::from(s1)),
        }
    }

    pub fn set_key_config(&mut self, slot: u8, config: &KeyConfig) -> Result {
        let slot_address = Address::key_config(slot)?;
        let bytes = self.read(false, slot_address)?;
        let (s0, s1) = bytes.split_at(2);
        let mut new_bytes = BytesMut::with_capacity(4);
        match slot & 1 == 0 {
            true => {
                new_bytes.put_u16(config.into());
                new_bytes.extend_from_slice(s1);
            }
            false => {
                new_bytes.extend_from_slice(s0);
                new_bytes.put_u16(config.into());
            }
        }
        self.write(slot_address, &new_bytes.freeze())
    }

    pub fn get_locked(&mut self, zone: &Zone) -> Result<bool> {
        let bytes = self.read(false, Address::config(2, 5)?)?;
        let (_, s1) = bytes.split_at(2);
        match zone {
            Zone::Config => Ok(s1[1] == 0),
            Zone::Data => Ok(s1[0] == 0),
        }
    }

    pub fn set_locked(&mut self, zone: Zone) -> Result {
        self.send_command(&EccCommand::lock(zone)).map(|_| ())
    }

    pub fn sign(&mut self, key_slot: u8, data: &[u8]) -> Result<Bytes> {
        let digest = Sha256::digest(data);
        let _ = self.send_command_retries(
            &EccCommand::nonce(DataBuffer::MessageDigest, Bytes::copy_from_slice(&digest)),
            false,
            1,
        )?;
        self.send_command_retries(
            &EccCommand::sign(DataBuffer::MessageDigest, key_slot),
            true,
            1,
        )
    }

    pub fn ecdh(&mut self, key_slot: u8, x: &[u8], y: &[u8]) -> Result<Bytes> {
        self.send_command(&EccCommand::ecdh(
            Bytes::copy_from_slice(x),
            Bytes::copy_from_slice(y),
            key_slot,
        ))
    }

    pub fn random(&mut self) -> Result<Bytes> {
        self.send_command(&EccCommand::random())
    }

    pub fn nonce(&mut self, target: DataBuffer, data: &[u8]) -> Result {
        self.send_command(&EccCommand::nonce(target, Bytes::copy_from_slice(data)))
            .map(|_| ())
    }

    pub fn read(&mut self, read_32: bool, address: Address) -> Result<Bytes> {
        self.send_command(&EccCommand::read(read_32, address))
    }

    pub fn write(&mut self, address: Address, bytes: &[u8]) -> Result {
        self.send_command(&EccCommand::write(address, bytes))
            .map(|_| ())
    }

    pub(crate) fn send_command(&mut self, command: &EccCommand) -> Result<Bytes> {
        self.send_command_retries(command, true, CMD_RETRIES)
    }

    pub(crate) fn send_command_retries(
        &mut self,
        command: &EccCommand,
        sleep: bool,
        retries: u8,
    ) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(ATCA_CMD_SIZE_MAX as usize);
        let delay = self.config.command_duration(command);

        for retry in 0..retries {
            buf.clear();
            buf.put_u8(self.transport.put_command_flag());
            command.bytes_into(&mut buf);

            self.transport.send_wake(self.config.wake_delay)?;

            if let Err(_err) = self.transport.send_recv_buf(delay, &mut buf) {
                if retry == retries {
                    break;
                } else {
                    continue;
                }
            }

            let response = EccResponse::from_bytes(&buf[..])?;
            if sleep {
                self.transport.send_sleep();
            }
            match response {
                EccResponse::Data(bytes) => return Ok(bytes),
                EccResponse::Error(err) if err.is_recoverable() && retry < retries => continue,
                EccResponse::Error(err) => return Err(Error::ecc(err)),
            }
        }
        Err(Error::timeout())
    }
}
