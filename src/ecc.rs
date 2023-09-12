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
use std::{thread, time::Duration};

pub use crate::command::KeyType;

pub struct Ecc {
    transport: transport::TransportProtocol,
    config: EccConfig,
}

pub const MAX_SLOT: u8 = 15;

pub(crate) const CMD_RETRIES: u8 = 10;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct EccConfig {
    pub wake_delay: u32,
    pub durations: EccCommandDuration,
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
    pub fn from_path(path: &str) -> Result<Self> {
        if path.starts_with("/dev/tty") {
            Ok(Self::for_swi())
        } else if path.starts_with("/dev/i2c") {
            Ok(Self::for_i2c())
        } else {
            Err(Error::invalid_address())
        }
    }

    pub fn for_swi() -> Self {
        Self {
            wake_delay: 1500,
            durations: EccCommandDuration {
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
            wake_delay: 1000,
            durations: EccCommandDuration {
                info: 500,
                read: 800,
                write: 8_000,
                lock: 19_500,
                nonce: 7_000,
                random: 15_000,
                genkey: 59_000,
                sign: 62_000,
                ecdh: 28_000,
            },
        }
    }

    pub fn command_duration(&self, command: &EccCommand) -> Duration {
        let micros = match command {
            EccCommand::Info => self.durations.info,
            EccCommand::Read { .. } => self.durations.read,
            EccCommand::Write { .. } => self.durations.write,
            EccCommand::Lock { .. } => self.durations.lock,
            EccCommand::Nonce { .. } => self.durations.nonce,
            EccCommand::Random => self.durations.random,
            EccCommand::GenKey { .. } => self.durations.genkey,
            EccCommand::Sign { .. } => self.durations.sign,
            EccCommand::Ecdh { .. } => self.durations.ecdh,
        };
        Duration::from_micros(micros as u64)
    }
}

impl Ecc {
    pub fn from_path(path: &str, address: u16, config: Option<EccConfig>) -> Result<Self> {
        let transport = if path.starts_with("/dev/tty") {
            transport::SwiTransport::new(path)?.into()
        } else if path.starts_with("/dev/i2c") {
            transport::I2cTransport::new(path, address)?.into()
        } else {
            return Err(Error::invalid_address());
        };

        let config = if let Some(config) = config {
            config
        } else {
            EccConfig::from_path(path)?
        };

        Ok(Self { transport, config })
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
            true,
            false,
            1,
        )?;
        self.send_command_retries(
            &EccCommand::sign(DataBuffer::MessageDigest, key_slot),
            false,
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
        self.send_command_retries(command, true, true, CMD_RETRIES)
    }

    pub(crate) fn send_command_retries(
        &mut self,
        command: &EccCommand,
        wake: bool,
        idle: bool,
        retries: u8,
    ) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(ATCA_CMD_SIZE_MAX as usize);
        let delay = self.config.command_duration(command);
        let wake_delay = Duration::from_micros(self.config.wake_delay as u64);

        for retry in 0..retries {
            buf.clear();
            buf.put_u8(self.transport.put_command_flag());
            command.bytes_into(&mut buf);

            if wake {
                self.transport.send_wake(wake_delay)?;
            }

            if let Err(_err) = self.transport.send_recv_buf(delay, &mut buf) {
                if retry == retries {
                    // Sleep the chip to clear the SRAM when the maximum error retries have been exhausted
                    self.transport.send_sleep();
                    break;
                } else {
                    continue;
                }
            }

            let response = EccResponse::from_bytes(&buf[..])?;
            
            match response {
                EccResponse::Data(bytes) => {
                    if idle {
                        self.transport.send_idle();
                    }
                    return Ok(bytes)
                },
                EccResponse::Error(err) if err.is_recoverable() && retry < retries => continue,
                EccResponse::Error(err) => {
                    self.error_mitigation(wake_delay);
                    return Err(Error::ecc(err));
                }
            }
        }
        self.error_mitigation(wake_delay);
        Err(Error::timeout())
    }
    
    fn error_mitigation(&mut self, wake_delay: Duration) {
        // Error mitigation sequence;
        // 1. Wait to make sure any command it may have still been executed completed
        // 2. Sleep chip to clear SRAM
        // 3. Wake chip up again
        // 4. Put chip in idle
        thread::sleep(Duration::from_millis(150));
        self.transport.send_sleep();
        thread::sleep(Duration::from_micros((2 * self.config.wake_delay).into())); // Convert to u64
        let _ = self.transport.send_wake(wake_delay);
        thread::sleep(Duration::from_micros((2 * self.config.wake_delay).into())); // Convert to u64
        self.transport.send_idle();
    }
}
