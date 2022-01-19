use crate::constants::{ ATCA_CMD_SIZE_MAX, ATCA_I2C_COMMAND_FLAG, ATCA_SWI_COMMAND_FLAG };
use crate::transport::{EccTransport, TransportProtocol};
use crate::{
    command::{EccCommand, EccResponse},
    Address, DataBuffer, Error, KeyConfig, Result, SlotConfig, Zone,
};
use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};
use std::{thread, time::Duration};

pub use crate::command::KeyType;

pub struct Ecc {
    transport: EccTransport,
}

pub const MAX_SLOT: u8 = 15;

pub(crate) const CMD_RETRIES: u8 = 10;

impl Ecc {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {

        let transport = EccTransport::from_path( path, address)?;

        Ok(Self {transport})
    }

    pub fn get_info(&mut self) -> Result<Bytes> {
        self.send_command(&EccCommand::info())
    }

    /// Returns the 9 bytes that represent the serial number of the ECC. Per
    /// section 2.2.6 of the Data Sheet the first two, and last byte of the
    /// returned binary will always be `[0x01, 0x23]` and `0xEE`
    pub fn get_serial(&mut self) -> Result<Bytes> {
        let bytes = self.read(true, &Address::config(0, 0)?)?;
        let mut result = BytesMut::with_capacity(9);
        result.extend_from_slice(&bytes.slice(0..=3));
        result.extend_from_slice(&bytes.slice(8..=12));
        Ok(result.freeze())
    }

    pub fn genkey(&mut self, key_type: KeyType, slot: u8) -> Result<Bytes> {
        self.send_command(&EccCommand::genkey(key_type, slot))
    }

    pub fn get_slot_config(&mut self, slot: u8) -> Result<SlotConfig> {
        let bytes = self.read(false, &Address::slot_config(slot)?)?;
        let (s0, s1) = bytes.split_at(2);
        match slot & 1 == 0 {
            true => Ok(SlotConfig::from(s0)),
            false => Ok(SlotConfig::from(s1)),
        }
    }

    pub fn set_slot_config(&mut self, slot: u8, config: &SlotConfig) -> Result {
        let slot_address = Address::slot_config(slot)?;
        let bytes = self.read(false, &slot_address)?;
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
        self.write(&slot_address, &new_bytes.freeze())
    }

    pub fn get_key_config(&mut self, slot: u8) -> Result<KeyConfig> {
        let bytes = self.read(false, &Address::key_config(slot)?)?;
        let (s0, s1) = bytes.split_at(2);
        match slot & 1 == 0 {
            true => Ok(KeyConfig::from(s0)),
            false => Ok(KeyConfig::from(s1)),
        }
    }

    pub fn set_key_config(&mut self, slot: u8, config: &KeyConfig) -> Result {
        let slot_address = Address::key_config(slot)?;
        let bytes = self.read(false, &slot_address)?;
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
        self.write(&slot_address, &new_bytes.freeze())
    }

    pub fn get_locked(&mut self, zone: &Zone) -> Result<bool> {
        let bytes = self.read(false, &Address::config(2, 5)?)?;
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

    pub fn read(&mut self, read_32: bool, address: &Address) -> Result<Bytes> {
        self.send_command(&EccCommand::read(read_32, address.clone()))
    }

    pub fn write(&mut self, address: &Address, bytes: &[u8]) -> Result {
        self.send_command(&EccCommand::write(address.clone(), bytes))
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

        for retry in 0..retries {
            let response = self.transport.send_wake();

            match response {
                Ok(_) => (),
                Err(_err) if retry < retries => {
                    thread::sleep(Duration::from_millis(65));
                    continue
                },
                Err(err) =>{
                    return Err(err )
                }
            }

            buf.clear();         
            command.bytes_into(&mut buf);

            match self.transport.protocol {
                TransportProtocol::I2c => {buf[0] = ATCA_I2C_COMMAND_FLAG}
                TransportProtocol::Swi => {buf[0] = ATCA_SWI_COMMAND_FLAG}
            }

            let delay = match self.transport.protocol {
                TransportProtocol::I2c => {command.duration( false )}
                TransportProtocol::Swi => {command.duration( true )}
            };
            
            if let Err(_err) = self.transport.send_recv_buf(delay, &mut buf) {
                if retry == retries {
                    break;
                } else {
                    thread::sleep(Duration::from_millis(65));
                    continue;
                }    
            }
            
            let response = EccResponse::from_bytes(&buf[..]);
            if sleep {
                self.transport.send_sleep();
            }
            match response {
                Ok(EccResponse::Data(bytes)) => return Ok(bytes),
                Ok(EccResponse::Error(err)) if err.is_recoverable() && retry < retries => {
                    continue;
                }
                Err(Error::Crc{expected: _, actual: _}) if retry < retries => {
                    continue;
                }
                Ok(EccResponse::Error(err)) => return Err(Error::ecc(err)),
                Err(e) => return Err(e)
            }
        }
        Err(Error::timeout())
    }
}
