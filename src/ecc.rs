use crate::constants::{ATCA_CMD_SIZE_MAX, WAKE_DELAY};
use crate::{
    command::{EccCommand, EccResponse},
    Address, DataBuffer, Error, KeyConfig, Result, SlotConfig, Zone,
};
use bytes::{BufMut, Bytes, BytesMut};
use serialport::{DataBits, SerialPort, StopBits};
use sha2::{Digest, Sha256};
use std::{thread, time::Duration};

pub use crate::command::KeyType;

pub struct Ecc {
    uart_cmd: Box<dyn SerialPort>,
    uart_wake: Box<dyn SerialPort>,
}

pub const MAX_SLOT: u8 = 15;

pub(crate) const RECV_RETRIES: u8 = 2;
pub(crate) const RECV_RETRY_WAIT: Duration = Duration::from_millis(50);
pub(crate) const CMD_RETRIES: u8 = 10;

impl Ecc {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {

        let _ = address; //keep the API the same. Address refers to i2c addr which isn't required for SWI

        let port_name = path;
        let baud_rate = 230_400;
        let stop_bits = StopBits::One;
        let data_bits = DataBits::Seven;
        let builder = serialport::new(port_name, baud_rate)
            .stop_bits(stop_bits)
            .data_bits(data_bits);

        let uart_cmd = builder.open().unwrap_or_else(|e| {
            eprintln!("Failed to open \"{}\". Error: {}", port_name, e);
            ::std::process::exit(1);
        });

        let port_name = path;
        let baud_rate = 115_200;
        let stop_bits = StopBits::One;
        let data_bits = DataBits::Eight;
        let builder = serialport::new(port_name, baud_rate)
            .stop_bits(stop_bits)
            .data_bits(data_bits);
        let uart_wake = builder.open().unwrap_or_else(|e| {
            eprintln!("Failed to open \"{}\". Error: {}", port_name, e);
            ::std::process::exit(1);
        });

        Ok(Self {uart_cmd, uart_wake})
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

    fn send_wake(&mut self) {
        let _ = self.uart_wake.write(&[0]);
    }

    fn send_sleep(&mut self) {
        let _ = self.uart_cmd.write(&[0xCC]);
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
            buf.clear();
            command.bytes_into(&mut buf);

            self.send_wake();
            thread::sleep(WAKE_DELAY);

            if let Err(_err) = self.send_recv_buf(command.duration(), &mut buf) {
                if retry == retries {
                    break;
                } else {
                    continue;
                }
            }

            let response = EccResponse::from_bytes(&buf[..])?;
            if sleep {
                self.send_sleep();
            }
            match response {
                EccResponse::Data(bytes) => return Ok(bytes),
                EccResponse::Error(err) if err.is_recoverable() && retry < retries => {
                    continue;
                }
                EccResponse::Error(err) => return Err(Error::ecc(err)),
            }
        }
        Err(Error::timeout())
    }

    fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) -> Result {
        let mut swi_msg = self.encode_uart_to_swi(&buf);
        self.send_buf(&swi_msg)?;
        thread::sleep(delay);
        self.recv_buf(&mut swi_msg)?;
        self.decode_swi_to_uart(&swi_msg, buf);
        Ok(())
    }

    pub(crate) fn send_buf(&mut self, buf: &[u8]) -> Result {
        self.uart_cmd.write(buf)?;
        Ok(())
    }

    pub(crate) fn recv_buf(&mut self, buf: &mut BytesMut) -> Result {
        buf.resize(8,0xff);
        
        for _retry in 0..RECV_RETRIES {
            let read = self.uart_cmd.read(buf);
            
            match read {
                Ok(cnt) => {
                    assert!(cnt == 8);
                    break;
                },
                Err(_e) => {} 
            }
            
            thread::sleep(RECV_RETRY_WAIT);
        }
        
        let mut msg_size = BytesMut::new();
        msg_size.resize(1,0xFF);

        self.decode_swi_to_uart(&buf, &mut msg_size);

        let count = msg_size[0] as usize;
        if count == 0xff {
            return Err(Error::timeout());
        }
        buf.reserve((count-1)*8);
        self.uart_cmd.read( &mut buf[8..])?;
        Ok(())
    }

    fn encode_uart_to_swi(&mut self, uart_msg: &BytesMut ) -> BytesMut {
        
        let mut bit_field = BytesMut::new();
        bit_field.reserve(uart_msg.len() * 8 );
    
        for byte in uart_msg.iter() {
            for bit_index in 0..8 {
                if ( ((1 << bit_index ) & byte) >> bit_index ) == 0 {
                    bit_field.put_u8(0xFD); 
                } else {
                    bit_field.put_u8(0xFF);
                }
            }
        }
        bit_field
    }
    
    fn decode_swi_to_uart(&mut self, swi_msg: &BytesMut, uart_msg: &mut BytesMut ) {
    
        uart_msg.clear();
        assert!( (swi_msg.len() % 8) == 0);
        uart_msg.resize( &swi_msg.len() / 8, 0 );
    
        let mut i = 0; 
        for byte in uart_msg.iter_mut() {
            let bit_slice= &swi_msg[i..i+8];
            
            for bit in bit_slice.iter(){
                if *bit == 0xFF {
                    *byte ^= 1;
                }
                *byte = byte.rotate_right(1);
            }
            i += 8;
        }
    }
}
