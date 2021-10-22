use crate::constants::{ATCA_CMD_SIZE_MAX, WAKE_DELAY};
use crate::{
    command::{EccCommand, EccResponse},
    Address, DataBuffer, Error, KeyConfig, Result, SlotConfig, Zone,
};
use bytes::{BufMut, Bytes, BytesMut};
use serialport::{ClearBuffer, DataBits, SerialPort, StopBits};
use sha2::{Digest, Sha256};
use std::{thread, time::Duration};

pub use crate::command::KeyType;

pub struct Ecc {
    port: String,
}

pub const MAX_SLOT: u8 = 15;

pub(crate) const RECV_RETRIES: u8 = 2;
pub(crate) const RECV_RETRY_WAIT: Duration = Duration::from_millis(50);
pub(crate) const CMD_RETRIES: u8 = 10; 

impl Ecc {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {

        let _ = address; //keep the API the same. Address refers to i2c addr which isn't required for SWI
        let port = String::from( path );

        Ok(Self {port})
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

    fn send_wake(&mut self) -> Result {
        let port_name = &self.port;
        let baud_rate = 115_200;
        let stop_bits = StopBits::One;
        let data_bits = DataBits::Eight;
        let uart_wake_builder = serialport::new(port_name, baud_rate)
            .stop_bits(stop_bits)
            .data_bits(data_bits);

        let mut uart_wake = uart_wake_builder.open().unwrap_or_else(|e| {
            eprintln!("Failed to open port {}. Error: {}", port_name,e);
            ::std::process::exit(1);
        });
        let _ = uart_wake.write(&[0]);
        
        thread::sleep(WAKE_DELAY);
        self.read_wake_response()
    }

    fn read_wake_response( &mut self) -> Result {
        let port_name = &self.port;
        let baud_rate = 230_400;
        let stop_bits = StopBits::One;
        let data_bits = DataBits::Seven;
        let uart_cmd_builder = serialport::new(port_name, baud_rate)
            .stop_bits(stop_bits)
            .data_bits(data_bits);

        let mut uart_cmd = uart_cmd_builder.open().unwrap_or_else(|e| {
            eprintln!("Failed to open port {}. Error: {}", port_name,e);
            ::std::process::exit(1);
        });
        
        // Send transmit flag to signal bus
        let mut encoded_msg = BytesMut::new();
        encoded_msg.resize(32,0);
        let mut transmit_flag = BytesMut::new();
        transmit_flag.put_u8(0x88);
        let encoded_transmit_flag = self.encode_uart_to_swi(&transmit_flag );
        self.send_buf(&encoded_transmit_flag, &mut uart_cmd)?;
        thread::sleep(Duration::from_micros(3_000) );

        let _ = uart_cmd.read(&mut encoded_msg);

        let mut decoded_msg = BytesMut::new();
        decoded_msg.resize(4, 0);
        
        self.decode_swi_to_uart(&encoded_msg, &mut decoded_msg);
        
        thread::sleep(RECV_RETRY_WAIT);

        let response = EccResponse::from_bytes(&decoded_msg)?;
        match response {
            EccResponse::Error(err) => return Err(Error::ecc(err)),
            _ => return Ok(()),
        }
    }

    fn send_sleep(&mut self) {        
        let port_name = &self.port;
        let baud_rate = 230_400;
        let stop_bits = StopBits::One;
        let data_bits = DataBits::Seven;
        let uart_cmd_builder = serialport::new(port_name, baud_rate)
            .stop_bits(stop_bits)
            .data_bits(data_bits);

        let mut uart_cmd = uart_cmd_builder.open().unwrap_or_else(|e| {
            eprintln!("Failed to open port {}. Error: {}", port_name,e);
            ::std::process::exit(1);
        });

        let mut sleep_msg = BytesMut::new();
        sleep_msg.put_u8(0xCC);
        let sleep_encoded = self.encode_uart_to_swi(&sleep_msg);

        let _ = uart_cmd.write(&sleep_encoded);
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
            if let Err(_err) = self.send_wake() {
                if retry == retries {
                    break;
                } else {
                    continue;
                }
            }
            break;
        }
        for retry in 0..retries {
            buf.clear();         
            command.bytes_into(&mut buf);

            self.send_recv_buf(command.duration(), &mut buf);

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

    fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) {
        
        let port_name = &self.port;
        let baud_rate = 230_400;
        let stop_bits = StopBits::One;
        let data_bits = DataBits::Seven;
        let uart_cmd_builder = serialport::new(port_name, baud_rate)
            .stop_bits(stop_bits)
            .data_bits(data_bits);

        let mut uart_driver = uart_cmd_builder.open().unwrap_or_else(|e| {
            eprintln!("Failed to open port {}. Error: {}", port_name,e);
            ::std::process::exit(1);
        });
        
        let _ = uart_driver.clear(ClearBuffer::All);

        let swi_msg = self.encode_uart_to_swi(buf);
        let _ = self.send_buf(&swi_msg, &mut uart_driver);
        thread::sleep(delay);
        let _ = self.recv_buf(buf, &mut uart_driver);
    }

    pub(crate) fn send_buf(&mut self, buf: &[u8], serial_port: &mut Box<dyn SerialPort>) -> Result {
        
        let send_size = serial_port.write(buf)?;

        //Each byte takes ~45us to transmit, so we must wait for the transmission to finish before proceeding
        let uart_tx_time = Duration::from_micros( (buf.len() * 45) as u64); 
        thread::sleep(uart_tx_time);
        //Because Tx line is linked with Rx line, all sent msgs are returned on the Rx line and must be cleared from the buffer
        let mut clear_rx_line = BytesMut::new();
        clear_rx_line.resize(send_size, 0);
        serial_port.read_exact( &mut clear_rx_line )?;

        Ok(())
    }

    pub(crate) fn recv_buf(&mut self, buf: &mut BytesMut,  serial_port: &mut Box<dyn SerialPort>) -> Result {
        let mut encoded_msg = BytesMut::new();
        encoded_msg.resize(ATCA_CMD_SIZE_MAX as usize,0);
        
        let mut transmit_flag = BytesMut::new();
        transmit_flag.put_u8(0x88);
        let encoded_transmit_flag = self.encode_uart_to_swi(&transmit_flag );
        
        let _ = serial_port.clear(ClearBuffer::All);

        for _retry in 0..RECV_RETRIES {
            self.send_buf(&encoded_transmit_flag, serial_port)?;
            thread::sleep(Duration::from_micros(32_000) );
            let read_response = serial_port.read(&mut encoded_msg);
            
            match read_response {
                Ok(cnt) if cnt == 0 => { //If the buffer is empty, wait & try again
                },
                Ok(cnt) if cnt > 8 => {
                    break;
                },
                _ => return Err(Error::Timeout) 
            }
            
            thread::sleep(RECV_RETRY_WAIT);
        }
        
        let mut encoded_msg_size = BytesMut::new();
        encoded_msg_size.resize(8, 0);
        encoded_msg_size.copy_from_slice(&encoded_msg[..8]);
        
        let mut msg_size = BytesMut::new();
        msg_size.put_u8(0);

        self.decode_swi_to_uart(&encoded_msg_size, &mut msg_size);

        let _excess = encoded_msg.split_off((msg_size[0] as usize) * 8);
        
        self.decode_swi_to_uart(&encoded_msg, buf);

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
                if *bit == 0x7F {
                    *byte ^= 1;
                }
                *byte = byte.rotate_right(1);
            }
            i += 8;
        }
    }
}
