use bytes::{BytesMut, BufMut};
use std::{thread, time::Duration, fs::File};

use crate::{Result, Error, command::EccCommand};
use crate::constants::{ATCA_SWI_SLEEP_FLAG, ATCA_SWI_TRANSMIT_FLAG, ATCA_I2C_COMMAND_FLAG,
    ATCA_SWI_COMMAND_FLAG, WAKE_DELAY};
    
use serialport::{ClearBuffer, SerialPort};
use i2c_linux::{I2c, ReadFlags};

const RECV_RETRY_WAIT: Duration = Duration::from_millis(50);
const RECV_RETRIES: u8 = 2;
const SWI_DEFAULT_BAUDRATE: u32 = 230_400;
const SWI_WAKE_BAUDRATE: u32 = 115_200;
const SWI_BIT_SEND_DELAY: Duration = Duration::from_micros(45);
pub struct I2cTransport {
    port: I2c<File>,
    address: u16,
}

pub struct SwiTransport {
    port: Box<dyn SerialPort>
}
pub(crate) enum TransportProtocol {
    I2c(I2cTransport),
    Swi(SwiTransport),
}

impl TransportProtocol {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {

        if path.starts_with("/dev/tty"){
            let swi_handle = SwiTransport::init( path )?;
            Ok(Self::Swi(swi_handle))
        }
        else if path.starts_with("/dev/i2c") {
            let i2c_handle = I2cTransport::init(path, address)?;
            Ok(Self::I2c(i2c_handle) )
        }
        else {
            eprintln!("Failed to open selected port");
            ::std::process::exit(1);
        }
    }

    pub fn send_wake(&mut self) -> Result {
        match self {
            Self::I2c(i2c_handle) => {
                i2c_handle.send_wake()
            }
            Self::Swi(swi_handle) => {
                swi_handle.send_wake()
            },
        }
    }

    pub fn send_sleep(&mut self) {
        match self {
            Self::I2c(i2c_handle) => {
                i2c_handle.send_sleep()
            }
            Self::Swi(swi_handle) => {
                swi_handle.send_sleep()
            },
        }
    }

    pub fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) -> Result {
        match self {
            Self::I2c(i2c_handle) => {
                i2c_handle.send_recv_buf( delay, buf )
            }
            Self::Swi(swi_handle) => {
                swi_handle.send_recv_buf( delay, buf )
            },
        }
    }

    pub fn command_duration(&self, command: &EccCommand ) -> Duration {

        let micros = match command {
            EccCommand::Info => 500,
            EccCommand::Read { .. } => 800,
            EccCommand::Write { .. } => 8_000,
            // ecc608b increases the default lock duration of 15_000 by about 30%
            EccCommand::Lock { .. } => 19_500,
            EccCommand::Nonce { .. } => 17_000,
            EccCommand::Random => 15_000,
            EccCommand::GenKey { .. } => match self {
                Self::Swi(_) => {85_000}
                Self::I2c(_) => {59_000}
            }
            EccCommand::Sign { .. } => match self {
                Self::Swi(_) => {80_000}
                Self::I2c(_) => {64_000}
            }
            EccCommand::Ecdh { .. } => match self {
                Self::Swi(_) => {42_000}
                Self::I2c(_) => {28_000}
            }
        };
        Duration::from_micros(micros)
    }

    pub fn put_command_flag( &self ) -> u8 {
        match self {
            Self::I2c(_) => ATCA_I2C_COMMAND_FLAG,
            Self::Swi(_) => ATCA_SWI_COMMAND_FLAG,
        }
    }
}

impl I2cTransport {
    fn init( path: &str, address: u16 ) -> Result<Self> {
        let mut port = I2c::from_path(path)?;
        port.smbus_set_slave_address(address, false)?;

        Ok(Self{port,address,})
    }

    fn send_wake( &mut self ) -> Result {
        let _ = self.send_buf(0, &[0]);
        thread::sleep(WAKE_DELAY);
        Ok(())
    }

    fn send_sleep( &mut self ) {
        let _ = self.send_buf(self.address, &[1]);
    }

    fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) -> Result {
        self.send_buf(self.address, &buf[..])?;
        thread::sleep(delay);
        self.recv_buf(buf)
    }

    fn send_buf(&mut self, address: u16, buf: &[u8]) -> Result {
        let write_msg = i2c_linux::Message::Write {
            address,
            data: buf,
            flags: Default::default(),
        };

        self.port.i2c_transfer(&mut [write_msg])?;
        Ok(())
    }

    fn recv_buf(&mut self, buf: &mut BytesMut) -> Result {
        unsafe { buf.set_len(1) };
        buf[0] = 0xff;
        for _retry in 0..RECV_RETRIES {
            let msg = i2c_linux::Message::Read {
                address: self.address,
                data: &mut buf[0..1],
                flags: Default::default(),
            };
            if let Err(_err) = self.port.i2c_transfer(&mut [msg]) {
            } else {
                break;
            }
            thread::sleep(RECV_RETRY_WAIT);
        }
        let count = buf[0] as usize;
        if count == 0xff {
            return Err(Error::timeout());
        }
        unsafe { buf.set_len(count) };
        let read_msg = i2c_linux::Message::Read {
            address: self.address,
            data: &mut buf[1..count],
            flags: ReadFlags::NO_START,
        };
        self.port.i2c_transfer(&mut [read_msg])?;
        Ok(())
    }
}

impl SwiTransport {
    fn init( path: &str ) -> Result<Self> {
        let port = serialport::new(path, SWI_DEFAULT_BAUDRATE)
        .data_bits(serialport::DataBits::Seven)
        .parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One)
        .timeout(Duration::from_millis(50))
        .open().unwrap_or_else(|e| {
            eprintln!("Failed to open serial port. Error: {}", e);
            ::std::process::exit(1);
        });

        Ok(Self{port})
    }

    fn send_wake(&mut self) -> Result {
        if let Err(_err) = self.port.as_mut().set_baud_rate(SWI_WAKE_BAUDRATE)
        {
            return Err(Error::timeout());
        }

        let _ = self.port.as_mut().write(&[0]);

        thread::sleep(WAKE_DELAY);
        let _ = self.port.as_mut().set_baud_rate(SWI_DEFAULT_BAUDRATE);
        let _ = self.port.as_mut().clear(ClearBuffer::All);
        Ok(())
    }

    fn send_sleep(&mut self) {
        let sleep_encoded = self.encode_uart_to_swi(&[ATCA_SWI_SLEEP_FLAG]);
        let _ = self.port.as_mut().write(&sleep_encoded);
        thread::sleep( SWI_BIT_SEND_DELAY * 8);
    }

    fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) -> Result {
        let _ = self.port.as_mut().clear(ClearBuffer::All);
        let swi_msg = self.encode_uart_to_swi(buf);
        self.send_swi_buf(&swi_msg)?;
        thread::sleep(delay);
        self.recv_swi_buf(buf)
    }

    fn send_swi_buf(&mut self, buf: &[u8]) -> Result {

        let send_size = self.port.as_mut().write(buf)?;

        //Each byte takes ~45us to transmit, so we must wait for the transmission to finish before proceeding
        let uart_tx_time = buf.len() as u32 * SWI_BIT_SEND_DELAY;
        thread::sleep(uart_tx_time);
        //Because Tx line is linked with Rx line, all sent msgs are returned on the Rx line and must be cleared from the buffer
        let mut clear_rx_line = BytesMut::new();
        clear_rx_line.resize(send_size, 0);
        let _ = self.port.as_mut().read_exact( &mut clear_rx_line );

        Ok(())
    }

    fn recv_swi_buf(&mut self, buf: &mut BytesMut) -> Result {
        buf.resize(2, 0xFF);
        buf[1] = 0xFF;

        let encoded_transmit_flag = self.encode_uart_to_swi(&[ATCA_SWI_TRANSMIT_FLAG] );

        let _ = self.port.as_mut().clear(ClearBuffer::All);

        for _retry in 0..RECV_RETRIES {
            self.port.as_mut().write(&encoded_transmit_flag)?;

            if let Err(_err) = self.decode_swi_to_uart(&mut buf[0..2]) {
            } else {
                break;
            }
            thread::sleep(RECV_RETRY_WAIT);
        }

        let _ = buf.split_to(1); // Discard transmit flag

        let count = buf[0] as usize;
        if count == 0xFF {
            return Err(Error::timeout());
        }
        unsafe { buf.set_len(count) };
        if let Err(_err) = self.decode_swi_to_uart(&mut buf[1..count]) {
            return Err(Error::timeout());
        }
        Ok(())
    }

    fn encode_uart_to_swi(&mut self, uart_msg: &[u8] ) -> BytesMut {

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

    fn decode_swi_to_uart(&mut self, buf: &mut [u8]) -> Result {
        for byte_idx in 0..buf.len() {
            let mut decoded_byte = 0;
            let mut bit_mask: u8 = 1;

            while bit_mask != 0 {
                let mut rx_byte = [0; 1];

                if let Ok(_rx_count) = self.port.as_mut().read(&mut rx_byte) {
                    if (rx_byte[0] ^ 0x7F) < 2 {
                        decoded_byte |= bit_mask;
                    }
                } else {
                    return Err(Error::timeout());
                }
                bit_mask = bit_mask << 1;
            }

            buf[byte_idx] = decoded_byte;
        }
        Ok(())
    }
}