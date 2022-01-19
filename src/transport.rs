use bytes::BytesMut;
use std::{thread, time::Duration};

use crate::{Result, Error};

use bytes::BufMut;
use serialport::{ClearBuffer, SerialPort};
use crate::{constants::{ATCA_SWI_SLEEP_FLAG, ATCA_SWI_TRANSMIT_FLAG, WAKE_DELAY}};

use i2c_linux::{I2c, ReadFlags};
use std::fs::File;

const RECV_RETRY_WAIT: Duration = Duration::from_millis(50);
const RECV_RETRIES: u8 = 2;
const SWI_DEFAULT_BAUDRATE: u32 = 230_400;
const SWI_WAKE_BAUDRATE: u32 = 115_200;
const SWI_BIT_SEND_DELAY: Duration = Duration::from_micros(45);

pub(crate) enum TransportProtocol { 
    I2c,
    Swi,
}
pub(crate) struct EccTransport {
    swi_port: Option<Box<dyn SerialPort>>, 
    i2c_port: Option<I2c<File>>,
    i2c_address: u16,
    pub(crate) protocol: TransportProtocol,
}

impl EccTransport {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {
        
        if path.starts_with("/dev/tty"){
            let swi_port = serialport::new(path, SWI_DEFAULT_BAUDRATE)
            .data_bits(serialport::DataBits::Seven)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .timeout(Duration::from_millis(50))
            .open().unwrap_or_else(|e| {
                eprintln!("Failed to open serial port. Error: {}", e);
                ::std::process::exit(1);
            });
            
            Ok(Self {
                i2c_port: None,
                i2c_address: address,
                swi_port: Some(swi_port),
                protocol: TransportProtocol::Swi
            })    
        }
        else if path.starts_with("/dev/i2c") {
            let mut i2c = I2c::from_path(path)?;
            i2c.smbus_set_slave_address(address, false)?;
            
            Ok(Self { 
                swi_port: None,
                i2c_port: Some(i2c),
                i2c_address: address,
                protocol: TransportProtocol::I2c
            })
        }
        else {
            eprintln!("Failed to open selected port");
            ::std::process::exit(1);
        }
    }

    pub fn send_wake(&mut self) -> Result {
        match self.protocol {
            TransportProtocol::I2c =>{
                let _ = self.send_i2c_buf(0, &[0]);
                thread::sleep(WAKE_DELAY);
                Ok(())
            }
            TransportProtocol::Swi => {
                if let Err(_err) = self.swi_port.as_mut().unwrap().set_baud_rate(SWI_WAKE_BAUDRATE)
                {
                    return Err(Error::timeout());
                }
                
                let _ = self.swi_port.as_mut().unwrap().write(&[0]);
                
                thread::sleep(WAKE_DELAY);
                let _ = self.swi_port.as_mut().unwrap().set_baud_rate(SWI_DEFAULT_BAUDRATE);
                let _ = self.swi_port.as_mut().unwrap().clear(ClearBuffer::All);
                Ok(()) 
            },
        }
    }

    pub fn send_sleep(&mut self) {
        match self.protocol {
            TransportProtocol::I2c => {
                let _ = self.send_i2c_buf(self.i2c_address, &[1]);
            } 
            TransportProtocol::Swi => {
                let mut sleep_msg = BytesMut::new();
                sleep_msg.put_u8(ATCA_SWI_SLEEP_FLAG);
                let sleep_encoded = self.encode_uart_to_swi(&sleep_msg);
        
                let _ = self.swi_port.as_mut().unwrap().write(&sleep_encoded);
                thread::sleep( SWI_BIT_SEND_DELAY * 8);
            },
        }
    }

    pub fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) -> Result {
        match self.protocol {
            TransportProtocol::I2c => {
                self.send_i2c_buf(self.i2c_address, &buf[..])?;
                thread::sleep(delay);
                self.recv_i2c_buf(buf)
            },
            TransportProtocol::Swi => {
                let _ = self.swi_port.as_mut().unwrap().clear(ClearBuffer::All);
                let swi_msg = self.encode_uart_to_swi(buf);
                self.send_swi_buf(&swi_msg)?;
                thread::sleep(delay);
                self.recv_swi_buf(buf)
            },
        }
    }

    fn send_i2c_buf(&mut self, address: u16, buf: &[u8]) -> Result {
        let write_msg = i2c_linux::Message::Write {
            address,
            data: buf,
            flags: Default::default(),
        };

        self.i2c_port.as_mut().unwrap().i2c_transfer(&mut [write_msg])?;
        Ok(())
    }

    fn recv_i2c_buf(&mut self, buf: &mut BytesMut) -> Result {
        unsafe { buf.set_len(1) };
        buf[0] = 0xff;
        for _retry in 0..RECV_RETRIES {
            let msg = i2c_linux::Message::Read {
                address: self.i2c_address,
                data: &mut buf[0..1],
                flags: Default::default(),
            };
            if let Err(_err) = self.i2c_port.as_mut().unwrap().i2c_transfer(&mut [msg]) {
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
            address: self.i2c_address,
            data: &mut buf[1..count],
            flags: ReadFlags::NO_START,
        };
        self.i2c_port.as_mut().unwrap().i2c_transfer(&mut [read_msg])?;
        Ok(())
    }

    fn send_swi_buf(&mut self, buf: &[u8]) -> Result {
        
        let send_size = self.swi_port.as_mut().unwrap().write(buf)?;

        //Each byte takes ~45us to transmit, so we must wait for the transmission to finish before proceeding
        let uart_tx_time = buf.len() as u32 * SWI_BIT_SEND_DELAY; 
        thread::sleep(uart_tx_time);
        //Because Tx line is linked with Rx line, all sent msgs are returned on the Rx line and must be cleared from the buffer
        let mut clear_rx_line = BytesMut::new();
        clear_rx_line.resize(send_size, 0);
        let _ = self.swi_port.as_mut().unwrap().read_exact( &mut clear_rx_line );

        Ok(())
    }

    fn recv_swi_buf(&mut self, buf: &mut BytesMut) -> Result {
        unsafe { buf.set_len(2) };
        buf[1] = 0xFF;

        let mut transmit_flag = BytesMut::new();
        transmit_flag.put_u8(ATCA_SWI_TRANSMIT_FLAG);
        let encoded_transmit_flag = self.encode_uart_to_swi(&transmit_flag );

        let _ = self.swi_port.as_mut().unwrap().clear(ClearBuffer::All);

        for _retry in 0..RECV_RETRIES {
            self.swi_port.as_mut().unwrap().write(&encoded_transmit_flag)?;

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

    fn decode_swi_to_uart(&mut self, buf: &mut [u8]) -> Result {
        for byte_idx in 0..buf.len() {
            let mut decoded_byte = 0;
            let mut bit_mask: u8 = 1;

            while bit_mask != 0 {
                let mut rx_byte = [0; 1];

                if let Ok(_rx_count) = self.swi_port.as_mut().unwrap().read(&mut rx_byte) {
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