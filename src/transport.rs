use bytes::BytesMut;
use std::{thread, time::Duration};

use crate::{Result, Error};

#[cfg(all(feature = "swi", feature = "i2c"))]
compile_error!("feature \"swi\" and feature \"i2c\" cannot be enabled at the same time");

#[cfg(feature = "swi")]
use bytes::BufMut;
#[cfg(feature = "swi")]
use serialport::{ClearBuffer, DataBits, SerialPort, StopBits};
#[cfg(feature = "swi")]
use crate::{command::EccResponse, constants::{ATCA_CMD_SIZE_MAX, WAKE_DELAY}};

#[cfg(feature = "i2c")]
use i2c_linux::{I2c, ReadFlags};
#[cfg(feature = "i2c")]
use std::fs::File;


#[cfg(feature = "swi")]
pub struct EccTransport {
    port: String,
}

pub(crate) const RECV_RETRIES: u8 = 2;
pub(crate) const RECV_RETRY_WAIT: Duration = Duration::from_millis(50);

#[cfg(feature = "i2c")]
pub struct EccTransport {
    i2c: I2c<File>,
    address: u16,
}

#[cfg(feature = "i2c")]
impl EccTransport {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {
        let mut i2c = I2c::from_path(path)?;
        i2c.smbus_set_slave_address(address, false)?;
        Ok(Self { i2c, address })
    }

    pub fn send_wake(&mut self) -> Result {
        let _ = self.send_buf(0, &[0]);
        Ok(())
    }

    pub fn send_sleep(&mut self) {
        let _ = self.send_buf(self.address, &[1]);
    }

    pub fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) -> Result {
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

        self.i2c.i2c_transfer(&mut [write_msg])?;
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
            if let Err(_err) = self.i2c.i2c_transfer(&mut [msg]) {
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
        self.i2c.i2c_transfer(&mut [read_msg])?;
        Ok(())
    }
}

#[cfg(feature = "swi")]
impl EccTransport {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {

        let _ = address; //keep the API the same. Address refers to i2c addr which isn't required for SWI
        let port = String::from( path );

        Ok(Self {port})
    }

    pub fn send_wake(&mut self) -> Result {
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
        let mut transmit_flag = BytesMut::new();
        transmit_flag.put_u8(0x88);
        let encoded_transmit_flag = self.encode_uart_to_swi(&transmit_flag );
        uart_cmd.write(&encoded_transmit_flag)?;
        thread::sleep(Duration::from_micros(5_000) );
        
        let mut encoded_msg = BytesMut::new();
        encoded_msg.resize(40,0);
        let _ = uart_cmd.read(&mut encoded_msg);

        let mut decoded_msg = BytesMut::new();
        decoded_msg.resize(5, 0);
        
        self.decode_swi_to_uart(&encoded_msg, &mut decoded_msg);
        
        let response = EccResponse::from_bytes(&decoded_msg[1..]);
        match response {
            Err(e) => return Err(e),
            _ => return Ok(()),
        }
    }

    pub fn send_sleep(&mut self) {        
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

    pub fn send_recv_buf(&mut self, delay: Duration, buf: &mut BytesMut) -> Result {
        
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
        self.send_buf(&swi_msg, &mut uart_driver)?;
        thread::sleep(delay);
        self.recv_buf(buf, &mut uart_driver)
    }

    fn send_buf(&mut self, buf: &[u8], serial_port: &mut Box<dyn SerialPort>) -> Result {
        
        let send_size = serial_port.write(buf)?;

        //Each byte takes ~45us to transmit, so we must wait for the transmission to finish before proceeding
        let uart_tx_time = Duration::from_micros( (buf.len() * 45) as u64); 
        thread::sleep(uart_tx_time);
        //Because Tx line is linked with Rx line, all sent msgs are returned on the Rx line and must be cleared from the buffer
        let mut clear_rx_line = BytesMut::new();
        clear_rx_line.resize(send_size, 0);
        let _ = serial_port.read_exact( &mut clear_rx_line );

        Ok(())
    }

    fn recv_buf(&mut self, buf: &mut BytesMut,  serial_port: &mut Box<dyn SerialPort>) -> Result {
        let mut encoded_msg = BytesMut::new();
        encoded_msg.resize(ATCA_CMD_SIZE_MAX as usize,0);
        
        let mut transmit_flag = BytesMut::new();
        transmit_flag.put_u8(0x88);
        let encoded_transmit_flag = self.encode_uart_to_swi(&transmit_flag );
        
        let _ = serial_port.clear(ClearBuffer::All);

        for retry in 0..RECV_RETRIES {
            serial_port.write(&encoded_transmit_flag)?;
            thread::sleep(Duration::from_micros(40_000) );
            let read_response = serial_port.read(&mut encoded_msg);
            
            match read_response {
                Ok(cnt) if cnt == 8 => { //If the buffer is empty except for the transmit flag, wait & try again
                },
                Ok(cnt) if cnt > 16 => {
                    break;
                },
                _ if retry != RECV_RETRIES => continue,
                _  => return Err(Error::Timeout) 
            }
            
            thread::sleep(RECV_RETRY_WAIT);
        }

        let mut decoded_message = BytesMut::new();
        decoded_message.resize((ATCA_CMD_SIZE_MAX) as usize, 0);   

        self.decode_swi_to_uart(&encoded_msg, &mut decoded_message);

        let encoded_msg_size = decoded_message[1];

        if encoded_msg_size as u16 > ATCA_CMD_SIZE_MAX/8{
            return Err(Error::Timeout)
        }

        buf.resize(encoded_msg_size as usize, 0);

        // Remove the transmit flag at the beginning & the excess buffer space at the end
        let _transmit_flag = decoded_message.split_to(1);
        decoded_message.truncate(encoded_msg_size as usize);

        buf.copy_from_slice(&decoded_message);

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
                if *bit == 0x7F || *bit == 0x7E {
                    *byte ^= 1;
                }
                *byte = byte.rotate_right(1);
            }
            i += 8;
        }
    }

}