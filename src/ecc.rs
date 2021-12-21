use crate::constants::{ATCA_CMD_SIZE_MAX, WAKE_DELAY};
use crate::{
    command::{EccCommand, EccResponse},
    Address, DataBuffer, Error, KeyConfig, Result, SlotConfig, Zone,
};
use bytes::{BufMut, Bytes, BytesMut};
use i2c_linux::{I2c, ReadFlags};
use serialport::SerialPort;
use sha2::{Digest, Sha256};
use std::{fs::File, thread, time::Duration};

pub use crate::command::KeyType;

#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum EccIface {
    EccI2CIface = 0,                         //Standard I2C interface
    EccSWIIface = 1,                         //SWI Iface over UART
}

pub struct Ecc {
    i2c: Option<I2c<File>>,                  //Field changed to optional to support other protocols
    address: u16,                            //To keep backward compatibility, the address field is used to decide on the protocol. Address 0 reserved for SWI
    port: Option<Box<dyn SerialPort>>,       //Used to implement SWI over UART, or other direct uart interfaces
    iface: EccIface,                         //Should be set on instance creation to define the selected protocol. Parsed from address in from_path
}

pub const MAX_SLOT: u8 = 15;

pub(crate) const RECV_RETRIES: u8 = 2;
pub(crate) const RECV_RETRY_WAIT: Duration = Duration::from_millis(50);
pub(crate) const CMD_RETRIES: u8 = 10;

pub(crate) const SWI_IOFLAG_CMD: u8   = 0x77;          //Header flag to be sent before command in case of SWI
pub(crate) const SWI_IOFLAG_TX: u8    = 0x88;          //Transmit flag used to tell the device to start transmitting its response
pub(crate) const SWI_IOFLAG_WAKE: u8  = 0x00;          //Upon receipt of a wake flag, the device wakes up from sleep or idle modes
pub(crate) const SWI_IOFLAG_SLEEP: u8 = 0xCC;          //Upon receipt of a sleep flag, the device enters the low-power sleep mode

pub(crate) const SWI_DEFAULT_BAUDRATE: u32  = 230_400;    //Default baud rate used for communication
pub(crate) const SWI_WAKE_BAUDRATE: u32     = 115_200;    //Baudrate used only for wake to simulate a long low level pulse
pub(crate) const SWI_SERIAL_TIMEOUT_MS: u64 = 500;        //Default timeout on serial bus
pub(crate) const SWI_BYTE_AS_BIT_ONE: u8    = 0x7F;       //In SWI each bit is transmitted as UART byte, bit 1 is sent as 0x7F
pub(crate) const SWI_BYTE_AS_BIT_ZERO: u8   = 0x7D;       //In SWI each bit is transmitted as UART byte, bit 0 is sent as 0x7D

impl Ecc {
    pub fn from_path(path: &str, address: u16) -> Result<Self> {
        if address != 0 {                            //Address 0 is reserved for SWI, I2C being the only other option for this implementation
        let mut i2c = I2c::from_path(path)?;
        i2c.smbus_set_slave_address(address, false)?;
            Ok(Self {
                i2c: Some(i2c),
                address,
                port: None,
                iface: EccIface::EccI2CIface,
            })
        } else {
            if let Ok(port) = serialport::new(path, SWI_DEFAULT_BAUDRATE) //From ECC datasheet, The UART should be set to seven data bits, no parity and one Stop bit.
                .data_bits(serialport::DataBits::Seven)
                .parity(serialport::Parity::None)
                .stop_bits(serialport::StopBits::One)
                .timeout(Duration::from_millis(SWI_SERIAL_TIMEOUT_MS))
                .open()
            {
                Ok(Self {
                    i2c: None,
                    address,
                    port: Some(port),
                    iface: EccIface::EccSWIIface,
                })
            } else {
                Err(Error::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unable to open serial port",
                )))
            }
        }
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

    fn send_wake(&mut self) {
        match self.iface {
            EccIface::EccI2CIface => {
                let _ = self.send_buf(self.address, &[0]);
            }
            EccIface::EccSWIIface => {
                let mut rx_buf: Vec<u8> = vec![0; 1];

                let _ = self.port.as_mut().unwrap().set_baud_rate(SWI_WAKE_BAUDRATE);     //Wake is a long low pulse, reduce baudrate to emulate it
                let _ = self.port.as_mut().unwrap().write(&[SWI_IOFLAG_WAKE]);            //No need to encode bits for wake, just send
                let _ = self.port.as_mut().unwrap().read(rx_buf.as_mut_slice());          //Dummy read back
                let _ = self.port.as_mut().unwrap().set_baud_rate(SWI_DEFAULT_BAUDRATE);  //Reset baud rate to default value
            }
        }
    }

    fn send_sleep(&mut self) {
        match self.iface {
            EccIface::EccI2CIface => {
        let _ = self.send_buf(self.address, &[1]);
    }
            EccIface::EccSWIIface => {
                let _ = self.send_buf(self.address, &[SWI_IOFLAG_SLEEP]);
            }
        }
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

            match self.iface {                  //CMD byte is different between SWI and I2C
                EccIface::EccI2CIface => {
                    buf[0] = 0x03;
                }
                EccIface::EccSWIIface => {
                    buf[0] = SWI_IOFLAG_CMD;
                }
            }

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
        self.send_buf(self.address, &buf[..])?;
        thread::sleep(delay);
        self.recv_buf(buf)
    }

    pub(crate) fn swi_bits_to_bytes(&mut self, buf: &[u8]) -> Vec<u8> {
        let mut vec = Vec::new();
        for n in 0..buf.len() {
            for bit_mask in 0..8 {
                if buf[n] & (1 << bit_mask) == 0 {
                    vec.push(SWI_BYTE_AS_BIT_ZERO);
                } else {
                    vec.push(SWI_BYTE_AS_BIT_ONE);
                }
            }
        }
        vec
    }

    pub(crate) fn send_buf(&mut self, address: u16, buf: &[u8]) -> Result {
        match self.iface {
            EccIface::EccI2CIface => {
        let write_msg = i2c_linux::Message::Write {
            address,
            data: buf,
            flags: Default::default(),
        };
                self.i2c.as_mut().unwrap().i2c_transfer(&mut [write_msg])?;
            }

            EccIface::EccSWIIface => {
                let bytes = &self.swi_bits_to_bytes(buf);        //In SWI mode, each bit is sent as byte. Transform bits to bytes before sending.

                for i in 0..bytes.len() {                        //Send one byte at a time and make sure the byte is transferred succesfully by comparing it to RX byte.
                    let mut rx_buf: Vec<u8> = vec![0; 1];
                    self.port.as_mut().unwrap().write(&[bytes[i]])?;
                    self.port.as_mut().unwrap().read(rx_buf.as_mut_slice())?;
                    if rx_buf[0] != bytes[i] {
                        return Err(Error::timeout());
                    }
                }
            }
        }

        Ok(())
    }

    fn swi_receive(&mut self, buf: &mut [u8]) -> Result {
        for byte_idx in 0..buf.len() {
            let mut decoded_byte = 0;
            let mut bit_mask: u8 = 1;

            while bit_mask != 0 {
                let mut rx_byte = [0; 1];

                if let Ok(_rx_count) = self.port.as_mut().unwrap().read(&mut rx_byte) {
                    if (rx_byte[0] ^ SWI_BYTE_AS_BIT_ONE) < 2 {
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

    pub(crate) fn recv_buf(&mut self, buf: &mut BytesMut) -> Result {
        match self.iface {
            EccIface::EccI2CIface => {
                unsafe { buf.set_len(1) };
                buf[0] = 0xff;
                for _retry in 0..RECV_RETRIES {
                    let msg = i2c_linux::Message::Read {
                        address: self.address,
                        data: &mut buf[0..1],
                        flags: Default::default(),
                    };
                    
                    if let Err(_err) = self.i2c.as_mut().unwrap().i2c_transfer(&mut [msg]) {
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
                self.i2c.as_mut().unwrap().i2c_transfer(&mut [read_msg])?;
            }

            EccIface::EccSWIIface => {

                if let Err(_err) = self.port.as_mut().unwrap().set_baud_rate(SWI_DEFAULT_BAUDRATE)
                {
                    return Err(Error::timeout());
                }
                unsafe { buf.set_len(1) };
                buf[0] = 0xff;
                for _retry in 0..RECV_RETRIES {
                    self.send_buf(self.address, &[SWI_IOFLAG_TX])?;
                    if let Err(_err) = self.swi_receive(&mut buf[0..1]) {
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
                if let Err(_err) = self.swi_receive(&mut buf[1..count]) {
                    return Err(Error::timeout());
                }
            }
        }

        Ok(())
    }
}
