use crate::{Error, Result};
use bitfield::bitfield;
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Zone {
    Data,
    Config,
}

impl FromStr for Zone {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "data" => Ok(Self::Data),
            "config" => Ok(Self::Config),
            _ => Err(Error::invalid_address()),
        }
    }
}

impl fmt::Display for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => f.write_str("config"),
            Self::Data => f.write_str("data"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DataBuffer {
    TempKey,
    MessageDigest,
    AlternateKey,
}

impl From<&DataBuffer> for u8 {
    fn from(v: &DataBuffer) -> Self {
        match v {
            DataBuffer::TempKey => 0,
            DataBuffer::MessageDigest => 1,
            DataBuffer::AlternateKey => 2,
        }
    }
}

impl From<u8> for DataBuffer {
    fn from(v: u8) -> Self {
        match v & 3 {
            0 => Self::TempKey,
            1 => Self::MessageDigest,
            2 => Self::AlternateKey,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Address {
    Otp(OffsetAddress),
    Config(OffsetAddress),
    Data(DataAddress),
}

bitfield! {
    #[derive(PartialEq, Eq, Clone, Copy)]
    pub struct OffsetAddress(u16);
    impl Debug;
    u8, block, set_block: 4, 3;
    u8, offset, set_offset: 2, 0;
}

bitfield! {
    #[derive(PartialEq, Clone, Copy, Eq)]
    pub struct DataAddress(u16);
    impl Debug;
    u8, block, set_block: 11, 8;
    u8, slot, set_slot: 6, 3;
    u8, offset, set_offset: 2, 0;
}

impl From<&Address> for u16 {
    fn from(v: &Address) -> Self {
        match v {
            Address::Otp(addr) => addr.0,
            Address::Config(addr) => addr.0,
            Address::Data(addr) => addr.0,
        }
    }
}

impl Address {
    pub fn otp(block: u8, offset: u8) -> Result<Self> {
        if block > 4 || offset > 7 {
            return Err(Error::invalid_address());
        }
        let mut address = OffsetAddress(0);
        address.set_block(block);
        address.set_offset(offset);
        Ok(Self::Otp(address))
    }

    pub fn config(block: u8, offset: u8) -> Result<Self> {
        if block > 4 || offset > 7 {
            return Err(Error::invalid_address());
        }
        let mut address = OffsetAddress(0);
        address.set_block(block);
        address.set_offset(offset);
        Ok(Self::Config(address))
    }

    pub fn slot_config(slot: u8) -> Result<Self> {
        if slot > 15 {
            return Err(Error::invalid_address());
        }
        let (block, offset) = if slot <= 5 {
            (0, (20 + slot * 2) >> 2)
        } else {
            (1, ((slot - 5) * 2) >> 2)
        };
        Self::config(block, offset)
    }

    pub fn key_config(slot: u8) -> Result<Self> {
        if slot > 15 {
            return Err(Error::invalid_address());
        }
        Self::config(3, (slot * 2) >> 2)
    }

    pub fn data(slot: u8, block: u8, offset: u8) -> Result<Self> {
        if slot > 15
            || (slot < 8 && block > 1)
            || (slot == 8 && block > 15)
            || (slot > 8 && block > 7)
        {
            return Err(Error::invalid_address());
        }
        let mut address = DataAddress(0);
        address.set_block(block);
        address.set_offset(offset);
        address.set_slot(slot);
        Ok(Self::Data(address))
    }

    pub fn zone(&self) -> u8 {
        match self {
            Self::Config(_) => 0x00,
            Self::Otp(_) => 0x01,
            Self::Data(_) => 0x02,
        }
    }
}
