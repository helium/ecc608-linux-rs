pub(crate) const ATCA_CMD_SIZE_MAX: u8 = 4 * 36 + 7;

pub(crate) const CMD_STATUS_BYTE_SUCCESS: u8 = 0x00;
pub(crate) const CMD_STATUS_BYTE_PARSE: u8 = 0x03;
pub(crate) const CMD_STATUS_BYTE_ECC: u8 = 0x05;
pub(crate) const CMD_STATUS_BYTE_SELF_TEST: u8 = 0x07;
pub(crate) const CMD_STATUS_BYTE_EXEC: u8 = 0x0F;
pub(crate) const CMD_STATUS_BYTE_WATCHDOG: u8 = 0xEE;
pub(crate) const CMD_STATUS_BYTE_COMM: u8 = 0xFF;

pub(crate) const ATCA_RSP_SIZE_MIN: u8 = 4;
pub(crate) const ATCA_RSP_SIZE_MAX: u8 = 75;

pub(crate) const ATCA_SWI_TRANSMIT_FLAG: u8 = 0x88;
pub(crate) const ATCA_SWI_SLEEP_FLAG: u8 = 0xCC;
pub(crate) const ATCA_SWI_IDLE_FLAG: u8 = 0xBB;
pub(crate) const ATCA_SWI_COMMAND_FLAG: u8 = 0x77;
pub(crate) const ATCA_I2C_COMMAND_FLAG: u8 = 0x03;
pub(crate) const ATCA_INFO: u8 = 0x30;
pub(crate) const ATCA_READ: u8 = 0x02;
pub(crate) const ATCA_WRITE: u8 = 0x12;
pub(crate) const ATCA_NONCE: u8 = 0x16;
pub(crate) const ATCA_LOCK: u8 = 0x17;
pub(crate) const ATCA_RANDOM: u8 = 0x1B;
pub(crate) const ATCA_GENKEY: u8 = 0x40;
pub(crate) const ATCA_SIGN: u8 = 0x41;
pub(crate) const ATCA_ECDH: u8 = 0x43;
