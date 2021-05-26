use bitfield::bitfield;
use bytes::Buf;
use serde_derive::Serialize;

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyConfigType {
    Ecc,
    NotEcc,
}

impl From<u8> for KeyConfigType {
    fn from(v: u8) -> Self {
        match v & 4 == 4 {
            true => Self::Ecc,
            _ => Self::NotEcc,
        }
    }
}

impl From<KeyConfigType> for u8 {
    fn from(v: KeyConfigType) -> Self {
        match v {
            KeyConfigType::Ecc => 4,
            KeyConfigType::NotEcc => 7,
        }
    }
}

impl From<&[u8]> for KeyConfig {
    fn from(v: &[u8]) -> Self {
        let mut buf = v;
        Self(buf.get_u16())
    }
}

bitfield! {
    #[derive(PartialEq)]
    pub struct KeyConfig(u16);
    impl Debug;

    u8, auth_key, set_auth_key: 3, 0;
    intrusion_disable, set_intrusion_disable: 4;
    u8, x509_index, set_x509_index: 7, 6;

    private, set_private: 8;
    pub_info, set_pub_info: 9;
    u8, from into KeyConfigType, key_type, set_key_type: 12, 10;
    lockable, set_is_lockable: 13;
    req_random, set_req_random: 14;
    req_auth, set_req_auth: 15;
}

impl From<u16> for KeyConfig {
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl From<KeyConfig> for u16 {
    fn from(v: KeyConfig) -> Self {
        v.0
    }
}

impl From<&KeyConfig> for u16 {
    fn from(v: &KeyConfig) -> Self {
        v.0
    }
}

///  Returns a key configuration set up to store ECC key private keys.
impl Default for KeyConfig {
    fn default() -> Self {
        let mut result = KeyConfig(0);
        result.set_key_type(KeyConfigType::Ecc);
        result.set_is_lockable(true);
        result.set_private(true);
        result.set_pub_info(true);
        result
    }
}

impl serde::ser::Serialize for KeyConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("key_config", 9)?;
        state.serialize_field("auth_key", &self.auth_key())?;
        state.serialize_field("intrusion_disable", &self.intrusion_disable())?;
        state.serialize_field("x509_index", &self.x509_index())?;
        state.serialize_field("private", &self.private())?;
        state.serialize_field("pub_info", &self.pub_info())?;
        state.serialize_field("key_type", &self.key_type())?;
        state.serialize_field("lockable", &self.lockable())?;
        state.serialize_field("req_random", &self.req_random())?;
        state.serialize_field("req_auth", &self.req_auth())?;

        state.end()
    }
}
