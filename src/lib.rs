pub mod file;
pub mod os;

use anyhow::Result;
use ed25519_consensus::SigningKey;
use mockall::automock;
use rand::rngs::OsRng;

pub use file::FileStore;
pub use os::KeyChain;

use crate::file::KeyType;

pub fn create_signing_key() -> SigningKey {
    SigningKey::new(OsRng)
}

pub enum Key {
    Ed25519SigningKey(SigningKey),
    Byte(Vec<u8>),
}

impl Key {
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self {
            Key::Ed25519SigningKey(signing_key) => signing_key.as_bytes().to_vec(),
            Key::Byte(v) => v.clone(),
        }
    }

    pub fn keytype(&self) -> KeyType {
        match &self {
            Key::Ed25519SigningKey(_) => KeyType::Ed25519,
            Key::Byte(_) => KeyType::Byte,
        }
    }
}

#[automock]
pub trait KeyStore {
    fn add_signing_key(&self, id: &str, signing_key: &Key) -> Result<()>;
    fn get_signing_key(&self, id: &str) -> Result<Key>;
    fn get_or_create_signing_key(&self, id: &str) -> Result<Key>;
}
