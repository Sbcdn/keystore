use crate::{create_signing_key, Key, KeyStore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use dotenvy::dotenv;
use ed25519_consensus::SigningKey;
use hex;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::{env, fs, path::PathBuf};

#[derive(Serialize, Deserialize, Default)]
struct EncryptedKeyStoreFile {
    keys: HashMap<String, EncryptedKey>,
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) enum KeyType {
    #[default]
    Ed25519,
    Byte,
}
#[derive(Serialize, Deserialize)]
struct EncryptedKey {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    keytype: KeyType,
}

pub struct FileStore {
    file_path: PathBuf,
    cipher: Aes256Gcm,
}

impl FileStore {
    pub fn new<P: Into<PathBuf>>(file_path: P) -> Result<Self> {
        let file_path = file_path.into();
        let expanded_path = if file_path.to_string_lossy().starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                home.join(file_path.to_string_lossy()[2..].to_string())
            } else {
                return Err(anyhow!("Could not determine home directory"));
            }
        } else {
            file_path
        };

        let cipher = load_symmetric_key()?;
        Ok(FileStore {
            file_path: expanded_path,
            cipher,
        })
    }

    fn read_store(&self) -> Result<EncryptedKeyStoreFile> {
        if !self.file_path.exists() {
            if let Some(parent) = self.file_path.parent() {
                fs::create_dir_all(parent).context("Failed to create keystore directory")?;
            }
            return Ok(EncryptedKeyStoreFile::default());
        }

        let content = fs::read_to_string(&self.file_path).context(format!(
            "Failed to read keystore file at {:?}",
            self.file_path
        ))?;

        serde_json::from_str(&content).context(format!(
            "Failed to parse keystore file at {:?}. Content: {}",
            self.file_path, content
        ))
    }

    fn write_store(&self, store: &EncryptedKeyStoreFile) -> Result<()> {
        // we have to ensure the directory exists
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent).context("Failed to create keystore directory")?;
        }

        let content =
            serde_json::to_string_pretty(store).context("Failed to serialize keystore")?;

        fs::write(&self.file_path, content).context("Failed to write keystore file")
    }

    fn encrypt_key(&self, key: &Key) -> Result<EncryptedKey> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, key.to_bytes().as_ref())
            .map_err(|e| anyhow!("Failed to encrypt key: {}", e))?;

        let keytype = key.keytype();

        Ok(EncryptedKey {
            nonce: nonce.to_vec(),
            ciphertext,
            keytype,
        })
    }

    fn decrypt_key(&self, encrypted: &EncryptedKey) -> Result<Key> {
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| anyhow!("Failed to decrypt key: {}", e))?;
        let mut key_array = [0u8; 32];
        match encrypted.keytype {
            KeyType::Ed25519 => {
                if plaintext.len() != 32 {
                    bail!("Decrypted data has incorrect length for ed25519 key");
                } else {
                    key_array.copy_from_slice(&plaintext);
                }
            }
            KeyType::Byte => {}
        }

        match encrypted.keytype {
            KeyType::Ed25519 => Ok(Key::Ed25519SigningKey(SigningKey::from(key_array))),
            KeyType::Byte => Ok(Key::Byte(plaintext)),
        }
    }
}

impl KeyStore for FileStore {
    fn add_signing_key(&self, id: &str, signing_key: &Key) -> Result<()> {
        let mut store = self.read_store()?;
        let encrypted = self.encrypt_key(signing_key)?;
        store.keys.insert(id.to_string(), encrypted);
        self.write_store(&store)
    }

    fn get_signing_key(&self, id: &str) -> Result<Key> {
        let store = self.read_store()?;

        let encrypted = store
            .keys
            .get(id)
            .ok_or_else(|| anyhow!("No key found for id: {}", id))?;

        self.decrypt_key(encrypted)
    }

    fn get_or_create_signing_key(&self, id: &str) -> Result<Key> {
        match self.get_signing_key(id) {
            Ok(key) => Ok(key),
            Err(_) => {
                let new_key = create_signing_key();
                self.add_signing_key(id, &Key::Ed25519SigningKey(new_key.clone()))?;
                Ok(Key::Ed25519SigningKey(new_key))
            }
        }
    }
}

fn load_symmetric_key() -> Result<Aes256Gcm> {
    dotenv().ok();
    let key = env::var("SYMMETRIC_KEY").context("Failed to load symmetric key")?;
    let cipher = Aes256Gcm::new_from_slice(&hex::decode(key)?)
        .map_err(|e| anyhow!("Failed to create symmetric key: {}", e))?;
    Ok(cipher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup_test_env() {
        std::env::set_var(
            "SYMMETRIC_KEY",
            "44a28a80b65029c1f4d4dd9e867cd91bb4c5ea07f232f395d64fb327f1c45c1c",
        );
    }

    #[test]
    fn test_store_and_retrieve_key() {
        setup_test_env();
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_keystore.json");
        let store = FileStore::new(file_path).unwrap();

        let id = "test_key";
        let original_key = create_signing_key();
        store
            .add_signing_key(id, &Key::Ed25519SigningKey(original_key.clone()))
            .unwrap();

        let retrieved_key: [u8; 32] = store
            .get_signing_key(id)
            .unwrap()
            .to_bytes()
            .try_into()
            .unwrap();
        assert_eq!(original_key.to_bytes(), retrieved_key);
    }

    #[test]
    fn test_get_nonexistent_key() {
        setup_test_env();
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_keystore.json");
        let store = FileStore::new(file_path).unwrap();

        let result = store.get_signing_key("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_or_create_key() {
        setup_test_env();
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_keystore.json");
        let store = FileStore::new(file_path).unwrap();

        let id = "test_key";

        let key1 = store.get_or_create_signing_key(id).unwrap();
        let key2 = store.get_or_create_signing_key(id).unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }
}
