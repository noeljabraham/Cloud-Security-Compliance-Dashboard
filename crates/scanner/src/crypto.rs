use ring::{
    aead::{
        AES_256_GCM, Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey,
        UnboundKey,
    },
    error::Unspecified,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use std::env;

use crate::error::ScannerError;

const DEFAULT_DEV_KEY: &str = "cloudsec-default-dev-managed-encryption-key-32bytes!";

struct SingleNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(Unspecified)
    }
}

pub struct EncryptionService {
    key_bytes: [u8; 32],
    rng: SystemRandom,
}

impl Default for EncryptionService {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionService {
    pub fn new() -> Self {
        let master_key = env::var("ENCRYPTION_KEY").unwrap_or_else(|_| DEFAULT_DEV_KEY.to_string());
        let mut hasher = Sha256::new();
        hasher.update(master_key.as_bytes());
        let hash = hasher.finalize();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&hash);

        Self {
            key_bytes,
            rng: SystemRandom::new(),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, ScannerError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| ScannerError::Internal("failed to generate cryptographic nonce".into()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| ScannerError::Internal("invalid encryption key".into()))?;
        let mut sealing_key = SealingKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|_| ScannerError::Internal("encryption failed".into()))?;

        Ok(format!(
            "aes256gcm:{}:{}",
            hex::encode(nonce_bytes),
            hex::encode(in_out)
        ))
    }

    pub fn decrypt(&self, encrypted_payload: &str) -> Result<Vec<u8>, ScannerError> {
        let parts: Vec<&str> = encrypted_payload.split(':').collect();
        if parts.len() != 3 || parts[0] != "aes256gcm" {
            return Err(ScannerError::Internal(
                "invalid encrypted payload format".into(),
            ));
        }

        let nonce_bytes = hex::decode(parts[1])
            .map_err(|_| ScannerError::Internal("invalid nonce hex in payload".into()))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(ScannerError::Internal("invalid nonce length".into()));
        }

        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&nonce_bytes);

        let mut in_out = hex::decode(parts[2])
            .map_err(|_| ScannerError::Internal("invalid ciphertext hex in payload".into()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| ScannerError::Internal("invalid encryption key".into()))?;
        let mut opening_key = OpeningKey::new(unbound_key, SingleNonce(Some(nonce_arr)));

        let decrypted = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| {
                ScannerError::AuthenticationFailed(
                    "ciphertext integrity or decryption check failed".into(),
                )
            })?;

        Ok(decrypted.to_vec())
    }

    /// Decrypts a payload attempting the active master key first, then falling back to previous keys during rotation.
    pub fn decrypt_with_fallback(
        &self,
        encrypted_payload: &str,
        previous_keys: &[[u8; 32]],
    ) -> Result<Vec<u8>, ScannerError> {
        if let Ok(res) = self.decrypt(encrypted_payload) {
            return Ok(res);
        }

        let parts: Vec<&str> = encrypted_payload.split(':').collect();
        if parts.len() != 3 || parts[0] != "aes256gcm" {
            return Err(ScannerError::Internal(
                "invalid encrypted payload format".into(),
            ));
        }

        let nonce_bytes = hex::decode(parts[1])
            .map_err(|_| ScannerError::Internal("invalid nonce hex in payload".into()))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(ScannerError::Internal("invalid nonce length".into()));
        }

        for fallback_key in previous_keys {
            let mut nonce_arr = [0u8; NONCE_LEN];
            nonce_arr.copy_from_slice(&nonce_bytes);

            let mut in_out = match hex::decode(parts[2]) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let unbound_key = match UnboundKey::new(&AES_256_GCM, fallback_key) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let mut opening_key = OpeningKey::new(unbound_key, SingleNonce(Some(nonce_arr)));
            if let Ok(decrypted) = opening_key.open_in_place(Aad::empty(), &mut in_out) {
                return Ok(decrypted.to_vec());
            }
        }

        Err(ScannerError::AuthenticationFailed(
            "ciphertext integrity or decryption check failed across active and fallback keys"
                .into(),
        ))
    }
}

/// Pluggable Secrets Manager abstraction for KMS, HashiCorp Vault, AWS Secrets Manager, or Environment variables.
pub trait SecretsProvider: Send + Sync {
    fn get_secret(&self, secret_id: &str) -> Result<String, ScannerError>;
}

pub struct EnvSecretsProvider;

impl SecretsProvider for EnvSecretsProvider {
    fn get_secret(&self, secret_id: &str) -> Result<String, ScannerError> {
        env::var(secret_id).map_err(|_| {
            ScannerError::Internal(format!("secret '{secret_id}' not found in environment"))
        })
    }
}

pub struct StaticSecretsProvider {
    secrets: std::collections::HashMap<String, String>,
}

impl StaticSecretsProvider {
    pub fn new(secrets: std::collections::HashMap<String, String>) -> Self {
        Self { secrets }
    }
}

impl SecretsProvider for StaticSecretsProvider {
    fn get_secret(&self, secret_id: &str) -> Result<String, ScannerError> {
        self.secrets
            .get(secret_id)
            .cloned()
            .ok_or_else(|| ScannerError::Internal(format!("secret '{secret_id}' not found")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_and_decryption_roundtrip() {
        let service = EncryptionService::new();
        let secret = b"sensitive_cloud_workload_token_or_credential_xyz";

        let encrypted = service.encrypt(secret).expect("encryption should succeed");
        assert!(encrypted.starts_with("aes256gcm:"));
        assert!(!encrypted.contains("sensitive_cloud_workload_token"));

        let decrypted = service
            .decrypt(&encrypted)
            .expect("decryption should succeed");
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_decryption_tamper_detection() {
        let service = EncryptionService::new();
        let secret = b"super_secret";
        let encrypted = service.encrypt(secret).unwrap();

        // Tamper with ciphertext
        let mut tampered = encrypted.clone();
        tampered.push('a');
        assert!(service.decrypt(&tampered).is_err());
    }

    #[test]
    fn test_key_rotation_dual_key_fallback() {
        let old_service = EncryptionService::new();
        let old_key = old_service.key_bytes;
        let secret = b"payload_encrypted_with_retiring_key";
        let ciphertext = old_service.encrypt(secret).unwrap();

        // New service with a rotated key
        let mut new_service = EncryptionService::new();
        new_service.key_bytes = [0x42u8; 32];

        // Direct decryption with new key fails
        assert!(new_service.decrypt(&ciphertext).is_err());

        // Decryption with previous key fallback succeeds seamlessly
        let decrypted = new_service
            .decrypt_with_fallback(&ciphertext, &[old_key])
            .expect("fallback key decryption should succeed");
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_static_secrets_provider() {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert("db_pass".to_string(), "super-safe-pass".to_string());
        let provider = StaticSecretsProvider::new(secrets);

        assert_eq!(provider.get_secret("db_pass").unwrap(), "super-safe-pass");
        assert!(provider.get_secret("non_existent").is_err());
    }
}
