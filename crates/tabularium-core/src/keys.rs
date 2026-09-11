//! Ed25519 vault keys: generation, storage, signing, verification.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fs;
use std::path::Path;

pub const SECRET_FILE: &str = "vault.key";
pub const PUBLIC_FILE: &str = "vault.pub";

pub struct VaultKeys {
    signing: SigningKey,
}

impl VaultKeys {
    pub fn generate() -> Result<VaultKeys> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Crypto(format!("rng: {e}")))?;
        Ok(VaultKeys { signing: SigningKey::from_bytes(&seed) })
    }

    pub fn from_seed(seed: [u8; 32]) -> VaultKeys {
        VaultKeys { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn save(&self, keys_dir: &Path) -> Result<()> {
        fs::create_dir_all(keys_dir)?;
        let secret_path = keys_dir.join(SECRET_FILE);
        fs::write(&secret_path, hex::encode(self.signing.to_bytes()))?;
        fs::write(keys_dir.join(PUBLIC_FILE), self.public_key_hex())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(keys_dir: &Path) -> Result<VaultKeys> {
        let raw = fs::read_to_string(keys_dir.join(SECRET_FILE))
            .map_err(|e| Error::Config(format!("cannot read vault key: {e}")))?;
        let bytes = hex::decode(raw.trim()).map_err(|e| Error::Crypto(format!("bad key hex: {e}")))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Crypto("vault key must be 32 bytes".into()))?;
        Ok(VaultKeys::from_seed(seed))
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign a message, returning the hex signature.
    pub fn sign_hex(&self, msg: &[u8]) -> Result<String> {
        let sig = self
            .signing
            .try_sign(msg)
            .map_err(|e| Error::Crypto(format!("sign: {e}")))?;
        Ok(hex::encode(sig.to_bytes()))
    }
}

/// Verify a hex signature against a hex public key.
pub fn verify_hex(public_key_hex: &str, msg: &[u8], sig_hex: &str) -> Result<()> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|e| Error::Crypto(format!("bad pubkey hex: {e}")))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| Error::Crypto("public key must be 32 bytes".into()))?;
    let pk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| Error::Crypto(format!("bad pubkey: {e}")))?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| Error::Crypto(format!("bad sig hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::Crypto("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    pk.verify_strict(msg, &sig)
        .map_err(|e| Error::Integrity(format!("signature verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_roundtrip_and_tamper() {
        let keys = VaultKeys::from_seed([7u8; 32]);
        let sig = keys.sign_hex(b"hello").unwrap();
        verify_hex(&keys.public_key_hex(), b"hello", &sig).unwrap();
        assert!(verify_hex(&keys.public_key_hex(), b"hellp", &sig).is_err());
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let keys = VaultKeys::generate().unwrap();
        keys.save(dir.path()).unwrap();
        let loaded = VaultKeys::load(dir.path()).unwrap();
        assert_eq!(keys.public_key_hex(), loaded.public_key_hex());
    }
}
