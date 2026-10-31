use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::crypto::{DataEncryptionKey, KeyEncryptionKey};

const MAGIC_BYTES: &[u8; 4] = b"VLT1";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 117;

#[derive(Debug)]
pub enum VaultError {
    InvalidFormat,
    UnsupportedVersion,
    DecryptionFailed,
}

pub fn encrypt_vault(
    kek: &KeyEncryptionKey,
    argon_salt: &[u8; 16],
    payload_plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let mut dek_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut dek_bytes);
    let dek = DataEncryptionKey::new(dek_bytes);
    dek_bytes.zeroize();

    // Le PlaintextGuard gere sa propre destruction en fin de scope
    let kek_guard = kek.unseal().map_err(|_| VaultError::DecryptionFailed)?;
    let cipher_kek = XChaCha20Poly1305::new(kek_guard.as_bytes().into());

    let mut dek_nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut dek_nonce_bytes);
    let dek_nonce = XNonce::from(dek_nonce_bytes);

    let encrypted_dek = cipher_kek
        .encrypt(&dek_nonce, dek.as_bytes())
        .map_err(|_| VaultError::DecryptionFailed)?;

    let cipher_dek = XChaCha20Poly1305::new(dek.as_bytes().into());
    let mut payload_nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut payload_nonce_bytes);
    let payload_nonce = XNonce::from(payload_nonce_bytes);

    let encrypted_payload = cipher_dek
        .encrypt(&payload_nonce, payload_plaintext)
        .map_err(|_| VaultError::DecryptionFailed)?;

    let mut vault_file = Vec::with_capacity(HEADER_SIZE + encrypted_payload.len());
    vault_file.extend_from_slice(MAGIC_BYTES);
    vault_file.push(VERSION);
    vault_file.extend_from_slice(argon_salt);
    vault_file.extend_from_slice(&dek_nonce_bytes);
    vault_file.extend_from_slice(&encrypted_dek);
    vault_file.extend_from_slice(&payload_nonce_bytes);
    vault_file.extend_from_slice(&encrypted_payload);

    Ok(vault_file)
}

pub fn decrypt_vault(kek: &KeyEncryptionKey, vault_bytes: &[u8]) -> Result<Vec<u8>, VaultError> {
    if vault_bytes.len() < HEADER_SIZE {
        return Err(VaultError::InvalidFormat);
    }
    if &vault_bytes[0..4] != MAGIC_BYTES {
        return Err(VaultError::InvalidFormat);
    }
    if vault_bytes[4] != VERSION {
        return Err(VaultError::UnsupportedVersion);
    }

    let dek_nonce = XNonce::from_slice(&vault_bytes[21..45]);
    let encrypted_dek = &vault_bytes[45..93];
    let payload_nonce = XNonce::from_slice(&vault_bytes[93..117]);
    let encrypted_payload = &vault_bytes[117..];

    // Le PlaintextGuard gère sa propre destruction en fin de scope
    let kek_guard = kek.unseal().map_err(|_| VaultError::DecryptionFailed)?;
    let cipher_kek = XChaCha20Poly1305::new(kek_guard.as_bytes().into());

    let mut dek_bytes = cipher_kek
        .decrypt(dek_nonce, encrypted_dek)
        .map_err(|_| VaultError::DecryptionFailed)?;

    let mut safe_dek_array = [0u8; 32];
    safe_dek_array.copy_from_slice(&dek_bytes);

    dek_bytes.zeroize();

    let dek = DataEncryptionKey::new(safe_dek_array);
    safe_dek_array.zeroize();

    let cipher_dek = XChaCha20Poly1305::new(dek.as_bytes().into());
    let plaintext_payload = cipher_dek
        .decrypt(payload_nonce, encrypted_payload)
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok(plaintext_payload)
}
