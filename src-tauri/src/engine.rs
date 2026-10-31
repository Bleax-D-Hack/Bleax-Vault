use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::fmt::Write;
use zeroize::Zeroize;

use crate::crypto::{KeyEncryptionKey, MasterPassword, UsbKey};
use crate::models::VaultPayload;
use crate::vault::encrypt_vault;

use bip39::{Language, Mnemonic};

pub fn generate_usb_key() -> UsbKey {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let key = UsbKey::new(key_bytes);
    key_bytes.zeroize();
    key
}

pub fn derive_password(
    password: &MasterPassword,
    salt: &[u8; 16],
) -> Result<[u8; 32], argon2::Error> {
    // Contraintes Argon2id: 512MB RAM, 3 iterations pour mitiger le parallélisme ASIC/GPU.
    let params = Params::new(524288, 3, 4, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut output)?;
    Ok(output)
}

pub fn generate_kek(
    password_hash: &[u8; 32],
    usb_key: &UsbKey,
) -> Result<KeyEncryptionKey, hkdf::InvalidLength> {
    let hkdf = Hkdf::<Sha256>::new(Some(usb_key.as_bytes()), password_hash);

    let mut kek_bytes = [0u8; 32];
    hkdf.expand(b"Vault-KEK-v1", &mut kek_bytes)?;

    let kek = KeyEncryptionKey::new(kek_bytes);
    kek_bytes.zeroize();
    Ok(kek)
}

pub fn pack_and_encrypt(
    kek: &KeyEncryptionKey,
    salt: &[u8; 16],
    payload: &VaultPayload,
) -> Result<Vec<u8>, String> {
    let mut json_bytes = Vec::with_capacity(1024 * 1024);

    serde_json::to_writer(&mut json_bytes, payload).map_err(|e| format!("Erreur JSON : {}", e))?;

    let final_bytes = encrypt_vault(kek, salt, &json_bytes)
        .map_err(|_| "Erreur lors du chiffrement du coffre".to_string())?;

    json_bytes.zeroize();
    Ok(final_bytes)
}

pub fn generate_argon_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_recovery_phrase(usb_key: &UsbKey) -> Result<String, String> {
    let mnemonic = Mnemonic::from_entropy(usb_key.as_bytes()).map_err(|e| e.to_string())?;

    let mut phrase = String::with_capacity(256);
    write!(&mut phrase, "{}", mnemonic).map_err(|_| "Erreur de formatage".to_string())?;

    Ok(phrase)
}

pub fn recover_usb_key_from_phrase(phrase: &str) -> Result<UsbKey, String> {
    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, phrase).map_err(|e| e.to_string())?;

    let mut entropy = mnemonic.to_entropy();
    let mut key_bytes = [0u8; 32];
    let is_valid = entropy.len() == 32;

    if is_valid {
        key_bytes.copy_from_slice(&entropy);
    }

    entropy.zeroize();

    if is_valid {
        let key = UsbKey::new(key_bytes);
        key_bytes.zeroize();
        Ok(key)
    } else {
        key_bytes.zeroize();
        Err("L'entropie ne correspond pas à 256 bits (24 mots attendus).".into())
    }
}
