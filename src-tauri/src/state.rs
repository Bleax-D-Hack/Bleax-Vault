use std::sync::Mutex;
use std::time::Instant;
use crate::crypto::KeyEncryptionKey;

pub struct VaultSession {
    pub kek: KeyEncryptionKey,
    pub argon_salt: [u8; 16],
    pub vault_path: String,
}

pub struct AppState {
    pub session: Mutex<Option<VaultSession>>,
    pub last_activity: Mutex<Instant>,
}

impl AppState {
    pub fn new() -> Self {
        Self { 
            session: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
        }
    }
}