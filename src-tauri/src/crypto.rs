use crate::os_memory::{lock_memory, unlock_memory};
use zeroize::Zeroize;

#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectMemory, CryptUnprotectMemory, CRYPTPROTECTMEMORY_SAME_PROCESS,
};

pub struct MasterPassword(String);

impl MasterPassword {
    pub fn new(password: String) -> Self {
        let ptr = password.as_ptr();
        let cap = password.capacity();
        lock_memory(ptr, cap);
        Self(password)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Drop for MasterPassword {
    fn drop(&mut self) {
        unlock_memory(self.0.as_ptr(), self.0.capacity());
        self.0.zeroize();
    }
}

pub struct UsbKey([u8; 32]);

impl UsbKey {
    pub fn new(key: [u8; 32]) -> Self {
        lock_memory(key.as_ptr(), key.len());
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for UsbKey {
    fn drop(&mut self) {
        self.0.zeroize();
        unlock_memory(self.0.as_ptr(), self.0.len());
    }
}

pub struct KeyEncryptionKey([u8; 32]);

pub struct PlaintextGuard {
    pub data: [u8; 32],
}

impl PlaintextGuard {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for PlaintextGuard {
    fn drop(&mut self) {
        self.data.zeroize(); // Auto-destruction apres utilisation
    }
}

impl KeyEncryptionKey {
    pub fn new(mut key: [u8; 32]) -> Self {
        lock_memory(key.as_ptr(), key.len());

        #[cfg(windows)]
        unsafe {
            // Chiffrement in-process via l'API DPAPI du noyau pour prevenir les dumps memoire a froid
            CryptProtectMemory(
                key.as_mut_ptr() as *mut std::ffi::c_void,
                key.len() as u32,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            );
        }

        Self(key)
    }

    pub fn unseal(&self) -> Result<PlaintextGuard, String> {
        let mut guard = PlaintextGuard { data: self.0 };

        #[cfg(windows)]
        unsafe {
            let result = CryptUnprotectMemory(
                guard.data.as_mut_ptr() as *mut std::ffi::c_void,
                guard.data.len() as u32,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            );

            if result == 0 {
                guard.data.zeroize();
                return Err("Erreur critique: Windows a refusé de desceller la clé en RAM.".into());
            }
        }

        Ok(guard)
    }
}

impl Drop for KeyEncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize(); // Zerote le blob chiffre quand on verrouille le coffre
        unlock_memory(self.0.as_ptr(), self.0.len());
    }
}

pub struct DataEncryptionKey([u8; 32]);

impl DataEncryptionKey {
    pub fn new(key: [u8; 32]) -> Self {
        lock_memory(key.as_ptr(), key.len());
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for DataEncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
        unlock_memory(self.0.as_ptr(), self.0.len());
    }
}
