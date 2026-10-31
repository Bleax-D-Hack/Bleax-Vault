use std::ffi::c_void;

#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

pub fn lock_memory(ptr: *const u8, len: usize) {
    if len == 0 { return; }
    
    #[cfg(windows)]
    unsafe {
        VirtualLock(ptr as *const c_void, len);
    }
}

pub fn unlock_memory(ptr: *const u8, len: usize) {
    if len == 0 { return; }
    
    #[cfg(windows)]
    unsafe {
        VirtualUnlock(ptr as *const c_void, len);
    }
}