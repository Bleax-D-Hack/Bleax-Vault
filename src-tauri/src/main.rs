#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod crypto;
mod engine;
mod models;
mod os_memory;
mod state;
mod vault;

use state::AppState;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;
use tauri::{Emitter, Manager};

static SESSION_PTR: AtomicPtr<Mutex<Option<state::VaultSession>>> =
    AtomicPtr::new(std::ptr::null_mut());

// Communication avec Librewolf
fn run_native_messaging_bridge() {
    use std::io::{Read, Write};
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut len_bytes = [0u8; 4];
    if stdin.read_exact(&mut len_bytes).is_err() {
        std::process::exit(1);
    }
    let len = u32::from_ne_bytes(len_bytes) as usize;
    if len > 1024 * 1024 {
        std::process::exit(1);
    }
    let mut msg_buf = vec![0u8; len];
    if stdin.read_exact(&mut msg_buf).is_err() {
        std::process::exit(1);
    }

    #[cfg(windows)]
    unsafe {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, ReadFile, WriteFile};

        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const OPEN_EXISTING: u32 = 3;

        let pipe_name: Vec<u16> = OsStr::new(r"\\.\pipe\bleax_vault_ipc")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let h_pipe = CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        );

        if h_pipe == INVALID_HANDLE_VALUE {
            let err_msg = r#"{"status":"closed"}"#;
            let err_len = (err_msg.len() as u32).to_ne_bytes();
            stdout.write_all(&err_len).unwrap();
            stdout.write_all(err_msg.as_bytes()).unwrap();
            stdout.flush().unwrap();
            std::process::exit(0);
        }
        let mut bytes_written = 0;
        WriteFile(
            h_pipe,
            msg_buf.as_ptr() as _,
            msg_buf.len() as u32,
            &mut bytes_written,
            std::ptr::null_mut(),
        );
        let mut out_buf = [0u8; 4096];
        let mut bytes_read = 0;
        ReadFile(
            h_pipe,
            out_buf.as_mut_ptr() as _,
            out_buf.len() as u32,
            &mut bytes_read,
            std::ptr::null_mut(),
        );
        CloseHandle(h_pipe);
        if bytes_read > 0 {
            let response_len = bytes_read.to_ne_bytes();
            stdout.write_all(&response_len).unwrap();
            stdout.write_all(&out_buf[..bytes_read as usize]).unwrap();
            stdout.flush().unwrap();
        }
    }
    std::process::exit(0);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let is_browser_call = args
        .iter()
        .any(|arg| arg == "bleax@vault.com" || arg.starts_with("chrome-extension://"));

    if is_browser_call {
        run_native_messaging_bridge(); // Devient un processus invisible et s'arrete
        return;
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new())
        .setup(|app| {
            commands::start_ipc_server(app.handle().clone());

            let app_handle = app.handle().clone();
            let state = app_handle.state::<AppState>();

            // 1. Sauvegarde du pointeur de session pour acces depuis le WNDPROC
            SESSION_PTR.store(&state.session as *const _ as *mut _, Ordering::SeqCst);

            // 2. Le Watchdog standard (Activite Utilisateur)
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let state = app_handle.state::<AppState>();

                let should_lock = {
                    let session = state.session.lock().unwrap();
                    if session.is_some() {
                        let last = state.last_activity.lock().unwrap();
                        last.elapsed().as_secs() > 120
                    } else {
                        false
                    }
                };

                if should_lock {
                    let mut session = state.session.lock().unwrap();
                    if session.is_some() {
                        *session = None;
                        let _ = app_handle.emit("vault-locked", ());
                    }
                }
            });

            // 3. Hook système (S3/S4)
            #[cfg(windows)]
            std::thread::spawn(|| {
                unsafe {
                    use std::ffi::OsStr;
                    use std::os::windows::ffi::OsStrExt;
                    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
                    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
                    use windows_sys::Win32::UI::WindowsAndMessaging::{
                        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW,
                        RegisterClassW, TranslateMessage, MSG, WNDCLASSW,
                    };

                    unsafe extern "system" fn power_wnd_proc(
                        hwnd: HWND,
                        msg: u32,
                        wparam: WPARAM,
                        lparam: LPARAM,
                    ) -> LRESULT {
                        const WM_POWERBROADCAST: u32 = 0x021B;
                        const PBT_APMSUSPEND: usize = 0x0004;

                        // Interception de l'IRP de suspension (Mise en veille/Hibernation)
                        // Objectif : Purger la RAM chiffrée avant que l'OS n'écrive le fichier hiberfil.sys
                        if msg == WM_POWERBROADCAST && wparam == PBT_APMSUSPEND {
                            let ptr = SESSION_PTR.load(Ordering::SeqCst);
                            if !ptr.is_null() {
                                let mutex = &*ptr;
                                if let Ok(mut session) = mutex.lock() {
                                    *session = None;
                                }
                            }
                        }
                        DefWindowProcW(hwnd, msg, wparam, lparam)
                    }

                    let class_name: Vec<u16> =
                        OsStr::new("BleaxPowerHook\0").encode_wide().collect();
                    let mut wc: WNDCLASSW = std::mem::zeroed();
                    wc.lpfnWndProc = Some(power_wnd_proc);
                    wc.hInstance = GetModuleHandleW(std::ptr::null_mut());
                    wc.lpszClassName = class_name.as_ptr();
                    RegisterClassW(&wc);

                    // Creation d'une fenetre fantome (Message-Only) invisible
                    let _hwnd = CreateWindowExW(
                        0,
                        class_name.as_ptr(),
                        std::ptr::null_mut(),
                        0,
                        0,
                        0,
                        0,
                        0,
                        -3isize as HWND,
                        0,
                        wc.hInstance,
                        std::ptr::null_mut(),
                    );

                    let mut msg: MSG = std::mem::zeroed();
                    while GetMessageW(&mut msg, 0, 0, 0) > 0 {
                        TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            });

            #[cfg(windows)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    if let Ok(hwnd) = window.hwnd() {
                        let hwnd_isize = hwnd.0 as isize;
                        commands::TAURI_HWND.store(hwnd_isize, Ordering::SeqCst);
                        unsafe {
                            windows_sys::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity(
                                hwnd_isize, 0x00000011,
                            );
                        }
                    }
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::unlock_vault,
            commands::lock_vault,
            commands::create_vault,
            commands::recover_usb_key,
            commands::secure_copy_secret,
            commands::add_login,
            commands::add_note,
            commands::update_metadata,
            commands::update_secret,
            commands::delete_entry,
            commands::show_secret,
            commands::ping_activity,
            commands::get_browser_profiles,
            commands::install_browser_hook,
            commands::uninstall_browser_hook,
            commands::generate_and_save_secret
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
