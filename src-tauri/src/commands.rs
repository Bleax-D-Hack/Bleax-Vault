use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::{
    atomic::{AtomicBool, AtomicIsize, AtomicU8, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;
use zeroize::Zeroize;

use rusttype::{point, Font, Scale};
use std::cell::{Cell, RefCell};

use std::path::PathBuf;
#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, PublicKey};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    AllocConsole, FlushConsoleInputBuffer, FreeConsole, GetConsoleMode, GetConsoleWindow,
    GetStdHandle, ReadConsoleW, SetConsoleMode, WriteConsoleInputW, WriteConsoleW,
    ENABLE_ECHO_INPUT, INPUT_RECORD, KEY_EVENT, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, EnableMenuItem,
    GetForegroundWindow, GetMessageW, GetSystemMenu, GetWindowRect, LoadCursorW, PostQuitMessage,
    RegisterClassW, SetForegroundWindow, SetTimer, SetWindowDisplayAffinity, SetWindowLongPtrW,
    SetWindowPos, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT,
    GWLP_HWNDPARENT, HWND_TOP, MF_BYCOMMAND, MF_GRAYED, MSG, SC_CLOSE, SWP_NOMOVE, SWP_NOSIZE,
    SWP_SHOWWINDOW, WM_CREATE, WM_DESTROY, WM_KEYDOWN, WM_PAINT, WM_TIMER, WNDCLASSW, WS_CAPTION,
    WS_OVERLAPPED, WS_SYSMENU, WS_VISIBLE,
};

use crate::crypto::{MasterPassword, UsbKey};
use crate::models::{EntryContent, SecretString, VaultEntry, VaultPayload, VaultPayloadMasked};
use crate::state::{AppState, VaultSession};
use crate::vault::decrypt_vault;

use serde::{Deserialize, Serialize};
use tauri::Manager;

#[cfg(windows)]
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, EndPaint, SetDIBitsToDevice, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
    PAINTSTRUCT,
};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};

#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};

#[cfg(windows)]
const WDA_EXCLUDEFROMCAPTURE: u32 = 0x00000011;

pub static TAURI_HWND: AtomicIsize = AtomicIsize::new(0);

static CONSOLE_ACTIVE: AtomicBool = AtomicBool::new(false);

struct ConsoleGuard;

impl ConsoleGuard {
    fn acquire() -> Result<Self, String> {
        if CONSOLE_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Ok(Self)
        } else {
            Err("Une action sécurisée est déjà en cours d'exécution.".into())
        }
    }
}

impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        CONSOLE_ACTIVE.store(false, Ordering::SeqCst);
    }
}

thread_local! {
    static PIXEL_BUFFER: RefCell<Vec<u32>> = RefCell::new(Vec::new());
    static GHOST_TIMEOUT: Cell<u32> = Cell::new(10000);
}

#[cfg(windows)]
fn render_styled_text_to_pixels(lines: &[(&str, u32)], width: usize, height: usize) -> Vec<u32> {
    let font_data = std::fs::read("C:\\Windows\\Fonts\\consola.ttf").expect("Police introuvable");
    let font = Font::try_from_vec(font_data).expect("Erreur de police");

    let mut pixels = vec![0x00_0F_0F_0F; width * height];
    let scale = Scale::uniform(17.0);
    let v_metrics = font.v_metrics(scale);
    let line_height = v_metrics.ascent - v_metrics.descent + 4.0;

    let mut current_y = 15.0;
    let start_x = 10.0;

    for &(text, color) in lines {
        let offset = point(start_x, current_y + v_metrics.ascent);
        let r_base = ((color >> 16) & 0xFF) as f32;
        let g_base = ((color >> 8) & 0xFF) as f32;
        let b_base = (color & 0xFF) as f32;

        for glyph in font.layout(text, scale, offset) {
            if let Some(bounding_box) = glyph.pixel_bounding_box() {
                glyph.draw(|x, y, v| {
                    let px = x as i32 + bounding_box.min.x;
                    let py = y as i32 + bounding_box.min.y;

                    if px >= 0 && px < width as i32 && py >= 0 && py < height as i32 {
                        if v > 0.05 {
                            let r = (r_base * v) as u32;
                            let g = (g_base * v) as u32;
                            let b = (b_base * v) as u32;
                            let argb = (r << 16) | (g << 8) | b;
                            pixels[(py * width as i32 + px) as usize] = argb;
                        }
                    }
                });
            }
        }
        current_y += line_height;
    }
    pixels
}

#[cfg(windows)]
extern "system" fn ghost_wndproc(
    window: isize,
    message: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    unsafe {
        match message {
            WM_CREATE => {
                SetWindowDisplayAffinity(window, WDA_EXCLUDEFROMCAPTURE);
                let timeout = GHOST_TIMEOUT.with(|t| t.get());
                SetTimer(window, 1, timeout, None);
                0
            }
            WM_KEYDOWN => {
                let key_code = wparam as u16;
                if key_code == 0x0D || key_code == 0x1B {
                    DestroyWindow(window);
                }
                0
            }
            WM_TIMER => {
                DestroyWindow(window);
                0
            }
            WM_PAINT => {
                let mut ps: PAINTSTRUCT = std::mem::zeroed();
                let hdc = BeginPaint(window, &mut ps);

                PIXEL_BUFFER.with(|buf| {
                    let pixels = buf.borrow();
                    if !pixels.is_empty() {
                        let width = 850;
                        // Alignement de la hauteur sur le buffer bitmap pour éviter l'out-of-bounds
                        let height = (pixels.len() / width as usize) as u32;

                        let mut bmi: BITMAPINFO = std::mem::zeroed();
                        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
                        bmi.bmiHeader.biWidth = width as i32;
                        bmi.bmiHeader.biHeight = -(height as i32);
                        bmi.bmiHeader.biPlanes = 1;
                        bmi.bmiHeader.biBitCount = 32;
                        bmi.bmiHeader.biCompression = BI_RGB as u32;

                        SetDIBitsToDevice(
                            hdc,
                            0,
                            0,
                            width as u32,
                            height,
                            0,
                            0,
                            0,
                            height,
                            pixels.as_ptr() as *const _,
                            &bmi,
                            DIB_RGB_COLORS,
                        );
                    }
                });

                EndPaint(window, &ps);
                0
            }
            WM_DESTROY => {
                PIXEL_BUFFER.with(|buf| {
                    buf.borrow_mut().zeroize(); // Destruction des pixels en mémoire
                });
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(window, message, wparam, lparam),
        }
    }
}

#[cfg(windows)]
fn run_ghost_window(image_pixels: Vec<u32>, timeout_secs: u32) -> Result<(), String> {
    let _guard = ConsoleGuard::acquire()?;

    let width = 850;

    let height = (image_pixels.len() / width as usize) as i32;

    PIXEL_BUFFER.with(|buf| {
        *buf.borrow_mut() = image_pixels;
    });

    GHOST_TIMEOUT.with(|t| {
        t.set(timeout_secs * 1000);
    });

    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class_name: Vec<u16> = OsStr::new("GhostWindowClass")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.hCursor = LoadCursorW(0, 32512 as *const u16); // 32512 = IDC_ARROW
        wc.hInstance = instance;
        wc.lpszClassName = class_name.as_ptr();
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = Some(ghost_wndproc);

        RegisterClassW(&wc);

        let mut tauri_hwnd = TAURI_HWND.load(Ordering::SeqCst);
        if tauri_hwnd == 0 {
            tauri_hwnd = GetForegroundWindow() as isize;
        }

        let exe_path = std::env::current_exe().unwrap_or_default();
        let title_wide: Vec<u16> = OsStr::new(exe_path.to_string_lossy().as_ref())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title_wide.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            width as i32,
            height,
            tauri_hwnd,
            0,
            instance,
            std::ptr::null(),
        );

        if hwnd != 0 {
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&mut message, 0, 0, 0) > 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    Ok(())
}

// HACK Z-ORDER : DESTRUCTION SÉCURISÉE (Bouclier TopMost)
#[cfg(windows)]
unsafe fn safe_console_teardown(tauri_hwnd: isize) {
    let c_hwnd = GetConsoleWindow();
    if tauri_hwnd != 0 {
        SetWindowPos(tauri_hwnd, -1 as isize, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

        if c_hwnd != 0 {
            ShowWindow(c_hwnd, 0);
        }
        FreeConsole();

        SetForegroundWindow(tauri_hwnd);

        SetWindowPos(tauri_hwnd, -2 as isize, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    } else {
        FreeConsole();
    }
}

#[cfg(windows)]
fn secure_prompt(message: &str, timeout_secs: Option<u64>) -> Result<String, String> {
    let _guard = ConsoleGuard::acquire()?;

    let pwd;
    let process_state = Arc::new(AtomicU8::new(0)); // 0 = En cours, 1 = Succès, 2 = Timeout

    unsafe {
        let mut tauri_hwnd = TAURI_HWND.load(Ordering::SeqCst);
        if tauri_hwnd == 0 {
            tauri_hwnd = GetForegroundWindow() as isize;
        }

        AllocConsole();
        let console_hwnd = GetConsoleWindow();

        if console_hwnd != 0 {
            let hmenu = GetSystemMenu(console_hwnd, 0);
            if hmenu != 0 {
                EnableMenuItem(hmenu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
            }

            SetWindowDisplayAffinity(console_hwnd, WDA_EXCLUDEFROMCAPTURE);

            if tauri_hwnd != 0 {
                SetWindowLongPtrW(console_hwnd, GWLP_HWNDPARENT, tauri_hwnd);
                let mut rect = std::mem::zeroed();
                GetWindowRect(tauri_hwnd as isize, &mut rect);
                let x = rect.left + ((rect.right - rect.left) - 600) / 2;
                let y = rect.top + ((rect.bottom - rect.top) - 300) / 2;
                SetWindowPos(
                    console_hwnd,
                    HWND_TOP,
                    x,
                    y,
                    0,
                    0,
                    SWP_NOSIZE | SWP_SHOWWINDOW,
                );
            } else {
                SetWindowPos(
                    console_hwnd,
                    HWND_TOP,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
                );
            }
        }

        let handle_out = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut msg_w = Vec::with_capacity(message.len() + 10);
        msg_w.extend(OsStr::new(message).encode_wide());
        WriteConsoleW(
            handle_out,
            msg_w.as_ptr() as *const std::ffi::c_void,
            msg_w.len() as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        msg_w.zeroize();

        let handle_in = GetStdHandle(STD_INPUT_HANDLE);
        let handle_in_usize = handle_in as usize;

        FlushConsoleInputBuffer(handle_in);

        if let Some(secs) = timeout_secs {
            let state_clone = Arc::clone(&process_state);
            thread::spawn(move || {
                let mut elapsed = 0;
                while elapsed < secs && state_clone.load(Ordering::SeqCst) == 0 {
                    thread::sleep(Duration::from_secs(1));
                    elapsed += 1;
                }
                if state_clone
                    .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    let mut record: INPUT_RECORD = std::mem::zeroed();
                    record.EventType = KEY_EVENT as u16;
                    record.Event.KeyEvent.bKeyDown = 1;
                    record.Event.KeyEvent.wRepeatCount = 1;
                    record.Event.KeyEvent.wVirtualKeyCode = 0x0D;
                    record.Event.KeyEvent.uChar.UnicodeChar = 0x0D;
                    let mut written = 0;
                    WriteConsoleInputW(handle_in_usize as HANDLE, &record, 1, &mut written);
                }
            });
        }

        let mut mode = 0;
        GetConsoleMode(handle_in, &mut mode);
        SetConsoleMode(handle_in, mode & !ENABLE_ECHO_INPUT);

        let mut buf = vec![0u16; 512];
        let mut read_chars = 0;
        ReadConsoleW(
            handle_in,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len() as u32,
            &mut read_chars,
            ptr::null_mut(),
        );
        SetConsoleMode(handle_in, mode);

        let is_timeout = process_state
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err();
        FlushConsoleInputBuffer(handle_in);

        // Appel de la destruction sous bouclier anti-Windows
        safe_console_teardown(tauri_hwnd as isize);

        if is_timeout {
            buf.zeroize();
            return Err("Temps d'attente dépassé (Fermeture de sécurité).".into());
        }

        let mut len = read_chars as usize;
        while len > 0 && (buf[len - 1] == 10 || buf[len - 1] == 13) {
            len -= 1;
        }

        pwd = String::from_utf16(&buf[..len]).unwrap_or_default();
        buf.zeroize();
    }
    Ok(pwd)
}

fn load_payload(session: &VaultSession) -> Result<VaultPayload, String> {
    let vault_bytes = fs::read(&session.vault_path).map_err(|e| e.to_string())?;
    let mut decrypted_bytes = decrypt_vault(&session.kek, &vault_bytes)
        .map_err(|_| "Déchiffrement échoué.".to_string())?;
    let payload: VaultPayload =
        serde_json::from_slice(&decrypted_bytes).map_err(|_| "Erreur JSON".to_string())?;
    decrypted_bytes.zeroize();
    Ok(payload)
}

fn commit_to_disk(session: &VaultSession, payload: &mut VaultPayload) -> Result<(), String> {
    if payload.vault_updated_at > 0 {
        if let Ok(metadata) = fs::metadata(&session.vault_path) {
            if let Ok(m_time) = metadata.modified() {
                if let Ok(disk_ts) = m_time.duration_since(UNIX_EPOCH) {
                    if (disk_ts.as_secs() as i64) > payload.vault_updated_at + 2 {
                        return Err("Conflit Cloud.".into());
                    }
                }
            }
        }
    }
    if let Ok(time) = SystemTime::now().duration_since(UNIX_EPOCH) {
        payload.vault_updated_at = time.as_secs() as i64;
    }

    let vault_binary = crate::engine::pack_and_encrypt(&session.kek, &session.argon_salt, payload)
        .map_err(|e| format!("{:?}", e))?;
    let tmp_path = format!("{}.tmp", session.vault_path);

    fs::write(&tmp_path, &vault_binary).map_err(|e| e.to_string())?;
    fs::rename(&tmp_path, &session.vault_path).map_err(|e| e.to_string())?;
    Ok(())
}

// CYCLE DE VIE ET COMMANDES CRUD (100% ASYNCHRONE)

#[tauri::command]
pub async fn create_vault(vault_path: String, usb_key_path: String) -> Result<(), String> {
    if Path::new(&vault_path).exists() {
        return Err("Le coffre existe déjà.".into());
    }

    let mut pwd1 = secure_prompt(
        "\nNouveau mot de passe maitre (12 car. min, laissez vide pour annuler) : ",
        None,
    )?;
    if pwd1.is_empty() {
        pwd1.zeroize();
        return Err("Création annulée.".into());
    }

    let mut pwd2 = secure_prompt("\nConfirmez le mot de passe : ", None)?;

    if pwd1 != pwd2 {
        pwd1.zeroize();
        pwd2.zeroize();
        return Err("Les mots de passe ne correspondent pas.".into());
    }
    if pwd1.len() < 12 {
        pwd1.zeroize();
        pwd2.zeroize();
        return Err("Le mot de passe doit faire au moins 12 caractères.".into());
    }

    let password = MasterPassword::new(pwd1.clone());
    pwd1.zeroize();
    pwd2.zeroize();

    let usb_key = crate::engine::generate_usb_key();
    let argon_salt = crate::engine::generate_argon_salt();
    let mut pwd_hash = crate::engine::derive_password(&password, &argon_salt)
        .map_err(|_| "Erreur Argon".to_string())?;
    let kek =
        crate::engine::generate_kek(&pwd_hash, &usb_key).map_err(|_| "Erreur HKDF".to_string())?;
    pwd_hash.zeroize();

    let payload = VaultPayload::new();
    let vault_binary = crate::engine::pack_and_encrypt(&kek, &argon_salt, &payload)
        .map_err(|e| format!("{:?}", e))?;

    let mut sealed_usb = hardware_seal(usb_key.as_bytes())?;
    fs::write(&usb_key_path, &sealed_usb).map_err(|e| e.to_string())?;
    sealed_usb.zeroize();

    fs::write(&vault_path, vault_binary).map_err(|e| e.to_string())?;

    let mut phrase = crate::engine::generate_recovery_phrase(&usb_key)
        .map_err(|_| "Erreur phrase".to_string())?;

    // DECOUPAGE EN 4 LIGNES (OPSEC ZERO-LEAK)
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 24 {
        phrase.zeroize();
        return Err("Erreur de génération de la phrase.".into());
    }

    // Pre-allocation stricte pour éviter le memory slack lors du formatage
    let mut line1 = zeroize::Zeroizing::new(String::with_capacity(80));
    let mut line2 = zeroize::Zeroizing::new(String::with_capacity(80));
    let mut line3 = zeroize::Zeroizing::new(String::with_capacity(80));
    let mut line4 = zeroize::Zeroizing::new(String::with_capacity(80));

    // Remplissage 6 mots par ligne
    line1.push_str("  ");
    for w in &words[0..6] {
        line1.push_str(w);
        line1.push(' ');
    }

    line2.push_str("  ");
    for w in &words[6..12] {
        line2.push_str(w);
        line2.push(' ');
    }

    line3.push_str("  ");
    for w in &words[12..18] {
        line3.push_str(w);
        line3.push(' ');
    }

    line4.push_str("  ");
    for w in &words[18..24] {
        line4.push_str(w);
        line4.push(' ');
    }

    let color_gray = 0x00_CC_CC_CC;
    let color_red = 0x00_FF_55_55;
    let separator = "=================================================================";

    let lines = vec![
        (separator, color_gray),
        ("  TRES IMPORTANT : KIT DE SECOURS (24 MOTS)", color_red),
        (separator, color_gray),
        ("", color_gray),
        (
            "  Ecrivez ces 24 mots sur un papier et cachez-le.",
            color_gray,
        ),
        (
            "  Ne les sauvegardez JAMAIS sur votre ordinateur.",
            color_gray,
        ),
        ("", color_gray),
        ("  MOTS :", color_gray),
        ("", color_gray),
        (line1.as_str(), color_red), // Ligne 1 (mots 1-6)
        (line2.as_str(), color_red), // Ligne 2 (mots 7-12)
        (line3.as_str(), color_red), // Ligne 3 (mots 13-18)
        (line4.as_str(), color_red), // Ligne 4 (mots 19-24)
        ("", color_gray),
        (separator, color_gray),
        (
            "  Appuyez sur ENTREE une fois les mots copiees...",
            color_gray,
        ),
    ];

    let image_pixels = render_styled_text_to_pixels(&lines, 850, 450);

    drop(line1);
    drop(line2);
    drop(line3);
    drop(line4);
    phrase.zeroize();

    run_ghost_window(image_pixels, 300)?;

    Ok(())
}

#[tauri::command]
pub async fn unlock_vault(
    vault_path: String,
    usb_key_path: String,
    state: State<'_, AppState>,
) -> Result<VaultPayloadMasked, String> {
    let vault_bytes = fs::read(&vault_path).map_err(|e| e.to_string())?;
    let mut usb_bytes = fs::read(&usb_key_path).map_err(|e| e.to_string())?;

    // On demande a la carte mere / OS de dechiffrer le blob.
    // Si le fichier a été copie sur un autre PC, cela va renvoyer une erreur ici !
    let mut unsealed_bytes = hardware_unseal(&usb_bytes)?;
    usb_bytes.zeroize(); // Destruction immediate du blob chiffre en RAM

    if unsealed_bytes.len() != 32 {
        unsealed_bytes.zeroize();
        return Err("Clé USB corrompue ou taille invalide.".into());
    }

    let mut safe_usb_bytes = [0u8; 32];
    safe_usb_bytes.copy_from_slice(&unsealed_bytes[0..32]);
    unsealed_bytes.zeroize(); // Destruction du buffer temporaire descelle

    let mut pwd_str = secure_prompt(
        "\nTapez votre mot de passe maitre (laissez vide pour annuler) : ",
        Some(60),
    )?;
    if pwd_str.is_empty() {
        pwd_str.zeroize();
        return Err("Annulé.".into());
    }

    let password = MasterPassword::new(pwd_str.clone());
    pwd_str.zeroize();

    let usb_key = UsbKey::new(safe_usb_bytes);
    safe_usb_bytes.zeroize();

    if vault_bytes.len() < 21 {
        return Err("Fichier corrompu".into());
    }
    let mut argon_salt = [0u8; 16];
    argon_salt.copy_from_slice(&vault_bytes[5..21]);

    let mut pwd_hash = crate::engine::derive_password(&password, &argon_salt)
        .map_err(|_| "Erreur Argon".to_string())?;
    let kek =
        crate::engine::generate_kek(&pwd_hash, &usb_key).map_err(|_| "Erreur HKDF".to_string())?;
    pwd_hash.zeroize();

    let mut decrypted_bytes =
        decrypt_vault(&kek, &vault_bytes).map_err(|_| "Mot de passe incorrect.".to_string())?;
    let payload: VaultPayload =
        serde_json::from_slice(&decrypted_bytes).map_err(|_| "JSON Invalide".to_string())?;
    decrypted_bytes.zeroize();

    let masked = payload.to_masked();
    let mut session_guard = state.session.lock().unwrap();
    *session_guard = Some(VaultSession {
        kek,
        argon_salt,
        vault_path,
    });

    let mut last = state.last_activity.lock().unwrap();
    *last = std::time::Instant::now();

    Ok(masked)
}

#[tauri::command]
pub async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    *state.session.lock().unwrap() = None;
    Ok(())
}

#[tauri::command]
pub async fn recover_usb_key(usb_key_path: String) -> Result<(), String> {
    if Path::new(&usb_key_path).exists() {
        return Err("Un fichier existe déjà à cet emplacement.".into());
    }

    let mut recovery_phrase = secure_prompt("\n=======================================================\n RESTAURATION (AIR-GAP)\n=======================================================\n Collez vos 24 mots (Texte masque, vide pour annuler) :\n > ", None)?;
    if recovery_phrase.is_empty() {
        recovery_phrase.zeroize();
        return Err("Annulé.".into());
    }

    let mut clean_phrase = String::with_capacity(256);
    let mut space_last = false;

    for c in recovery_phrase.trim().chars() {
        if c.is_whitespace() {
            if !space_last {
                clean_phrase.push(' ');
                space_last = true;
            }
        } else {
            for lc in c.to_lowercase() {
                clean_phrase.push(lc);
            }
            space_last = false;
        }
    }
    recovery_phrase.zeroize();

    if clean_phrase.split(' ').count() != 24 {
        clean_phrase.zeroize();
        return Err("La phrase doit contenir exactement 24 mots.".into());
    }

    let usb_key_result = crate::engine::recover_usb_key_from_phrase(&clean_phrase);
    clean_phrase.zeroize();

    let usb_key = usb_key_result?;

    // Scellement de la cle restaurée avec la carte mere du NOUVEL ordinateur
    #[cfg(windows)]
    {
        let mut sealed_usb = hardware_seal(usb_key.as_bytes())?;
        fs::write(&usb_key_path, &sealed_usb).map_err(|e| e.to_string())?;
        sealed_usb.zeroize();
    }

    // Fallback de sécurité si un jour portage sur Linux/Mac
    #[cfg(not(windows))]
    {
        fs::write(&usb_key_path, usb_key.as_bytes()).map_err(|e| e.to_string())?;
    }

    Ok(())
}

#[tauri::command]
pub async fn add_login(
    _vault_path: String,
    id: String,
    title: String,
    username: String,
    url: String,
    state: State<'_, AppState>,
) -> Result<VaultPayloadMasked, String> {
    let session_guard = state.session.lock().unwrap();
    let session = session_guard.as_ref().ok_or("Verrouillé")?;
    let mut payload = load_payload(session)?;

    payload.entries.push(VaultEntry {
        id,
        last_modified: 0,
        title,
        content: EntryContent::Login {
            username,
            password: SecretString::default(),
            url: if url.is_empty() { None } else { Some(url) },
            totp_secret: None,
        },
    });

    commit_to_disk(session, &mut payload)?;
    Ok(payload.to_masked())
}

#[tauri::command]
pub async fn add_note(
    _vault_path: String,
    id: String,
    title: String,
    state: State<'_, AppState>,
) -> Result<VaultPayloadMasked, String> {
    let session_guard = state.session.lock().unwrap();
    let session = session_guard.as_ref().ok_or("Verrouillé")?;
    let mut payload = load_payload(session)?;

    payload.entries.push(VaultEntry {
        id,
        last_modified: 0,
        title,
        content: EntryContent::SecureNote {
            text: SecretString::default(),
        },
    });
    commit_to_disk(session, &mut payload)?;
    Ok(payload.to_masked())
}

#[tauri::command]
pub async fn update_metadata(
    _vault_path: String,
    id: String,
    title: String,
    username: String,
    url: String,
    state: State<'_, AppState>,
) -> Result<VaultPayloadMasked, String> {
    let session_guard = state.session.lock().unwrap();
    let session = session_guard.as_ref().ok_or("Verrouillé")?;
    let mut payload = load_payload(session)?;

    let entry = payload
        .entries
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or("Introuvable")?;
    entry.title = title;
    if let EntryContent::Login {
        username: ref mut u,
        url: ref mut l,
        ..
    } = entry.content
    {
        *u = username;
        *l = if url.is_empty() { None } else { Some(url) };
    }

    commit_to_disk(session, &mut payload)?;
    Ok(payload.to_masked())
}

#[tauri::command]
pub async fn update_secret(
    _vault_path: String,
    id: String,
    state: State<'_, AppState>,
) -> Result<VaultPayloadMasked, String> {
    let mut pwd_str = secure_prompt("\nNouveau secret (laissez vide pour annuler) : ", None)?;
    if pwd_str.is_empty() {
        pwd_str.zeroize();
        return Err("Annulé.".into());
    }

    let pwd = SecretString(pwd_str);

    let session_guard = state.session.lock().unwrap();
    let session = session_guard.as_ref().ok_or("Verrouillé")?;
    let mut payload = load_payload(session)?;

    let entry = payload
        .entries
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or("Introuvable")?;
    match &mut entry.content {
        EntryContent::Login { password, .. } => *password = pwd,
        EntryContent::SecureNote { text } => *text = pwd,
    }

    commit_to_disk(session, &mut payload)?;
    Ok(payload.to_masked())
}

#[tauri::command]
pub async fn delete_entry(
    _vault_path: String,
    id: String,
    state: State<'_, AppState>,
) -> Result<VaultPayloadMasked, String> {
    let session_guard = state.session.lock().unwrap();
    let session = session_guard.as_ref().ok_or("Verrouillé")?;
    let mut payload = load_payload(session)?;

    payload.entries.retain(|e| e.id != id);
    commit_to_disk(session, &mut payload)?;
    Ok(payload.to_masked())
}

#[tauri::command]
pub async fn show_secret(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut secret_clone = {
        let session_guard = state.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or("Coffre verrouillé")?;
        let payload = load_payload(session)?;
        let entry = payload
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or("Introuvable")?;
        match &entry.content {
            EntryContent::Login { password, .. } => password.0.clone(),
            EntryContent::SecureNote { text } => text.0.clone(),
        }
    };

    if secret_clone.is_empty() {
        secret_clone.zeroize();
        return Err("Le secret est vide.".into());
    }

    let mut secret_line = String::with_capacity(secret_clone.len() + 10);
    secret_line.push_str(" SECRET : ");
    secret_line.push_str(&secret_clone);

    let color_gray = 0x00_CC_CC_CC;
    let color_yellow = 0x00_FF_D7_00;
    let separator = "=================================================================";

    let lines = vec![
        (separator, color_gray),
        (" LECTURE SECURISEE (ISOLEMENT ACTIF)", color_yellow),
        (separator, color_gray),
        ("", color_gray),
        (secret_line.as_str(), color_gray),
        ("", color_gray),
        (separator, color_gray),
        (" Appuyez sur ENTREE pour fermer ce terminal...", color_gray),
    ];

    let image_pixels = render_styled_text_to_pixels(&lines, 850, 350);

    secret_line.zeroize();
    secret_clone.zeroize();

    run_ghost_window(image_pixels, 10)?;

    Ok(())
}

#[tauri::command]
pub async fn secure_copy_secret(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut secret_clone = {
        let session_guard = state.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or("Coffre verrouillé")?;
        let payload = load_payload(session)?;
        let entry = payload
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or("Introuvable")?;
        match &entry.content {
            EntryContent::Login { password, .. } => password.0.clone(),
            EntryContent::SecureNote { text } => text.0.clone(),
        }
    };

    if secret_clone.is_empty() {
        secret_clone.zeroize();
        return Err("Le secret est vide.".into());
    }

    #[cfg(windows)]
    unsafe {
        if OpenClipboard(0) == 0 {
            secret_clone.zeroize();
            return Err("Erreur Presse-papiers".into());
        }
        EmptyClipboard();

        let mut text_w: Vec<u16> = OsStr::new(&secret_clone)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let h_global_text = GlobalAlloc(GMEM_MOVEABLE, text_w.len() * 2);
        if !h_global_text.is_null() {
            let locked = GlobalLock(h_global_text) as *mut u16;
            ptr::copy_nonoverlapping(text_w.as_ptr(), locked, text_w.len());
            GlobalUnlock(h_global_text);
            SetClipboardData(13, h_global_text as HANDLE);
        }
        text_w.zeroize();

        let mut format_name: Vec<u16> = OsStr::new("ExcludeClipboardContentFromMonitorProcessing")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let exclude_format = RegisterClipboardFormatW(format_name.as_ptr());
        if exclude_format != 0 {
            let h_global_exclude = GlobalAlloc(GMEM_MOVEABLE, 1);
            if !h_global_exclude.is_null() {
                let locked = GlobalLock(h_global_exclude) as *mut u8;
                *locked = 0;
                GlobalUnlock(h_global_exclude);
                SetClipboardData(exclude_format, h_global_exclude as HANDLE);
            }
        }
        format_name.zeroize();
        CloseClipboard();
    }

    secret_clone.zeroize();

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(10));
        #[cfg(windows)]
        unsafe {
            if OpenClipboard(0) != 0 {
                EmptyClipboard();
                CloseClipboard();
            }
        }
    });

    Ok(())
}

// SECURITE ANTI-HIBERNATION

#[tauri::command]
pub fn ping_activity(state: State<'_, AppState>) {
    if state.session.lock().unwrap().is_some() {
        let mut last = state.last_activity.lock().unwrap();
        *last = std::time::Instant::now(); // Reinitialise l'horloge de Rust
    }
}

// IPC NATIVE MESSAGING : SERVEUR NAMED PIPE "NSA-GRADE" (ZERO-ALLOCATION)

#[derive(Deserialize)]
struct IpcRequest {
    action: String,
    url: Option<String>,
    id: Option<String>,

    client_pubkey: Option<String>,
}

#[derive(Serialize)]
struct AccountInfo<'a> {
    id: &'a str,
    username: &'a str,
}

#[derive(Serialize)]
struct IpcResponse<'a> {
    status: &'a str,
    accounts: Option<Vec<AccountInfo<'a>>>,

    server_pubkey: Option<String>, // Notre clé publique éphémère
    nonce: Option<String>,         // Le vecteur d'initialisation AES
    ciphertext: Option<String>,    // Le payload chiffré (username + password)
}

fn extract_domain(url: &str) -> String {
    let mut s = url.trim();
    if s.starts_with("https://") {
        s = &s[8..];
    } else if s.starts_with("http://") {
        s = &s[7..];
    }
    if s.starts_with("www.") {
        s = &s[4..];
    }
    if let Some(idx) = s.find('/') {
        s = &s[..idx];
    }
    s.to_lowercase()
}

#[cfg(windows)]
unsafe fn process_and_respond(app_handle: &tauri::AppHandle, req_bytes: &[u8], h_pipe: HANDLE) {
    let req: IpcRequest = match serde_json::from_slice(req_bytes) {
        Ok(r) => r,
        Err(_) => {
            send_ipc_json(
                h_pipe,
                IpcResponse {
                    status: "error",
                    accounts: None,
                    server_pubkey: None,
                    nonce: None,
                    ciphertext: None,
                },
            );
            return;
        }
    };

    let state = app_handle.state::<AppState>();
    let session_guard = state.session.lock().unwrap();

    if let Some(session) = session_guard.as_ref() {
        *state.last_activity.lock().unwrap() = std::time::Instant::now();

        if let Ok(payload) = load_payload(session) {
            if req.action == "get_accounts" {
                if let Some(target_url) = req.url {
                    let target_domain = extract_domain(&target_url);
                    let mut matched_accounts = Vec::new();

                    for entry in &payload.entries {
                        if let EntryContent::Login {
                            username,
                            url: Some(u),
                            ..
                        } = &entry.content
                        {
                            let stored_domain = extract_domain(u);
                            if target_domain == stored_domain
                                || target_domain.ends_with(&format!(".{}", stored_domain))
                            {
                                matched_accounts.push(AccountInfo {
                                    id: &entry.id,
                                    username,
                                });
                            }
                        }
                    }

                    if matched_accounts.is_empty() {
                        send_ipc_json(
                            h_pipe,
                            IpcResponse {
                                status: "not_found",
                                accounts: None,
                                server_pubkey: None,
                                nonce: None,
                                ciphertext: None,
                            },
                        );
                    } else {
                        send_ipc_json(
                            h_pipe,
                            IpcResponse {
                                status: "ok",
                                accounts: Some(matched_accounts),
                                server_pubkey: None,
                                nonce: None,
                                ciphertext: None,
                            },
                        );
                    }
                    return;
                }
            }

            if req.action == "get_password" {
                if let (Some(target_id), Some(client_pubkey_b64)) = (req.id, req.client_pubkey) {
                    for entry in &payload.entries {
                        if entry.id == target_id {
                            if let EntryContent::Login {
                                username, password, ..
                            } = &entry.content
                            {
                                if let Ok(client_bytes) = b64.decode(&client_pubkey_b64) {
                                    if let Ok(client_pubkey) =
                                        PublicKey::from_sec1_bytes(&client_bytes)
                                    {
                                        let secret = EphemeralSecret::random(&mut OsRng);
                                        let server_pubkey = secret.public_key();

                                        // Calcul du Secret Partage (Diffie-Hellman)
                                        let shared_secret = secret.diffie_hellman(&client_pubkey);

                                        // Derivation de la cle AES-256 (HKDF)
                                        let (_prk, hkdf) = Hkdf::<Sha256>::extract(
                                            None,
                                            shared_secret.raw_secret_bytes().as_slice(),
                                        );
                                        let mut aes_key = [0u8; 32];
                                        hkdf.expand(b"bleax-ipc-e2ee", &mut aes_key).unwrap();

                                        let cipher =
                                            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

                                        let mut nonce_bytes = [0u8; 12];
                                        OsRng.fill_bytes(&mut nonce_bytes);
                                        let nonce = Nonce::from_slice(&nonce_bytes);

                                        // Assemblage du Secret en clair (Zero-Allocation contrôlée)
                                        let mut pt_vec = Vec::with_capacity(512);
                                        pt_vec.extend_from_slice(b"{\"u\":\"");
                                        pt_vec.extend_from_slice(username.as_bytes());
                                        pt_vec.extend_from_slice(b"\",\"p\":\"");
                                        pt_vec.extend_from_slice(password.0.as_bytes());
                                        pt_vec.extend_from_slice(b"\"}");

                                        if let Ok(encrypted_payload) =
                                            cipher.encrypt(nonce, pt_vec.as_slice())
                                        {
                                            pt_vec.zeroize();
                                            aes_key.zeroize();

                                            send_ipc_json(
                                                h_pipe,
                                                IpcResponse {
                                                    status: "ok",
                                                    accounts: None,
                                                    server_pubkey: Some(
                                                        b64.encode(server_pubkey.to_sec1_bytes()),
                                                    ),
                                                    nonce: Some(b64.encode(nonce_bytes)),
                                                    ciphertext: Some(b64.encode(encrypted_payload)),
                                                },
                                            );
                                            return;
                                        }
                                        pt_vec.zeroize();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        send_ipc_json(
            h_pipe,
            IpcResponse {
                status: "error",
                accounts: None,
                server_pubkey: None,
                nonce: None,
                ciphertext: None,
            },
        );
        return;
    }

    send_ipc_json(
        h_pipe,
        IpcResponse {
            status: "locked",
            accounts: None,
            server_pubkey: None,
            nonce: None,
            ciphertext: None,
        },
    );
}

#[cfg(windows)]
unsafe fn send_ipc_json(h_pipe: HANDLE, response: IpcResponse) {
    let mut out_buffer = [0u8; 4096];

    {
        // Utilisation d'un Cursor pour ecrire le JSON octet par octet dans notre buffer
        let mut cursor = std::io::Cursor::new(&mut out_buffer[..]);
        let _ = serde_json::to_writer(&mut cursor, &response);

        let len = cursor.position() as u32;
        let mut bytes_written = 0;

        WriteFile(
            h_pipe,
            out_buffer.as_ptr() as _,
            len,
            &mut bytes_written,
            std::ptr::null_mut(),
        );
    }

    out_buffer.zeroize();
}

pub fn start_ipc_server(app_handle: tauri::AppHandle) {
    std::thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            let pipe_name: Vec<u16> = OsStr::new(r"\\.\pipe\bleax_vault_ipc")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
            const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
            const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
            const PIPE_WAIT: u32 = 0x00000000;
            const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;

            loop {
                let h_pipe = CreateNamedPipeW(
                    pipe_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    1,
                    4096,
                    4096,
                    0,
                    std::ptr::null_mut(),
                );

                if h_pipe == INVALID_HANDLE_VALUE {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }

                let connected = ConnectNamedPipe(h_pipe, std::ptr::null_mut()) != 0;
                if connected || GetLastError() == ERROR_PIPE_CONNECTED {
                    let mut in_buffer = [0u8; 4096];
                    let mut bytes_read = 0;

                    if ReadFile(
                        h_pipe,
                        in_buffer.as_mut_ptr() as _,
                        in_buffer.len() as u32,
                        &mut bytes_read,
                        std::ptr::null_mut(),
                    ) != 0
                        && bytes_read > 0
                    {
                        process_and_respond(&app_handle, &in_buffer[..bytes_read as usize], h_pipe);
                    }

                    in_buffer.zeroize();
                }
                DisconnectNamedPipe(h_pipe);
                CloseHandle(h_pipe);
            }
        }
    });
}

use std::fs::OpenOptions;
use std::io::Write;

#[derive(Serialize)]
pub struct BrowserProfile {
    name: String,
    path: String,
}

#[tauri::command]
pub fn get_browser_profiles() -> Result<Vec<BrowserProfile>, String> {
    let mut profiles = Vec::new();

    if let Some(appdata) = std::env::var_os("APPDATA") {
        let mut profiles_dir = PathBuf::from(appdata);
        profiles_dir.push(r"librewolf\Profiles");

        if let Ok(entries) = fs::read_dir(profiles_dir) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let folder_name = entry.file_name().to_string_lossy().to_string();
                        let full_path = entry.path().to_string_lossy().to_string();

                        profiles.push(BrowserProfile {
                            name: folder_name,
                            path: full_path,
                        });
                    }
                }
            }
        }
    }
    Ok(profiles)
}

#[tauri::command]
pub fn install_browser_hook(profile_path: String) -> Result<(), String> {
    let xpi_bytes = include_bytes!("../bleax-vault.xpi");
    let current_exe = std::env::current_exe().map_err(|_| "Impossible de localiser l'exe")?;
    let exe_path_str = current_exe.to_string_lossy().replace("\\", "\\\\");

    let target_profile = PathBuf::from(&profile_path);
    if !target_profile.exists() {
        return Err("Profil introuvable".into());
    }

    // Injection de l'extension dans le profil (Sideloading)
    let mut ext_dir = target_profile.clone();
    ext_dir.push("extensions");
    let _ = fs::create_dir_all(&ext_dir);
    let mut xpi_path = ext_dir.clone();
    xpi_path.push("bleax@vault.com.xpi");
    fs::write(&xpi_path, xpi_bytes).map_err(|_| "Échec de l'écriture XPI")?;

    // Desactivation des boucliers LibreWolf via user.js
    let mut user_js_path = target_profile.clone();
    user_js_path.push("user.js");
    let pref_payload = "\nuser_pref(\"xpinstall.signatures.required\", false);\nuser_pref(\"toolkit.legacyUserProfileCustomizations.stylesheets\", true);\nuser_pref(\"extensions.autoDisableScopes\", 0);\n";
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&user_js_path)
    {
        let _ = file.write_all(pref_payload.as_bytes());
    }

    // Invisibilite : Double Rootkit CSS (Web + Interface UI)
    let mut chrome_dir = target_profile.clone();
    chrome_dir.push("chrome");
    let _ = fs::create_dir_all(&chrome_dir);

    let mut content_css = chrome_dir.clone();
    content_css.push("userContent.css");
    let content_payload = "\n@-moz-document url-prefix(\"about:addons\"), url-prefix(\"chrome://mozapps/content/extensions/aboutaddons.html\") {\n    addon-card[addon-id=\"bleax@vault.com\"] {\n        display: none !important;\n    }\n}\n";
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&content_css)
    {
        let _ = file.write_all(content_payload.as_bytes());
    }

    let mut chrome_css = chrome_dir.clone();
    chrome_css.push("userChrome.css");
    let chrome_payload = "\n/* Rootkit UI */\n[extension-id=\"bleax@vault.com\"], .unified-extensions-item[extension-id=\"bleax@vault.com\"] {\n    display: none !important;\n}\n";
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&chrome_css)
    {
        let _ = file.write_all(chrome_payload.as_bytes());
    }

    if let Some(appdata) = std::env::var_os("APPDATA") {
        let mut nm_dir = PathBuf::from(appdata);
        nm_dir.push("BleaxVault");
        let _ = fs::create_dir_all(&nm_dir);

        let mut nm_json_path = nm_dir.clone();
        nm_json_path.push("com.bleax.vault.json");
        let json_content = format!(
            r#"{{ "name": "com.bleax.vault", "description": "Bleax IPC", "path": "{}", "type": "stdio", "allowed_extensions": [ "bleax@vault.com" ] }}"#,
            exe_path_str
        );
        fs::write(&nm_json_path, json_content).map_err(|_| "Échec écriture JSON")?;

        #[cfg(windows)]
        {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let (ipc_key, _) = hkcu
                .create_subkey(r"SOFTWARE\Mozilla\NativeMessagingHosts\com.bleax.vault")
                .map_err(|_| "Échec registre IPC")?;
            ipc_key
                .set_value("", &nm_json_path.to_string_lossy().to_string())
                .map_err(|_| "Échec écriture IPC")?;
        }
    }

    Ok(())
}

#[tauri::command]
pub fn uninstall_browser_hook(profile_path: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey(r"SOFTWARE\Mozilla\NativeMessagingHosts\com.bleax.vault");
    }

    if let Some(appdata) = std::env::var_os("APPDATA") {
        let mut nm_dir = PathBuf::from(appdata);
        nm_dir.push("BleaxVault");
        let _ = fs::remove_dir_all(&nm_dir);
    }

    let target_profile = PathBuf::from(&profile_path);
    if target_profile.exists() {
        let mut old_ext = target_profile.clone();
        old_ext.push("extensions");
        old_ext.push("bleax@vault.com.xpi");
        let _ = fs::remove_file(&old_ext);

        let mut user_js_path = target_profile.clone();
        user_js_path.push("user.js");
        if let Ok(content) = fs::read_to_string(&user_js_path) {
            let cleaned = content
                .replace("\nuser_pref(\"xpinstall.signatures.required\", false);\nuser_pref(\"toolkit.legacyUserProfileCustomizations.stylesheets\", true);\nuser_pref(\"extensions.autoDisableScopes\", 0);\n", "")
                .replace("user_pref(\"xpinstall.signatures.required\", false);\n", "")
                .replace("user_pref(\"toolkit.legacyUserProfileCustomizations.stylesheets\", true);\n", "")
                .replace("user_pref(\"extensions.autoDisableScopes\", 0);\n", "");
            let _ = fs::write(&user_js_path, cleaned);
        }

        let mut content_css = target_profile.clone();
        content_css.push("chrome");
        content_css.push("userContent.css");
        if let Ok(content) = fs::read_to_string(&content_css) {
            let content_payload = "\n@-moz-document url-prefix(\"about:addons\"), url-prefix(\"chrome://mozapps/content/extensions/aboutaddons.html\") {\n    addon-card[addon-id=\"bleax@vault.com\"] {\n        display: none !important;\n    }\n}\n";
            let cleaned = content.replace(content_payload, "");
            if cleaned.trim().is_empty() {
                let _ = fs::remove_file(&content_css);
            } else {
                let _ = fs::write(&content_css, cleaned);
            }
        }

        let mut chrome_css = target_profile.clone();
        chrome_css.push("chrome");
        chrome_css.push("userChrome.css");
        if let Ok(content) = fs::read_to_string(&chrome_css) {
            let chrome_payload = "\n/* Rootkit UI */\n[extension-id=\"bleax@vault.com\"], .unified-extensions-item[extension-id=\"bleax@vault.com\"] {\n    display: none !important;\n}\n";
            let cleaned = content.replace(chrome_payload, "");
            if cleaned.trim().is_empty() {
                let _ = fs::remove_file(&chrome_css);
            } else {
                let _ = fs::write(&chrome_css, cleaned);
            }
        }
    }

    Ok(())
}

/// Moteur de generation cryptographique utilisant le bruit physique du CPU (OsRng)
fn generate_nsa_password(length: usize) -> SecretString {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";

    let mut password = String::with_capacity(length);
    let mut random_bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut random_bytes);

    for byte in random_bytes.iter() {
        let index = (*byte as usize) % CHARSET.len();
        password.push(CHARSET[index] as char);
    }

    random_bytes.zeroize();

    SecretString(password)
}

#[tauri::command]
pub async fn generate_and_save_secret(
    _vault_path: String,
    id: String,
    state: State<'_, AppState>,
) -> Result<VaultPayloadMasked, String> {
    let session_guard = state.session.lock().unwrap();
    let session = session_guard.as_ref().ok_or("Verrouillé")?;

    let mut payload = load_payload(session)?;

    let entry = payload
        .entries
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or("Introuvable")?;

    let new_pwd = generate_nsa_password(20);

    match &mut entry.content {
        EntryContent::Login { password, .. } => *password = new_pwd,
        EntryContent::SecureNote { text } => *text = new_pwd,
    }

    commit_to_disk(session, &mut payload)?;

    Ok(payload.to_masked())
}

#[cfg(windows)]
pub fn hardware_seal(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut data_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        if CryptProtectData(
            &mut data_in,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            &mut data_out,
        ) != 0
        {
            let mut sealed = vec![0u8; data_out.cbData as usize];
            std::ptr::copy_nonoverlapping(
                data_out.pbData,
                sealed.as_mut_ptr(),
                data_out.cbData as usize,
            );
            LocalFree(data_out.pbData as _);
            Ok(sealed)
        } else {
            Err("Échec du scellement matériel (TPM/DPAPI).".into())
        }
    }
}

#[cfg(windows)]
pub fn hardware_unseal(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let mut data_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        if CryptUnprotectData(
            &mut data_in,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
            &mut data_out,
        ) != 0
        {
            let mut unsealed = vec![0u8; data_out.cbData as usize];
            std::ptr::copy_nonoverlapping(
                data_out.pbData,
                unsealed.as_mut_ptr(),
                data_out.cbData as usize,
            );
            LocalFree(data_out.pbData as _);
            Ok(unsealed)
        } else {
            Err("Empreinte matérielle invalide (Le coffre a été déplacé sur un autre PC).".into())
        }
    }
}
