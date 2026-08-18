//! Native-only password capture for mail-provider onboarding.
//!
//! This module deliberately has no serde implementations and never exposes the secret to a
//! command DTO. Callers must move the captured value directly into [`crate::vault::CredentialVault`].

use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

const MAX_PROVIDER_BYTES: usize = 16;
const MAX_USERNAME_BYTES: usize = 320;
const MAX_HOST_BYTES: usize = 253;
const MAX_SECRET_BYTES: usize = 4096;

/// Public metadata used to explain a native credential prompt to the user.
///
/// None of these fields may contain credential material. They are validated before any native UI
/// is created so unbounded or control-character-bearing strings cannot reach platform controls.
pub struct NativeCredentialPrompt<'a> {
    pub provider: &'a str,
    pub username: &'a str,
    pub host: &'a str,
}

/// A password captured by an operating-system-native secure text control.
///
/// This type intentionally implements neither serde trait. Its `Debug` output is always redacted,
/// and the backing allocation is zeroized when dropped.
pub struct NativeCredential {
    secret: Zeroizing<String>,
}

impl NativeCredential {
    /// Borrows the secret for an immediate trusted-core vault write.
    pub fn expose_secret(&self) -> &str {
        self.secret.as_str()
    }
}

impl fmt::Debug for NativeCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeCredential([REDACTED])")
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NativeCredentialError {
    #[error("unsupported mail provider")]
    UnsupportedProvider,
    #[error("invalid credential prompt username")]
    InvalidUsername,
    #[error("invalid credential prompt host")]
    InvalidHost,
    #[error("credential must contain between 1 and 4096 bytes")]
    InvalidSecret,
    #[error("native credential capture must run on the application main thread")]
    NotMainThread,
    #[allow(dead_code)]
    #[error("native credential capture is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy)]
enum ValidatedProvider {
    Imap,
    Yahoo,
    Icloud,
}

impl ValidatedProvider {
    fn display_name(self) -> &'static str {
        match self {
            Self::Imap => "IMAP",
            Self::Yahoo => "Yahoo Mail",
            Self::Icloud => "iCloud Mail",
        }
    }
}

struct ValidatedPrompt<'a> {
    provider: ValidatedProvider,
    username: &'a str,
    host: &'a str,
}

/// Validates the public prompt fields independently, then opens a native password-masked control.
///
/// `Ok(None)` means the user cancelled. On success, the secret remains Rust-only in a zeroizing
/// allocation; it must be written directly to the credential vault rather than returned through
/// Tauri's invoke boundary.
pub fn capture_native_credential(
    prompt: NativeCredentialPrompt<'_>,
) -> Result<Option<NativeCredential>, NativeCredentialError> {
    let prompt = validate_prompt(prompt)?;
    let secret = platform::capture(&prompt)?;
    secret.map(NativeCredential::from_secret).transpose()
}

impl NativeCredential {
    fn from_secret(secret: Zeroizing<String>) -> Result<Self, NativeCredentialError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(NativeCredentialError::InvalidSecret);
        }
        Ok(Self { secret })
    }
}

fn validate_prompt(
    prompt: NativeCredentialPrompt<'_>,
) -> Result<ValidatedPrompt<'_>, NativeCredentialError> {
    let provider = validate_provider(prompt.provider)?;
    validate_username(prompt.username)?;
    validate_host(prompt.host)?;
    Ok(ValidatedPrompt {
        provider,
        username: prompt.username,
        host: prompt.host,
    })
}

fn validate_provider(value: &str) -> Result<ValidatedProvider, NativeCredentialError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(NativeCredentialError::UnsupportedProvider);
    }
    match value {
        "imap" => Ok(ValidatedProvider::Imap),
        "yahoo" => Ok(ValidatedProvider::Yahoo),
        "icloud" => Ok(ValidatedProvider::Icloud),
        _ => Err(NativeCredentialError::UnsupportedProvider),
    }
}

fn validate_username(value: &str) -> Result<(), NativeCredentialError> {
    if value.is_empty()
        || value.len() > MAX_USERNAME_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(NativeCredentialError::InvalidUsername);
    }
    Ok(())
}

fn validate_host(value: &str) -> Result<(), NativeCredentialError> {
    if value.is_empty()
        || value.len() > MAX_HOST_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(NativeCredentialError::InvalidHost);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod platform {
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{NSAlert, NSAlertFirstButtonReturn, NSSecureTextField};
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
    use zeroize::Zeroizing;

    use super::{NativeCredentialError, ValidatedPrompt};

    pub(super) fn capture(
        prompt: &ValidatedPrompt<'_>,
    ) -> Result<Option<Zeroizing<String>>, NativeCredentialError> {
        let main_thread = MainThreadMarker::new().ok_or(NativeCredentialError::NotMainThread)?;
        let alert = NSAlert::new(main_thread);
        alert.setMessageText(&NSString::from_str(&format!(
            "Connect {}",
            prompt.provider.display_name()
        )));
        alert.setInformativeText(&NSString::from_str(&format!(
            "Enter the password for {} on {}. It will be stored only in the system credential vault.",
            prompt.username, prompt.host
        )));
        alert.addButtonWithTitle(&NSString::from_str("Connect"));
        alert.addButtonWithTitle(&NSString::from_str("Cancel"));

        // NSSecureTextField is AppKit's password-masked control. Keep it strongly retained until
        // after extraction and explicitly clear the control before releasing the dialog.
        let field = NSSecureTextField::initWithFrame(
            NSSecureTextField::alloc(main_thread),
            NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(360.0, 24.0)),
        );
        alert.setAccessoryView(Some(&field));
        let response = alert.runModal();
        if response != NSAlertFirstButtonReturn {
            field.setStringValue(&NSString::from_str(""));
            return Ok(None);
        }

        let secret = Zeroizing::new(field.stringValue().to_string());
        field.setStringValue(&NSString::from_str(""));
        Ok(Some(secret))
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::{ffi::c_void, mem, ptr};

    use windows_sys::Win32::{
        Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM},
        Graphics::Gdi::{GetStockObject, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Controls::EM_SETLIMITTEXT,
            Input::KeyboardAndMouse::SetFocus,
            WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
                GetSystemMetrics, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW,
                IsDialogMessageW, LoadCursorW, RegisterClassW, SendMessageW, SetForegroundWindow,
                SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage, BN_CLICKED,
                BS_DEFPUSHBUTTON, BS_PUSHBUTTON, ES_AUTOHSCROLL, ES_PASSWORD, GWLP_USERDATA, HMENU,
                IDC_ARROW, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_HIDE, SW_SHOW, WM_CLOSE, WM_COMMAND,
                WM_SETFONT, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_EX_CONTROLPARENT,
                WS_EX_DLGMODALFRAME, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
            },
        },
    };
    use zeroize::Zeroizing;

    use super::{NativeCredentialError, ValidatedPrompt, MAX_SECRET_BYTES};

    const OK_ID: usize = 1;
    const CANCEL_ID: usize = 2;
    const CLASS_NAME: &[u16] = &[
        b'F' as u16,
        b'i' as u16,
        b'l' as u16,
        b'y' as u16,
        b'N' as u16,
        b'a' as u16,
        b't' as u16,
        b'i' as u16,
        b'v' as u16,
        b'e' as u16,
        b'C' as u16,
        b'r' as u16,
        b'e' as u16,
        b'd' as u16,
        b'e' as u16,
        b'n' as u16,
        b't' as u16,
        b'i' as u16,
        b'a' as u16,
        b'l' as u16,
        0,
    ];
    const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;

    struct DialogState {
        done: bool,
        accepted: bool,
    }

    pub(super) fn capture(
        prompt: &ValidatedPrompt<'_>,
    ) -> Result<Option<Zeroizing<String>>, NativeCredentialError> {
        // SAFETY: Every HWND and pointer is created and consumed on this thread. The state pointer
        // remains valid until after the nested message loop exits and the window is destroyed.
        unsafe { capture_inner(prompt) }
    }

    unsafe fn capture_inner(
        prompt: &ValidatedPrompt<'_>,
    ) -> Result<Option<Zeroizing<String>>, NativeCredentialError> {
        let instance = GetModuleHandleW(ptr::null());
        if instance.is_null() {
            return Err(NativeCredentialError::Unavailable);
        }

        let window_class = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: ptr::null_mut(),
            hCursor: LoadCursorW(ptr::null_mut(), IDC_ARROW),
            hbrBackground: (COLOR_WINDOW as isize + 1) as HBRUSH,
            lpszMenuName: ptr::null(),
            lpszClassName: CLASS_NAME.as_ptr(),
        };
        if RegisterClassW(&window_class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(NativeCredentialError::Unavailable);
        }

        let title = wide(&format!("Connect {}", prompt.provider.display_name()));
        let width = 520;
        let height = 230;
        let x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;
        let window = CreateWindowExW(
            WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
            CLASS_NAME.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            x,
            y,
            width,
            height,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        );
        if window.is_null() {
            return Err(NativeCredentialError::Unavailable);
        }

        let mut state = DialogState {
            done: false,
            accepted: false,
        };
        SetWindowLongPtrW(
            window,
            GWLP_USERDATA,
            &mut state as *mut DialogState as isize,
        );

        let explanation = wide(&format!(
            "Enter the password for {} on {}. It will be stored only in the system credential vault.",
            prompt.username, prompt.host
        ));
        let static_class = wide("STATIC");
        let edit_class = wide("EDIT");
        let button_class = wide("BUTTON");
        let empty = wide("");
        let connect = wide("Connect");
        let cancel = wide("Cancel");

        let label = create_control(
            window,
            &static_class,
            &explanation,
            WS_CHILD | WS_VISIBLE,
            24,
            22,
            456,
            48,
            0,
            instance,
        )?;
        let password = create_control(
            window,
            &edit_class,
            &empty,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32 | ES_PASSWORD as u32,
            24,
            82,
            456,
            25,
            0,
            instance,
        )?;
        let ok = create_control(
            window,
            &button_class,
            &connect,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            294,
            134,
            88,
            30,
            OK_ID,
            instance,
        )?;
        let cancel_button = create_control(
            window,
            &button_class,
            &cancel,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
            392,
            134,
            88,
            30,
            CANCEL_ID,
            instance,
        )?;

        let font = GetStockObject(DEFAULT_GUI_FONT);
        for control in [label, password, ok, cancel_button] {
            SendMessageW(control, WM_SETFONT, font as WPARAM, 1);
        }
        SendMessageW(password, EM_SETLIMITTEXT, MAX_SECRET_BYTES, 0);
        ShowWindow(window, SW_SHOW);
        SetForegroundWindow(window);
        SetFocus(password);

        let mut message: MSG = mem::zeroed();
        while !state.done {
            let status = GetMessageW(&mut message, ptr::null_mut(), 0, 0);
            if status <= 0 {
                state.done = true;
                state.accepted = false;
                break;
            }
            if IsDialogMessageW(window, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        let result = if state.accepted {
            let utf16_len = GetWindowTextLengthW(password);
            if utf16_len < 0 {
                Err(NativeCredentialError::Unavailable)
            } else {
                let mut utf16 = Zeroizing::new(vec![0_u16; utf16_len as usize + 1]);
                let copied = GetWindowTextW(password, utf16.as_mut_ptr(), utf16.len() as i32);
                if copied < 0 {
                    Err(NativeCredentialError::Unavailable)
                } else {
                    utf16.truncate(copied as usize);
                    decode_utf16_secret(utf16.as_slice()).map(Some)
                }
            }
        } else {
            Ok(None)
        };

        // Clear the native control before destroying it so the edit buffer is not left populated.
        SetWindowTextW(password, empty.as_ptr());
        SetWindowLongPtrW(window, GWLP_USERDATA, 0);
        DestroyWindow(window);
        result
    }

    unsafe fn create_control(
        parent: HWND,
        class_name: &[u16],
        text: &[u16],
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        id: usize,
        instance: *mut c_void,
    ) -> Result<HWND, NativeCredentialError> {
        let control = CreateWindowExW(
            0,
            class_name.as_ptr(),
            text.as_ptr(),
            style,
            x,
            y,
            width,
            height,
            parent,
            id as HMENU,
            instance,
            ptr::null(),
        );
        if control.is_null() {
            DestroyWindow(parent);
            Err(NativeCredentialError::Unavailable)
        } else {
            Ok(control)
        }
    }

    unsafe extern "system" fn window_proc(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let state = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut DialogState;
        match message {
            WM_COMMAND if !state.is_null() => {
                let id = wparam & 0xffff;
                let notification = (wparam >> 16) as u32;
                if notification == BN_CLICKED && (id == OK_ID || id == CANCEL_ID) {
                    (*state).accepted = id == OK_ID;
                    (*state).done = true;
                    ShowWindow(window, SW_HIDE);
                    return 0;
                }
            }
            WM_CLOSE if !state.is_null() => {
                (*state).accepted = false;
                (*state).done = true;
                ShowWindow(window, SW_HIDE);
                return 0;
            }
            _ => {}
        }
        DefWindowProcW(window, message, wparam, lparam)
    }

    fn decode_utf16_secret(value: &[u16]) -> Result<Zeroizing<String>, NativeCredentialError> {
        let mut secret = Zeroizing::new(String::with_capacity(value.len()));
        for character in char::decode_utf16(value.iter().copied()) {
            secret.push(character.map_err(|_| NativeCredentialError::InvalidSecret)?);
        }
        Ok(secret)
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod platform {
    use zeroize::Zeroizing;

    use super::{NativeCredentialError, ValidatedPrompt};

    pub(super) fn capture(
        _prompt: &ValidatedPrompt<'_>,
    ) -> Result<Option<Zeroizing<String>>, NativeCredentialError> {
        Err(NativeCredentialError::Unavailable)
    }
}
