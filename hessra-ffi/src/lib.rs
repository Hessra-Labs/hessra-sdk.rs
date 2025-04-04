//! C FFI bindings for Hessra token verification and configuration.
//!
//! This module provides a C-compatible interface for the core functionality
//! of the Hessra SDK, focused on token verification and configuration management.

use std::ffi::CString;
use std::os::raw::c_char;

mod config;
mod error;
mod token;

pub use config::{HessraConfig, HessraPublicKey};
pub use error::HessraResult;

/// Version information for the Hessra FFI library
#[no_mangle]
pub extern "C" fn hessra_version() -> *const c_char {
    static VERSION: &str = env!("CARGO_PKG_VERSION");
    let c_str = CString::new(VERSION).unwrap_or_default();
    c_str.into_raw()
}

/// Free a string allocated by the Hessra library
///
/// # Safety
///
/// This function must only be called with a pointer that was previously returned by a
/// Hessra library function that returns a string (like `hessra_version`).
/// The pointer must not be null and must not have been freed before.
/// After this call, the pointer is invalid and should not be used.
#[no_mangle]
pub unsafe extern "C" fn hessra_string_free(string: *mut c_char) {
    if !string.is_null() {
        let _ = CString::from_raw(string);
    }
}

/// Initialize the Hessra library.
/// This function should be called before using any other functions.
#[no_mangle]
pub extern "C" fn hessra_init() -> HessraResult {
    // Any global initialization can be done here
    error::HessraResult::SUCCESS
}
