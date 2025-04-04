use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

use crate::error::HessraResult;

/// Opaque type representing a Hessra public key
#[repr(C)]
pub struct HessraPublicKey(*mut PublicKeyHandle);

struct PublicKeyHandle {
    inner: hessra_token::PublicKey,
}

/// Opaque type representing a Hessra configuration
#[repr(C)]
pub struct HessraConfig(*mut ConfigHandle);

struct ConfigHandle {
    inner: hessra_config::HessraConfig,
}

impl HessraPublicKey {
    pub fn from_key(key: hessra_token::PublicKey) -> Self {
        let handle = Box::new(PublicKeyHandle { inner: key });
        HessraPublicKey(Box::into_raw(handle))
    }

    fn as_ref(&self) -> Option<&PublicKeyHandle> {
        if self.0.is_null() {
            None
        } else {
            unsafe { Some(&*self.0) }
        }
    }

    pub fn public_key(&self) -> Option<&hessra_token::PublicKey> {
        self.as_ref().map(|handle| &handle.inner)
    }
}

impl HessraConfig {
    fn from_config(config: hessra_config::HessraConfig) -> Self {
        let handle = Box::new(ConfigHandle { inner: config });
        HessraConfig(Box::into_raw(handle))
    }

    fn as_ref(&self) -> Option<&ConfigHandle> {
        if self.0.is_null() {
            None
        } else {
            unsafe { Some(&*self.0) }
        }
    }

    fn as_mut(&mut self) -> Option<&mut ConfigHandle> {
        if self.0.is_null() {
            None
        } else {
            unsafe { Some(&mut *self.0) }
        }
    }

    pub fn config(&self) -> Option<&hessra_config::HessraConfig> {
        self.as_ref().map(|handle| &handle.inner)
    }

    pub fn config_mut(&mut self) -> Option<&mut hessra_config::HessraConfig> {
        self.as_mut().map(|handle| &mut handle.inner)
    }
}

/// Create a new public key from a string
#[no_mangle]
pub extern "C" fn hessra_public_key_from_string(
    key_string: *const c_char,
    out_key: *mut *mut HessraPublicKey,
) -> HessraResult {
    if key_string.is_null() || out_key.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    let c_str = unsafe { CStr::from_ptr(key_string) };
    let key_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return HessraResult::ERROR_INVALID_KEY,
    };

    match hessra_token::PublicKey::from_pem(key_str) {
        Ok(key) => {
            let hessra_key = HessraPublicKey::from_key(key);
            let boxed_key = Box::new(hessra_key);
            unsafe {
                *out_key = Box::into_raw(boxed_key);
            }
            HessraResult::SUCCESS
        }
        Err(_) => HessraResult::ERROR_INVALID_KEY,
    }
}

/// Create a new public key from a file
#[no_mangle]
pub extern "C" fn hessra_public_key_from_file(
    file_path: *const c_char,
    out_key: *mut *mut HessraPublicKey,
) -> HessraResult {
    if file_path.is_null() || out_key.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    let c_str = unsafe { CStr::from_ptr(file_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
    };

    match hessra_token::public_key_from_pem_file(path_str) {
        Ok(key) => {
            let hessra_key = HessraPublicKey::from_key(key);
            let boxed_key = Box::new(hessra_key);
            unsafe {
                *out_key = Box::into_raw(boxed_key);
            }
            HessraResult::SUCCESS
        }
        Err(_) => HessraResult::ERROR_INVALID_KEY,
    }
}

/// Free a public key
///
/// # Safety
///
/// This function must only be called with a valid HessraPublicKey that was previously created
/// by functions like `hessra_public_key_from_string` or `hessra_public_key_from_file`.
/// The key must not have been freed before. After this call, the key is invalid and should not be used.
#[no_mangle]
pub unsafe extern "C" fn hessra_public_key_free(key: *mut HessraPublicKey) {
    if !key.is_null() {
        let key_ref = Box::from_raw(key);
        if !key_ref.0.is_null() {
            let _ = Box::from_raw(key_ref.0);
        }
    }
}

/// Create a new empty configuration
#[no_mangle]
pub extern "C" fn hessra_config_new(out_config: *mut *mut HessraConfig) -> HessraResult {
    if out_config.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    // Create a minimal empty configuration with placeholder values
    // that will be replaced by the user through other API calls
    match hessra_config::HessraConfigBuilder::new()
        .base_url("https://placeholder-url.example")
        .mtls_cert("-----BEGIN CERTIFICATE-----\nPLACEHOLDER\n-----END CERTIFICATE-----")
        .mtls_key("-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----")
        .server_ca("-----BEGIN CERTIFICATE-----\nPLACEHOLDER\n-----END CERTIFICATE-----")
        .build()
    {
        Ok(config) => {
            let hessra_config = HessraConfig::from_config(config);
            let boxed_config = Box::new(hessra_config);
            unsafe {
                *out_config = Box::into_raw(boxed_config);
            }
            HessraResult::SUCCESS
        }
        Err(_) => HessraResult::ERROR_INVALID_KEY,
    }
}

/// Load configuration from a file
#[no_mangle]
pub extern "C" fn hessra_config_from_file(
    file_path: *const c_char,
    out_config: *mut *mut HessraConfig,
) -> HessraResult {
    if file_path.is_null() || out_config.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    let c_str = unsafe { CStr::from_ptr(file_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return HessraResult::ERROR_INVALID_PARAMETER,
    };

    let path = Path::new(path_str);
    match hessra_config::HessraConfig::from_file(path) {
        Ok(config) => {
            let hessra_config = HessraConfig::from_config(config);
            let boxed_config = Box::new(hessra_config);
            unsafe {
                *out_config = Box::into_raw(boxed_config);
            }
            HessraResult::SUCCESS
        }
        Err(err) => err.into(),
    }
}

/// Free a configuration
///
/// # Safety
///
/// This function must only be called with a valid HessraConfig that was previously created
/// by functions like `hessra_config_new` or `hessra_config_from_file`.
/// The config must not have been freed before. After this call, the config is invalid and should not be used.
#[no_mangle]
pub unsafe extern "C" fn hessra_config_free(config: *mut HessraConfig) {
    if !config.is_null() {
        let config_ref = Box::from_raw(config);
        if !config_ref.0.is_null() {
            let _ = Box::from_raw(config_ref.0);
        }
    }
}

/// Set public key in the configuration
///
/// # Arguments
///
/// * `config` - Configuration to set the public key in
/// * `key` - Public key to set
///
/// # Returns
///
/// Result code indicating success or failure
#[no_mangle]
pub extern "C" fn hessra_config_set_public_key(
    config: *mut HessraConfig,
    key: *mut HessraPublicKey,
) -> HessraResult {
    if config.is_null() || key.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    let config_ref = unsafe { &mut *config };
    let key_ref = unsafe { &*key };

    // Get the public key as PEM string
    let public_key = match key_ref.as_ref() {
        Some(handle) => handle.inner.to_pem(),
        None => return HessraResult::ERROR_INVALID_KEY,
    };

    match public_key {
        Ok(pem_string) => {
            // Get mutable reference to configuration
            let config_handle = match config_ref.as_mut() {
                Some(handle) => handle,
                None => return HessraResult::ERROR_CONFIG_INVALID,
            };

            // Set the public key in the configuration
            config_handle.inner.public_key = Some(pem_string);

            HessraResult::SUCCESS
        }
        Err(_) => HessraResult::ERROR_INVALID_KEY,
    }
}

/// Get public key from the configuration
///
/// # Arguments
///
/// * `config` - Configuration to get the public key from
/// * `out_key` - Output parameter for the retrieved public key
///
/// # Returns
///
/// Result code indicating success or failure
#[no_mangle]
pub extern "C" fn hessra_config_get_public_key(
    config: *mut HessraConfig,
    out_key: *mut *mut HessraPublicKey,
) -> HessraResult {
    if config.is_null() || out_key.is_null() {
        return HessraResult::ERROR_INVALID_PARAMETER;
    }

    let config_ref = unsafe { &*config };

    // Get reference to configuration
    let config_handle = match config_ref.as_ref() {
        Some(handle) => handle,
        None => return HessraResult::ERROR_CONFIG_INVALID,
    };

    // Get the public key PEM string from the configuration
    let public_key_pem = match &config_handle.inner.public_key {
        Some(key) => key,
        None => return HessraResult::ERROR_INVALID_KEY,
    };

    // Convert the PEM string to a PublicKey
    match hessra_token::PublicKey::from_pem(public_key_pem) {
        Ok(key) => {
            let hessra_key = HessraPublicKey::from_key(key);
            let boxed_key = Box::new(hessra_key);
            unsafe {
                *out_key = Box::into_raw(boxed_key);
            }
            HessraResult::SUCCESS
        }
        Err(_) => HessraResult::ERROR_INVALID_KEY,
    }
}
