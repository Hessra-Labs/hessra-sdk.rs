use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

/// Result type for Hessra FFI functions.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HessraResult {
    SUCCESS = 0,
    ERROR_INVALID_TOKEN = 1,
    ERROR_INVALID_KEY = 2,
    ERROR_VERIFICATION_FAILED = 3,
    ERROR_CONFIG_INVALID = 4,
    ERROR_MEMORY = 5,
    ERROR_IO = 6,
    ERROR_INVALID_PARAMETER = 7,
    ERROR_UNKNOWN = 999,
}

impl From<hessra_token::TokenError> for HessraResult {
    fn from(err: hessra_token::TokenError) -> Self {
        use hessra_token::TokenError;

        match err {
            // Signature and format errors
            TokenError::InvalidSignature { .. }
            | TokenError::UnknownPublicKey
            | TokenError::DeserializationError { .. }
            | TokenError::SerializationError { .. }
            | TokenError::Base64DecodingError { .. }
            | TokenError::UnsupportedVersion { .. } => HessraResult::ERROR_INVALID_TOKEN,

            // Invalid key format
            TokenError::InvalidKeyFormat { .. } => HessraResult::ERROR_INVALID_KEY,

            // Verification failures
            TokenError::Expired { .. }
            | TokenError::DomainMismatch { .. }
            | TokenError::CheckFailed { .. }
            | TokenError::IdentityMismatch { .. }
            | TokenError::HierarchyViolation { .. }
            | TokenError::AttenuationFailed { .. }
            | TokenError::BearerNotAllowed { .. }
            | TokenError::RightsDenied { .. }
            | TokenError::ServiceChainFailed { .. }
            | TokenError::MultiPartyAttestationMissing { .. }
            | TokenError::NoMatchingPolicy { .. }
            | TokenError::PolicyMatchedButChecksFailed { .. } => {
                HessraResult::ERROR_VERIFICATION_FAILED
            }

            // Execution errors
            TokenError::ExecutionLimitReached { .. }
            | TokenError::ExpressionError { .. }
            | TokenError::InvalidBlockRule { .. } => HessraResult::ERROR_VERIFICATION_FAILED,

            // Generic errors
            TokenError::Internal(_) | TokenError::Generic(_) => HessraResult::ERROR_UNKNOWN,
        }
    }
}

impl From<hessra_config::ConfigError> for HessraResult {
    fn from(err: hessra_config::ConfigError) -> Self {
        #[allow(unreachable_patterns)]
        match err {
            hessra_config::ConfigError::MissingBaseUrl => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::InvalidPort => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::MissingCertificate => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::MissingKey => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::MissingServerCA => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::InvalidCertificate(_) => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::IOError(_) => HessraResult::ERROR_IO,
            hessra_config::ConfigError::ParseError(_) => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::AlreadyInitialized => HessraResult::ERROR_CONFIG_INVALID,
            hessra_config::ConfigError::EnvVarError(_) => HessraResult::ERROR_CONFIG_INVALID,
            _ => HessraResult::ERROR_UNKNOWN,
        }
    }
}

/// Get a human-readable error message for a result code
#[no_mangle]
pub extern "C" fn hessra_error_message(result: HessraResult) -> *mut c_char {
    let message = match result {
        HessraResult::SUCCESS => "Success",
        HessraResult::ERROR_INVALID_TOKEN => "Invalid token format",
        HessraResult::ERROR_INVALID_KEY => "Invalid public key",
        HessraResult::ERROR_VERIFICATION_FAILED => "Token verification failed",
        HessraResult::ERROR_CONFIG_INVALID => "Invalid configuration",
        HessraResult::ERROR_MEMORY => "Memory allocation error",
        HessraResult::ERROR_IO => "I/O error",
        HessraResult::ERROR_INVALID_PARAMETER => "Invalid parameter",
        HessraResult::ERROR_UNKNOWN => "Unknown error",
    };

    match CString::new(message) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
