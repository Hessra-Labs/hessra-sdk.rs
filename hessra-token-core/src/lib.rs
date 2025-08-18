//! # Hessra Token Core
//!
//! Core utilities and types shared across Hessra token implementations.
//!
//! This crate provides common functionality used by both authorization tokens
//! and identity tokens, including:
//!
//! - Token encoding/decoding utilities
//! - Time configuration for token validity
//! - Common error types
//! - Biscuit type re-exports

pub mod error;
pub mod time;
pub mod utils;

pub use error::TokenError;
pub use time::TokenTimeConfig;
pub use utils::{decode_token, encode_token, parse_token, public_key_from_pem_file};

// Re-export biscuit types that are needed for public API
pub use biscuit_auth::{Biscuit, KeyPair, PublicKey};
