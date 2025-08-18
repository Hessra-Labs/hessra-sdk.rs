//! # Hessra Token Authorization
//!
//! Authorization token implementation for the Hessra authentication system.
//!
//! This crate provides functionality for creating, verifying and attesting authorization
//! tokens (biscuit tokens) used in the Hessra authentication system. It supports advanced
//! features like service chain attestation and multi-party authorization.
//!
//! ## Features
//!
//! - Token creation: Create authorization tokens with configurable time settings
//! - Token verification: Verify tokens without contacting the authorization server
//! - Service chain attestation: Add service node attestations to tokens
//! - Multi-party authorization: Create tokens requiring multiple party attestations
//! - WASM compatibility: Can be compiled to WebAssembly for use in browsers
//!
//! ## Usage
//!
//! ```no_run
//! use hessra_token_authz::{create_biscuit, verify_token_local, biscuit_key_from_string};
//! use hessra_token_core::{TokenTimeConfig, KeyPair, encode_token};
//!
//! fn main() -> Result<(), hessra_token_core::TokenError> {
//!     // Create a new token
//!     let keypair = KeyPair::new();
//!     let token = create_biscuit(
//!         "user123".to_string(),
//!         "resource456".to_string(),
//!         "read".to_string(),
//!         keypair,
//!         TokenTimeConfig::default(),
//!     ).map_err(|e| hessra_token_core::TokenError::generic(e.to_string()))?;
//!     
//!     // Verify the token
//!     let token_string = encode_token(&token);
//!     let public_key = biscuit_key_from_string("ed25519/01234567890abcdef".to_string())?;
//!     verify_token_local(&token_string, public_key, "user123", "resource456", "read")?;
//!     
//!     println!("Token creation and verification successful!");
//!     Ok(())
//! }
//! ```

mod attest;
mod mint;
mod verify;

// Re-export all authorization-specific functionality
pub use attest::{
    add_multi_party_attestation, add_multi_party_attestation_to_token, add_service_node_attestation,
};
pub use mint::{
    create_biscuit, create_multi_party_biscuit, create_multi_party_biscuit_with_time,
    create_multi_party_token, create_multi_party_token_with_time, create_raw_multi_party_biscuit,
    create_service_chain_biscuit, create_service_chain_token, create_service_chain_token_with_time,
    create_token, create_token_with_time,
};
pub use verify::{
    biscuit_key_from_string, verify_biscuit_local, verify_service_chain_biscuit_local,
    verify_service_chain_token_local, verify_token_local, ServiceNode,
};

// Re-export commonly needed types from core
pub use hessra_token_core::{
    decode_token, encode_token, parse_token, public_key_from_pem_file, Biscuit, KeyPair, PublicKey,
    TokenError, TokenTimeConfig,
};
