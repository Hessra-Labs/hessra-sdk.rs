//! # Hessra Token Authorization
//!
//! Authorization token implementation for the Hessra authentication system.
//!
//! This crate provides functionality for creating, verifying and attesting authorization
//! tokens (biscuit tokens) used in the Hessra authentication system. It supports advanced
//! features like service chain attestation, multi-party authorization, and latent capability tokens.
//!
//! ## Features
//!
//! - Token creation: Create singleton or latent capability tokens with configurable time settings
//! - Token activation: Activate latent capability tokens with specific rights
//! - Token verification: Verify tokens without contacting the authorization server
//! - Service chain attestation: Add service node attestations to tokens
//! - Multi-party authorization: Create tokens requiring multiple party attestations
//! - WASM compatibility: WIP WASM bindings for token verification
//!
//! ## Token Types
//!
//! ### Singleton Capability Tokens
//!
//! Singleton tokens grant a specific right to a specific subject for a specific resource
//! and operation. They can be used immediately upon issuance.
//!
//! ### Latent Capability Tokens
//!
//! Latent tokens contain broad `latent_right(resource, operation)` permissions but cannot
//! be used directly. They must be activated by the holder of the bound activator key using
//! the `activate_latent_token` function. The same latent token can be activated multiple
//! times with different subjects and (resource, operation) pairs from the latent_rights set.
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

mod attenuate;
mod attest;
mod mint;
mod revocation;
mod verify;

// Re-export all authorization-specific functionality
pub use attenuate::{activate_latent_token, activate_latent_token_from_string};
pub use attest::{
    add_multi_party_attestation, add_multi_party_attestation_to_token, add_service_node_attestation,
};
pub use mint::{
    create_biscuit, create_multi_party_biscuit, create_multi_party_biscuit_with_time,
    create_multi_party_token, create_multi_party_token_with_time, create_raw_multi_party_biscuit,
    create_service_chain_biscuit, create_service_chain_token, create_service_chain_token_with_time,
    create_token, create_token_with_time, HessraAuthorization,
};
pub use revocation::{get_authorization_revocation_id, get_authorization_revocation_id_from_bytes};
pub use verify::{
    biscuit_key_from_string, verify_biscuit_local, verify_service_chain_biscuit_local,
    verify_service_chain_token_local, verify_token_local, AuthorizationVerifier, ServiceNode,
};

// Re-export commonly needed types from core
pub use hessra_token_core::{
    decode_token, encode_token, parse_token, public_key_from_pem_file, Biscuit, KeyPair, PublicKey,
    TokenError, TokenTimeConfig,
};
