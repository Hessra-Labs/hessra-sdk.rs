//! # Hessra Token
//!
//! Core verification library for Hessra authentication tokens.
//!
//! This crate provides functionality for verifying and attenuating biscuit tokens
//! used in the Hessra authentication system. It is designed to be WASM-compatible
//! and has no networking dependencies.
//!
//! ## Features
//!
//! - Token verification: Verify tokens without contacting the authorization server
//! - Token attestation: Add service node attestations to tokens
//! - WASM compatibility: Can be compiled to WebAssembly for use in browsers
//!
//! ## Usage
//!
//! ```no_run
//! use hessra_token::{verify_token, biscuit_key_from_string};
//!
//! fn main() -> Result<(), hessra_token::TokenError> {
//!     let token_base64 = "YOUR_TOKEN_STRING";
//!     
//!     // Parse public key from string format
//!     let public_key = biscuit_key_from_string("ed25519/01234567890abcdef".to_string())?;
//!     
//!     // Verify the token
//!     verify_token(token_base64, public_key, "user123", "resource456")?;
//!     
//!     println!("Token verification successful!");
//!     Ok(())
//! }
//! ```

mod attenuate;
mod error;
mod token;
mod utils;
mod verify;

pub use attenuate::add_service_node_attenuation;
pub use error::TokenError;
pub use token::{parse_token, verify_service_chain_token, verify_token};
pub use utils::{decode_token, encode_token};
pub use verify::{
    biscuit_key_from_string, verify_biscuit_local, verify_service_chain_biscuit_local, ServiceNode,
};

// Re-export biscuit types that are needed for public API
pub use biscuit_auth::{Biscuit, KeyPair, PublicKey};

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::macros::{biscuit, block};

    #[test]
    fn test_verify_biscuit_local() {
        // Create a test keypair
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create a simple test biscuit
        let biscuit_builder = biscuit!(
            r#"
                right("alice", "resource1", "read");
                right("alice", "resource1", "write");
            "#
        );
        let biscuit = biscuit_builder.build(&keypair).unwrap();
        let token_bytes = biscuit.to_vec().unwrap();

        // Verify the biscuit
        let result = verify_biscuit_local(
            token_bytes,
            public_key,
            "alice".to_string(),
            "resource1".to_string(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_service_chain_biscuit() {
        // Create test keypairs
        let root_keypair = KeyPair::new();
        let service_keypair = KeyPair::new();
        let service_public_key_hex = hex::encode(service_keypair.public().to_bytes());
        let service_public_key_str = format!("ed25519/{}", service_public_key_hex);

        // Create a simple test biscuit
        let biscuit_builder = biscuit!(
            r#"
                right("alice", "resource1", "read");
                right("alice", "resource1", "write");
                node("resource1", "service1") trusting authority, {service_keypair.public()};
            "#
        );
        let biscuit = biscuit_builder.build(&root_keypair).unwrap();
        let token_bytes = biscuit.to_vec().unwrap();

        // Define service nodes
        let service_nodes = vec![ServiceNode {
            component: "service1".to_string(),
            public_key: service_public_key_str,
        }];

        // Verify the biscuit with service chain
        let result = verify_service_chain_biscuit_local(
            token_bytes,
            root_keypair.public(),
            "alice".to_string(),
            "resource1".to_string(),
            service_nodes,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_service_node_attenuation() {
        // Create test keypairs
        let root_keypair = KeyPair::new();
        let service_keypair = KeyPair::new();

        // Create a simple test biscuit
        let biscuit_builder = biscuit!(
            r#"
                right("alice", "resource1", "read");
                right("alice", "resource1", "write");
            "#
        );
        let biscuit = biscuit_builder.build(&root_keypair).unwrap();
        let token_bytes = biscuit.to_vec().unwrap();

        // Add service node attenuation
        let attenuated_token = add_service_node_attenuation(
            token_bytes,
            root_keypair.public(),
            "resource1",
            &service_keypair,
        );
        assert!(attenuated_token.is_ok());

        // Verify the biscuit still works
        let result = verify_biscuit_local(
            attenuated_token.unwrap(),
            root_keypair.public(),
            "alice".to_string(),
            "resource1".to_string(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_base64_utils() {
        // Create a test keypair and biscuit
        let keypair = KeyPair::new();
        let biscuit_builder = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        );
        let biscuit = biscuit_builder.build(&keypair).unwrap();
        let original_bytes = biscuit.to_vec().unwrap();

        // Test encoding
        let encoded = encode_token(&original_bytes);
        assert!(!encoded.is_empty());

        // Test decoding
        let decoded = decode_token(&encoded).unwrap();
        assert_eq!(original_bytes, decoded);

        // Test decoding with invalid input
        let result = decode_token("invalid-base64!");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_token_string() {
        // Create a test keypair and biscuit
        let keypair = KeyPair::new();
        let biscuit_builder = biscuit!(
            r#"
                right("alice", "resource1", "read");
                right("alice", "resource1", "write");
            "#
        );
        let biscuit = biscuit_builder.build(&keypair).unwrap();
        let token_bytes = biscuit.to_vec().unwrap();
        let token_string = encode_token(&token_bytes);

        // Test verify_token
        let result = verify_token(&token_string, keypair.public(), "alice", "resource1");
        assert!(result.is_ok());

        // Test with invalid subject
        let result = verify_token(&token_string, keypair.public(), "bob", "resource1");
        assert!(result.is_err());
    }
}
