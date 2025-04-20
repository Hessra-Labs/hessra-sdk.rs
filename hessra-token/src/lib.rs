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
pub use utils::{decode_token, encode_token, public_key_from_pem_file};
pub use verify::{
    biscuit_key_from_string, verify_biscuit_local, verify_service_chain_biscuit_local, ServiceNode,
};

// Re-export biscuit types that are needed for public API
pub use biscuit_auth::{Biscuit, KeyPair, PublicKey};

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::macros::biscuit;
    use serde_json::Value;
    use std::fs;

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

        // Create a simple test biscuit with separate node facts
        let biscuit_builder = biscuit!(
            r#"
                right("alice", "resource1", "read");
                right("alice", "resource1", "write");
                node("resource1", "service1");
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

    #[test]
    fn test_token_verification_from_json() {
        // Load the test tokens from JSON
        let json_data =
            fs::read_to_string("tests/test_tokens.json").expect("Failed to read test_tokens.json");
        let tokens: Value =
            serde_json::from_str(&json_data).expect("Failed to parse test_tokens.json");

        // Load the public key
        let public_key = public_key_from_pem_file("tests/hessra_key.pem")
            .expect("Failed to load test public key");

        // Test each token
        for token_value in tokens["tokens"].as_array().unwrap() {
            let name = token_value["name"].as_str().unwrap();
            let token_string = token_value["token"].as_str().unwrap();
            let metadata = &token_value["metadata"];

            // Get values from metadata
            let subject = metadata["subject"].as_str().unwrap();
            let resource = metadata["resource"].as_str().unwrap();
            let expected_result = metadata["expected_result"].as_bool().unwrap();
            let description = metadata["description"].as_str().unwrap_or("No description");

            println!("Testing token '{}': {}", name, description);

            // Verify the token
            let result = parse_token(token_string, public_key).and_then(|biscuit| {
                // Print the token blocks for debugging
                println!("Token blocks: {}", biscuit.print());

                if metadata["type"].as_str().unwrap() == "singleton" {
                    verify_token(token_string, public_key, subject, resource)
                } else {
                    // Create test service nodes
                    let service_nodes = vec![
                        ServiceNode {
                            component: "auth_service".to_string(),
                            public_key: "ed25519/0123456789abcdef0123456789abcdef".to_string(),
                        },
                        ServiceNode {
                            component: "payment_service".to_string(),
                            public_key: "ed25519/fedcba9876543210fedcba9876543210".to_string(),
                        },
                    ];

                    verify_service_chain_token(
                        token_string,
                        public_key,
                        subject,
                        resource,
                        service_nodes,
                        None,
                    )
                }
            });

            // Check if the result matches expectations
            let verification_succeeded = result.is_ok();
            assert_eq!(
                verification_succeeded, expected_result,
                "Token '{}' verification resulted in {}, expected: {} - {}",
                name, verification_succeeded, expected_result, description
            );

            println!(
                "✓ Token '{}' - Verification: {}",
                name,
                if verification_succeeded == expected_result {
                    "PASSED"
                } else {
                    "FAILED"
                }
            );
        }
    }

    #[test]
    fn test_service_chain_tokens_from_json() {
        // Load the test tokens from JSON
        let json_data =
            fs::read_to_string("tests/test_tokens.json").expect("Failed to read test_tokens.json");
        let tokens: Value =
            serde_json::from_str(&json_data).expect("Failed to parse test_tokens.json");

        // Load the public key
        let public_key = public_key_from_pem_file("tests/hessra_key.pem")
            .expect("Failed to load test public key");

        // Find the service chain token (order_service)
        if let Some(tokens_array) = tokens["tokens"].as_array() {
            if let Some(order_service_token) = tokens_array
                .iter()
                .find(|t| t["name"].as_str().unwrap() == "argo-cli1_access_order_service")
            {
                let token_string = order_service_token["token"].as_str().unwrap();
                let subject = order_service_token["metadata"]["subject"].as_str().unwrap();
                let resource = order_service_token["metadata"]["resource"]
                    .as_str()
                    .unwrap();
                let expected_result = order_service_token["metadata"]["expected_result"]
                    .as_bool()
                    .unwrap();

                // Create test service nodes
                let service_nodes = vec![
                    ServiceNode {
                        component: "auth_service".to_string(),
                        public_key: "ed25519/0123456789abcdef0123456789abcdef".to_string(),
                    },
                    ServiceNode {
                        component: "payment_service".to_string(),
                        public_key: "ed25519/fedcba9876543210fedcba9876543210".to_string(),
                    },
                ];

                // Test the token with service chain verification
                let result = verify_service_chain_token(
                    token_string,
                    public_key,
                    subject,
                    resource,
                    service_nodes,
                    None,
                );

                let res = result.is_err();
                println!("res: {}", res);
                println!("expected_result: {}", expected_result);

                // The test should fail because service attestations haven't been added
                assert_eq!(result.is_err(), !expected_result,
                    "Service chain verification should have failed as specified in the token metadata");
            }
        }
    }
}
