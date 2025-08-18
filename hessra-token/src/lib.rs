//! # Hessra Token
//!
//! Core verification library for Hessra authentication tokens.
//!
//! This crate provides functionality for creating, verifying and attesting biscuit tokens
//! used in the Hessra authentication system. It is designed to be WASM-compatible
//! and has no networking dependencies.
//!
//! ## Features
//!
//! - Token creation: Create new tokens with configurable time settings
//! - Token verification: Verify tokens without contacting the authorization server
//! - Token attestation: Add service node attestations to tokens
//! - WASM compatibility: Can be compiled to WebAssembly for use in browsers
//!
//! ## Usage
//!
//! ```no_run
//! use hessra_token::{create_biscuit, verify_token_local, biscuit_key_from_string, TokenTimeConfig, KeyPair, encode_token};
//!
//! fn main() -> Result<(), hessra_token::TokenError> {
//!     // Create a new token
//!     let keypair = KeyPair::new();
//!     let token = create_biscuit(
//!         "user123".to_string(),
//!         "resource456".to_string(),
//!         "read".to_string(),
//!         keypair,
//!         TokenTimeConfig::default(),
//!     ).map_err(|e| hessra_token::TokenError::generic(e.to_string()))?;
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

// Re-export everything from hessra-token-authz for backward compatibility
pub use hessra_token_authz::{
    // Attestation functions
    add_multi_party_attestation,
    add_multi_party_attestation_to_token,
    add_service_node_attestation,
    // Verify functions
    biscuit_key_from_string,
    // Mint functions
    create_biscuit,
    create_multi_party_biscuit,
    create_multi_party_biscuit_with_time,
    create_multi_party_token,
    create_multi_party_token_with_time,
    create_raw_multi_party_biscuit,
    create_service_chain_biscuit,
    create_service_chain_token,
    create_service_chain_token_with_time,
    create_token,
    create_token_with_time,
    verify_biscuit_local,
    verify_service_chain_biscuit_local,
    verify_service_chain_token_local,
    verify_token_local,
    ServiceNode,
};

// Re-export core types
pub use hessra_token_core::{
    decode_token, encode_token, parse_token, public_key_from_pem_file, Biscuit, KeyPair, PublicKey,
    TokenError, TokenTimeConfig,
};

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
            "read".to_string(),
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
            "write".to_string(),
            service_nodes,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_service_node_attestation() {
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

        // Add service node attestation
        let attested_token = add_service_node_attestation(
            token_bytes,
            root_keypair.public(),
            "resource1",
            &service_keypair,
        );
        assert!(attested_token.is_ok());

        // Verify the biscuit still works
        let result = verify_biscuit_local(
            attested_token.unwrap(),
            root_keypair.public(),
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
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
        let result = verify_token_local(
            &token_string,
            keypair.public(),
            "alice",
            "resource1",
            "read",
        );
        assert!(result.is_ok());

        // Test with invalid subject
        let result =
            verify_token_local(&token_string, keypair.public(), "bob", "resource1", "read");
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
                    verify_token_local(token_string, public_key, subject, resource, "read")
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

                    verify_service_chain_token_local(
                        token_string,
                        public_key,
                        subject,
                        resource,
                        "read",
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
                let result = verify_service_chain_token_local(
                    token_string,
                    public_key,
                    subject,
                    resource,
                    "read",
                    service_nodes,
                    None,
                );

                // The test should fail because service attestations haven't been added
                assert_eq!(
                    result.is_ok(),
                    expected_result,
                    "Service chain verification for '{}' resulted in {}, expected: {}",
                    order_service_token["name"].as_str().unwrap(),
                    result.is_ok(),
                    expected_result
                );
            }
        }
    }

    #[test]
    fn test_service_chain_lifecycle() {
        // Load test data from service_chain_tokens.json
        let json_data = fs::read_to_string("tests/service_chain_tokens.json")
            .expect("Failed to read service_chain_tokens.json");
        let tokens: Value =
            serde_json::from_str(&json_data).expect("Failed to parse service_chain_tokens.json");

        // Extract tokens for each stage
        let initial_token = tokens["tokens"][0]["token"].as_str().unwrap();
        let token_after_auth = tokens["tokens"][1]["token"].as_str().unwrap();
        let token_after_payment = tokens["tokens"][2]["token"].as_str().unwrap();
        let final_token = tokens["tokens"][3]["token"].as_str().unwrap();

        // Get service details
        let subject = "uri:urn:test:argo-cli1";
        let resource = "order_service";

        // Load the public key from the PEM file
        let root_public_key = public_key_from_pem_file("tests/hessra_key.pem")
            .expect("Failed to load test public key");

        // Parse the public keys from the JSON
        let auth_service_pk_str = tokens["tokens"][1]["metadata"]["service_nodes"][0]["public_key"]
            .as_str()
            .unwrap();
        let payment_service_pk_str = tokens["tokens"][2]["metadata"]["service_nodes"][1]
            ["public_key"]
            .as_str()
            .unwrap();
        let order_service_pk_str = tokens["tokens"][3]["metadata"]["service_nodes"][2]
            ["public_key"]
            .as_str()
            .unwrap();

        // For this test we'll just skip token generation since we're using pre-made tokens
        // and focus on the verification of the service chain tokens

        // Step 1: Verify initial token as a regular token
        let result = verify_token_local(initial_token, root_public_key, subject, resource, "read");
        assert!(result.is_ok(), "Initial token verification failed");

        // Step 2: Payment Service verifies token with auth service attestation
        let service_nodes_for_payment = vec![ServiceNode {
            component: "auth_service".to_string(),
            public_key: auth_service_pk_str.to_string(),
        }];

        let result = verify_service_chain_token_local(
            token_after_auth,
            root_public_key,
            subject,
            resource,
            "read",
            service_nodes_for_payment.clone(),
            None,
        );
        assert!(
            result.is_ok(),
            "Token with auth attestation verification failed"
        );

        // Step 3: Order Service verifies token with auth and payment attestations
        let service_nodes_for_order = vec![
            ServiceNode {
                component: "auth_service".to_string(),
                public_key: auth_service_pk_str.to_string(),
            },
            ServiceNode {
                component: "payment_service".to_string(),
                public_key: payment_service_pk_str.to_string(),
            },
        ];

        let result = verify_service_chain_token_local(
            token_after_payment,
            root_public_key,
            subject,
            resource,
            "read",
            service_nodes_for_order.clone(),
            None,
        );
        assert!(
            result.is_ok(),
            "Token with payment attestation verification failed"
        );

        // Step 4: Final verification of the complete service chain token
        let service_nodes_complete = vec![
            ServiceNode {
                component: "auth_service".to_string(),
                public_key: auth_service_pk_str.to_string(),
            },
            ServiceNode {
                component: "payment_service".to_string(),
                public_key: payment_service_pk_str.to_string(),
            },
            ServiceNode {
                component: "order_service".to_string(),
                public_key: order_service_pk_str.to_string(),
            },
        ];

        let result = verify_service_chain_token_local(
            final_token,
            root_public_key,
            subject,
            resource,
            "read",
            service_nodes_complete.clone(),
            None,
        );

        // Print more details if verification fails
        if result.is_err() {
            println!("Error details: {:?}", result);

            // Parse the token to check its blocks
            let decoded_final = decode_token(final_token).unwrap();
            if let Ok(biscuit) = Biscuit::from(&decoded_final, root_public_key) {
                println!("Token blocks: {}", biscuit.print());
            } else {
                println!("Failed to parse token");
            }
        }

        assert!(result.is_ok(), "Final token verification failed");

        // Verify that token not attested by the full chain fails authorization against the full chain
        let result = verify_service_chain_token_local(
            token_after_auth,
            root_public_key,
            subject,
            resource,
            "read",
            service_nodes_complete,
            None,
        );
        // This should fail because we're missing attestations from payment and order service
        assert!(
            result.is_err(),
            "Incomplete service chain should be rejected"
        );
    }

    #[test]
    fn test_multi_party_token_verification_lifecycle() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Create a multi-party node that must attest to the token
        let approval_service_key = KeyPair::new();
        let approval_service_public_key = hex::encode(approval_service_key.public().to_bytes());
        let approval_service_public_key = format!("ed25519/{}", approval_service_public_key);
        let approval_service_node = ServiceNode {
            component: "approval_service".to_string(),
            public_key: approval_service_public_key.clone(),
        };
        let nodes = vec![approval_service_node];

        // Step 1: Create a new multi-party token successfully
        let token = create_multi_party_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            &nodes,
        );
        assert!(token.is_ok(), "Failed to create multi-party token");
        let token = token.unwrap();
        let token_string = encode_token(&token);

        println!("✓ Multi-party token created successfully");

        // Step 2: Show that the multi-party token fails to verify without attestation
        let result = verify_token_local(&token_string, public_key, &subject, &resource, &operation);
        assert!(
            result.is_err(),
            "Multi-party token should fail verification without attestation"
        );
        println!("✓ Unattested multi-party token correctly failed verification");

        // Step 3: Attest the token as the approval service
        let attested_token = add_multi_party_attestation(
            token,
            public_key,
            "approval_service".to_string(),
            approval_service_key,
        );
        assert!(
            attested_token.is_ok(),
            "Failed to add multi-party attestation"
        );
        let attested_token = attested_token.unwrap();
        let attested_token_string = encode_token(&attested_token);

        println!("✓ Multi-party attestation added successfully");

        // Step 4: Show that the token now verifies/authorizes
        let result = verify_token_local(
            &attested_token_string,
            public_key,
            &subject,
            &resource,
            &operation,
        );
        assert!(
            result.is_ok(),
            "Attested multi-party token should pass verification"
        );
        println!("✓ Attested multi-party token correctly passed verification");

        // Additional test: Verify that the wrong namespace attestation fails
        let wrong_service_key = KeyPair::new();
        let wrong_attested_token = add_multi_party_attestation(
            decode_token(&token_string).unwrap(),
            public_key,
            "wrong_service".to_string(),
            wrong_service_key,
        );
        assert!(wrong_attested_token.is_ok(), "Attestation should succeed");
        let wrong_attested_token_string = encode_token(&wrong_attested_token.unwrap());

        let result = verify_token_local(
            &wrong_attested_token_string,
            public_key,
            &subject,
            &resource,
            &operation,
        );
        assert!(
            result.is_err(),
            "Token attested by wrong namespace should fail verification"
        );
        println!("✓ Token attested by wrong namespace correctly failed verification");
    }

    #[test]
    fn test_multi_party_token_with_multiple_parties() {
        let subject = "test@test.com".to_owned();
        let resource = "sensitive_resource".to_string();
        let operation = "admin".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Create two multi-party nodes that must both attest to the token
        let legal_dept_key = KeyPair::new();
        let legal_dept_public_key = hex::encode(legal_dept_key.public().to_bytes());
        let legal_dept_public_key = format!("ed25519/{}", legal_dept_public_key);
        let legal_dept_node = ServiceNode {
            component: "legal_dept".to_string(),
            public_key: legal_dept_public_key.clone(),
        };

        let security_team_key = KeyPair::new();
        let security_team_public_key = hex::encode(security_team_key.public().to_bytes());
        let security_team_public_key = format!("ed25519/{}", security_team_public_key);
        let security_team_node = ServiceNode {
            component: "security_team".to_string(),
            public_key: security_team_public_key.clone(),
        };

        let nodes = vec![legal_dept_node, security_team_node];

        // Create a multi-party token requiring both attestations
        let token = create_multi_party_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            &nodes,
        );
        assert!(token.is_ok(), "Failed to create multi-party token");
        let token = token.unwrap();
        let token_string = encode_token(&token);

        // Verify token fails without any attestations
        let result = verify_token_local(&token_string, public_key, &subject, &resource, &operation);
        assert!(result.is_err(), "Token should fail without attestations");

        // Add attestation from legal department only
        let partially_attested_token = add_multi_party_attestation(
            decode_token(&token_string).unwrap(),
            public_key,
            "legal_dept".to_string(),
            legal_dept_key,
        )
        .unwrap();
        let partially_attested_token_string = encode_token(&partially_attested_token);

        // Verify token still fails with only one attestation
        let result = verify_token_local(
            &partially_attested_token_string,
            public_key,
            &subject,
            &resource,
            &operation,
        );
        assert!(
            result.is_err(),
            "Token should fail with only one of two required attestations"
        );

        // Add attestation from security team
        let fully_attested_token = add_multi_party_attestation(
            partially_attested_token,
            public_key,
            "security_team".to_string(),
            security_team_key,
        )
        .unwrap();
        let fully_attested_token_string = encode_token(&fully_attested_token);

        // Now the token should pass verification
        let result = verify_token_local(
            &fully_attested_token_string,
            public_key,
            &subject,
            &resource,
            &operation,
        );
        assert!(
            result.is_ok(),
            "Token should pass with both required attestations"
        );
        println!("✓ Multi-party token with multiple parties verified successfully");
    }
}
