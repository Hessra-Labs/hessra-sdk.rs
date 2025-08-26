mod attenuate;
mod jit;
mod mint;
mod verify;

pub use attenuate::add_identity_attenuation_to_token;
pub use jit::create_short_lived_identity_token;
pub use mint::{create_identity_biscuit, create_identity_token, create_raw_identity_biscuit};
pub use verify::verify_identity_token;

#[cfg(test)]
mod tests {
    use super::*;
    use hessra_token_core::{KeyPair, TokenTimeConfig};

    #[test]
    fn test_basic_identity_token_creation_and_verification() {
        // Create a keypair for signing
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Test 1: Create and verify token with exact match
        let subject = "urn:hessra:alice".to_string();
        let token = create_identity_token(subject.clone(), keypair, TokenTimeConfig::default())
            .expect("Failed to create identity token");

        // Should pass with exact identity
        assert!(
            verify_identity_token(token.clone(), public_key, subject.clone()).is_ok(),
            "Verification should succeed with exact identity match"
        );

        // Should fail with different identity
        assert!(
            verify_identity_token(token.clone(), public_key, "urn:hessra:bob".to_string()).is_err(),
            "Verification should fail with different identity"
        );

        // With the current implementation, more specific identities DO work without explicit attenuation
        // because the base token check allows: $a == {subject} || $a.starts_with({subject} + ":")
        // This might not be ideal - consider making base token more restrictive
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:alice:agent".to_string()
            )
            .is_ok(),
            "More specific identity works due to hierarchical check in base token"
        );
    }

    #[test]
    fn test_single_level_delegation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create base identity token
        let base_identity = "urn:hessra:alice".to_string();
        let token =
            create_identity_token(base_identity.clone(), keypair, TokenTimeConfig::default())
                .expect("Failed to create identity token");

        // Attenuate to a more specific identity
        let delegated_identity = "urn:hessra:alice:laptop".to_string();
        let attenuated_result = add_identity_attenuation_to_token(
            token.clone(),
            delegated_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        );

        let attenuated_token = match attenuated_result {
            Ok(t) => t,
            Err(e) => panic!("Failed to attenuate token: {:?}", e),
        };

        // Original identity should NOT work with attenuated token (delegation restricts usage)
        let base_verify_result =
            verify_identity_token(attenuated_token.clone(), public_key, base_identity.clone());
        assert!(
            base_verify_result.is_err(),
            "Base identity should NOT verify with attenuated token - use original token instead"
        );

        // Delegated identity should work
        assert!(
            verify_identity_token(
                attenuated_token.clone(),
                public_key,
                delegated_identity.clone()
            )
            .is_ok(),
            "Delegated identity should verify"
        );

        // Different branch should fail
        assert!(
            verify_identity_token(
                attenuated_token.clone(),
                public_key,
                "urn:hessra:alice:phone".to_string()
            )
            .is_err(),
            "Different branch of delegation should fail"
        );

        // Completely different identity should fail
        assert!(
            verify_identity_token(
                attenuated_token.clone(),
                public_key,
                "urn:hessra:bob".to_string()
            )
            .is_err(),
            "Completely different identity should fail"
        );
    }

    #[test]
    fn test_multi_level_delegation_chain() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create organizational hierarchy
        let org_identity = "urn:hessra:company".to_string();
        let dept_identity = "urn:hessra:company:dept_eng".to_string();
        let user_identity = "urn:hessra:company:dept_eng:alice".to_string();
        let device_identity = "urn:hessra:company:dept_eng:alice:laptop".to_string();

        // Create base token for organization
        let token =
            create_identity_token(org_identity.clone(), keypair, TokenTimeConfig::default())
                .expect("Failed to create org token");

        // First attenuation: org -> department
        let token = add_identity_attenuation_to_token(
            token,
            dept_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to department");

        // Second attenuation: department -> user
        let token = add_identity_attenuation_to_token(
            token,
            user_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to user");

        // Third attenuation: user -> device
        let token = add_identity_attenuation_to_token(
            token,
            device_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to device");

        // After all attenuations, only the most specific identity should work
        // (all checks must pass, so we get the intersection)
        assert!(
            verify_identity_token(token.clone(), public_key, org_identity).is_err(),
            "Organization level should NOT work after delegation to device"
        );
        assert!(
            verify_identity_token(token.clone(), public_key, dept_identity).is_err(),
            "Department level should NOT work after delegation to device"
        );
        assert!(
            verify_identity_token(token.clone(), public_key, user_identity).is_err(),
            "User level should NOT work after delegation to device"
        );
        assert!(
            verify_identity_token(token.clone(), public_key, device_identity).is_ok(),
            "Device level SHOULD work - it's the delegated identity"
        );

        // Different branches should fail
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:company:dept_hr".to_string()
            )
            .is_err(),
            "Different department should fail"
        );
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:company:dept_eng:bob".to_string()
            )
            .is_err(),
            "Different user in same department should fail"
        );
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:company:dept_eng:alice:phone".to_string()
            )
            .is_err(),
            "Different device for same user should fail"
        );
    }

    #[test]
    fn test_time_based_expiration() {
        let identity = "urn:hessra:alice".to_string();

        // Create token that's already expired
        let expired_config = TokenTimeConfig {
            start_time: Some(0), // Unix epoch
            duration: 1,         // 1 second
        };

        let expired_keypair = KeyPair::new();
        let expired_public_key = expired_keypair.public();
        let expired_token =
            create_identity_token(identity.clone(), expired_keypair, expired_config)
                .expect("Failed to create expired token");

        // Should fail verification due to expiration
        assert!(
            verify_identity_token(expired_token, expired_public_key, identity.clone()).is_err(),
            "Expired token should fail verification"
        );

        // Create valid base token with long duration
        let valid_config = TokenTimeConfig {
            start_time: None,
            duration: 3600, // 1 hour
        };

        let valid_keypair = KeyPair::new();
        let valid_public_key = valid_keypair.public();
        let valid_token = create_identity_token(identity.clone(), valid_keypair, valid_config)
            .expect("Failed to create valid token");

        // Attenuate with already expired time
        let attenuated_expired = add_identity_attenuation_to_token(
            valid_token.clone(),
            "urn:hessra:alice:laptop".to_string(),
            valid_public_key, // Use the same public key that signed the token
            expired_config,
        )
        .expect("Failed to attenuate token");

        // Should fail even though base token is valid
        assert!(
            verify_identity_token(
                attenuated_expired,
                valid_public_key,
                "urn:hessra:alice:laptop".to_string()
            )
            .is_err(),
            "Token with expired attenuation should fail"
        );
    }

    #[test]
    fn test_uri_validation_edge_cases() {
        // Test with different URI schemes
        // Note: Current implementation assumes ":" as hierarchy delimiter
        let test_cases = vec![
            ("urn:hessra:user", "urn:hessra:user:device"),
            (
                "https://example.com/user",
                "https://example.com/user:device",
            ), // Use : for hierarchy
            ("mailto:user@example.com", "mailto:user@example.com:device"),
            ("user", "user:device"), // Simple non-URI format
        ];

        for (base, delegated) in test_cases {
            // Create a new keypair for each test case
            let keypair = KeyPair::new();
            let public_key = keypair.public();

            let token =
                create_identity_token(base.to_string(), keypair, TokenTimeConfig::default())
                    .expect(&format!("Failed to create token for {}", base));

            let attenuated = add_identity_attenuation_to_token(
                token,
                delegated.to_string(),
                public_key, // Use the same public key
                TokenTimeConfig::default(),
            )
            .expect(&format!("Failed to attenuate {} to {}", base, delegated));

            // After attenuation, only the delegated identity should work
            assert!(
                verify_identity_token(attenuated.clone(), public_key, base.to_string()).is_err(),
                "Base identity {} should NOT verify after delegation",
                base
            );
            assert!(
                verify_identity_token(attenuated, public_key, delegated.to_string()).is_ok(),
                "Delegated identity {} should verify",
                delegated
            );
        }
    }

    #[test]
    fn test_prefix_attack_prevention() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create token for alice
        let alice_token = create_identity_token(
            "urn:hessra:alice".to_string(),
            keypair,
            TokenTimeConfig::default(),
        )
        .expect("Failed to create alice token");

        // alice2 should not be able to verify (even though "alice" is a prefix of "alice2")
        assert!(
            verify_identity_token(
                alice_token.clone(),
                public_key,
                "urn:hessra:alice2".to_string()
            )
            .is_err(),
            "alice2 should not verify against alice token"
        );

        // Create attenuated token
        let attenuated = add_identity_attenuation_to_token(
            alice_token,
            "urn:hessra:alice:device".to_string(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate");

        // Similar prefix attacks on attenuated token
        assert!(
            verify_identity_token(
                attenuated.clone(),
                public_key,
                "urn:hessra:alice:device2".to_string()
            )
            .is_err(),
            "device2 should not verify against device"
        );
        assert!(
            verify_identity_token(
                attenuated,
                public_key,
                "urn:hessra:alice2:device".to_string()
            )
            .is_err(),
            "alice2:device should not verify"
        );
    }

    #[test]
    fn test_empty_identity_handling() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Empty identity should be handled gracefully
        let result = create_identity_token("".to_string(), keypair, TokenTimeConfig::default());

        // This should succeed in creation (empty string is valid)
        assert!(
            result.is_ok(),
            "Should be able to create token with empty identity"
        );

        let token = result.unwrap();

        // Verification with empty identity should work
        assert!(
            verify_identity_token(token.clone(), public_key, "".to_string()).is_ok(),
            "Empty identity should verify against empty identity token"
        );

        // Non-empty identity that doesn't start with ":" should fail
        assert!(
            verify_identity_token(token.clone(), public_key, "urn:hessra:anyone".to_string())
                .is_err(),
            "Non-empty identity should not verify against empty identity token"
        );

        // But something starting with ":" would pass due to starts_with check
        assert!(
            verify_identity_token(token, public_key, ":something".to_string()).is_ok(),
            "Identity starting with : would match empty identity's hierarchy check"
        );
    }
}
