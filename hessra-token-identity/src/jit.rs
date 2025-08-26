extern crate biscuit_auth as biscuit;
use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, PublicKey, TokenError};

/// Create a short-lived version of an identity token for just-in-time use
///
/// This function takes an existing identity token and creates an attenuated version
/// that expires in 5 seconds. This is designed for security - the short-lived token
/// can be safely sent over the network while the original long-lived token stays secure
/// on the client.
///
/// The attenuated token preserves the original identity and all existing constraints,
/// only adding a time-based expiry check.
///
/// # Arguments
/// * `token` - The original identity token to attenuate
/// * `public_key` - The public key to verify the original token
///
/// # Returns
/// A new token string that expires in 5 seconds
pub fn create_short_lived_identity_token(
    token: String,
    public_key: PublicKey,
) -> Result<String, TokenError> {
    // Parse the original token
    let biscuit = Biscuit::from_base64(&token, public_key).map_err(TokenError::biscuit_error)?;

    // Generate a new ephemeral keypair for this attenuation
    let ephemeral_key = KeyPair::new();

    // Calculate expiration time (5 seconds from now)
    let expiration = Utc::now().timestamp() + 5;

    // Create an attenuation block that only adds a time check
    // We don't add any identity constraints - the original identity is preserved
    let time_block = block!(
        r#"
            check if time($time), $time < {expiration};
        "#
    );

    // Create a third-party request for the attenuation
    let third_party_request = biscuit
        .third_party_request()
        .map_err(TokenError::biscuit_error)?;

    // Create the block with the ephemeral key
    let time_block = third_party_request
        .create_block(&ephemeral_key.private(), time_block)
        .map_err(TokenError::biscuit_error)?;

    // Append the third-party block to the biscuit
    let attenuated_biscuit = biscuit
        .append_third_party(ephemeral_key.public(), time_block)
        .map_err(TokenError::biscuit_error)?;

    // Return the attenuated token as a base64 string
    let token = attenuated_biscuit
        .to_base64()
        .map_err(TokenError::biscuit_error)?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_identity_token, verify_identity_token};
    use hessra_token_core::{KeyPair, TokenTimeConfig};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_short_lived_token_creation() {
        // Create a base identity token
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let identity = "urn:hessra:test:user".to_string();

        let base_token =
            create_identity_token(identity.clone(), keypair, TokenTimeConfig::default())
                .expect("Failed to create base token");

        // Create a short-lived version
        let short_lived = create_short_lived_identity_token(base_token.clone(), public_key)
            .expect("Failed to create short-lived token");

        // The short-lived token should be different from the base
        assert_ne!(base_token, short_lived);

        // Should verify immediately
        assert!(
            verify_identity_token(short_lived.clone(), public_key, identity.clone()).is_ok(),
            "Short-lived token should verify immediately"
        );
    }

    #[test]
    fn test_short_lived_token_expiration() {
        // Create a base identity token
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let identity = "urn:hessra:test:user".to_string();

        let base_token =
            create_identity_token(identity.clone(), keypair, TokenTimeConfig::default())
                .expect("Failed to create base token");

        // Create a short-lived version
        let short_lived = create_short_lived_identity_token(base_token, public_key)
            .expect("Failed to create short-lived token");

        // Should verify immediately
        assert!(
            verify_identity_token(short_lived.clone(), public_key, identity.clone()).is_ok(),
            "Token should verify immediately after creation"
        );

        // Wait for 6 seconds (token expires in 5)
        thread::sleep(Duration::from_secs(6));

        // Should fail verification after expiration
        assert!(
            verify_identity_token(short_lived, public_key, identity).is_err(),
            "Token should fail verification after 5 seconds"
        );
    }

    #[test]
    fn test_short_lived_preserves_identity() {
        // Create tokens for different identities
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let alice = "urn:hessra:alice".to_string();
        let bob = "urn:hessra:bob".to_string();

        let alice_token = create_identity_token(alice.clone(), keypair, TokenTimeConfig::default())
            .expect("Failed to create alice token");

        // Create short-lived version
        let short_lived = create_short_lived_identity_token(alice_token, public_key)
            .expect("Failed to create short-lived token");

        // Should verify with correct identity
        assert!(
            verify_identity_token(short_lived.clone(), public_key, alice).is_ok(),
            "Should verify with correct identity"
        );

        // Should not verify with different identity
        assert!(
            verify_identity_token(short_lived, public_key, bob).is_err(),
            "Should not verify with different identity"
        );
    }
}
