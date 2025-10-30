extern crate biscuit_auth as biscuit;
use biscuit::macros::{authorizer, fact};
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError};

/// Builder for verifying Hessra identity tokens with flexible configuration.
///
/// This builder allows you to configure various verification parameters including
/// optional identity matching and domain restrictions.
///
/// # Example
/// ```no_run
/// use hessra_token_identity::{IdentityVerifier, create_identity_token};
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a token
/// let keypair = KeyPair::new();
/// let public_key = keypair.public();
/// let subject = "urn:hessra:alice".to_string();
/// let token = create_identity_token(subject.clone(), keypair, TokenTimeConfig::default())?;
///
/// // Verify as bearer token (no identity check)
/// IdentityVerifier::new(token.clone(), public_key)
///     .verify()?;
///
/// // Verify with specific identity
/// IdentityVerifier::new(token.clone(), public_key)
///     .with_identity(subject.clone())
///     .verify()?;
///
/// // Verify with identity and domain restriction
/// IdentityVerifier::new(token, public_key)
///     .with_identity(subject)
///     .with_domain("example.com".to_string())
///     .verify()?;
/// # Ok(())
/// # }
/// ```
pub struct IdentityVerifier {
    token: String,
    public_key: PublicKey,
    identity: Option<String>,
    domain: Option<String>,
}

impl IdentityVerifier {
    /// Creates a new identity verifier for the given token and public key.
    ///
    /// # Arguments
    /// * `token` - The base64-encoded identity token to verify
    /// * `public_key` - The public key used to verify the token signature
    pub fn new(token: String, public_key: PublicKey) -> Self {
        Self {
            token,
            public_key,
            identity: None,
            domain: None,
        }
    }

    /// Adds an identity requirement to the verification.
    ///
    /// When set, the token will only verify if the actor matches this identity.
    /// Without this, the token is verified as a bearer token (no identity check).
    ///
    /// # Arguments
    /// * `identity` - The identity to verify against (e.g., "urn:hessra:alice")
    pub fn with_identity(mut self, identity: String) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Adds a domain restriction to the verification.
    ///
    /// When set, adds a domain fact to the authorizer. This is required for
    /// verifying domain-restricted tokens.
    ///
    /// # Arguments
    /// * `domain` - The domain to verify against (e.g., "example.com")
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Performs the token verification with the configured parameters.
    ///
    /// # Returns
    /// * `Ok(())` - If the token is valid and meets all verification requirements
    /// * `Err(TokenError)` - If verification fails for any reason
    ///
    /// # Errors
    /// Returns an error if:
    /// - The token is malformed or cannot be parsed
    /// - The token signature is invalid
    /// - The token has expired
    /// - The identity doesn't match (if identity verification is enabled)
    /// - The domain doesn't match (if domain restriction is set on token)
    pub fn verify(self) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)
            .map_err(TokenError::biscuit_error)?;
        let now = Utc::now().timestamp();

        // Build the base authorizer depending on whether identity is specified
        let mut authz = if let Some(identity) = self.identity {
            // Identity verification: exact actor match
            authorizer!(
                r#"
                    time({now});
                    actor({identity});

                    // Allow if all checks pass
                    allow if true;
                "#
            )
        } else {
            // Bearer token: no specific identity requirement
            authorizer!(
                r#"
                    time({now});
                    actor($a) <- subject($a);

                    // Allow if all checks pass
                    allow if true;
                "#
            )
        };

        // Add domain fact if specified
        if let Some(domain) = self.domain {
            authz = authz.fact(fact!(r#"domain({domain});"#))?;
        }

        let mut authz = authz
            .build(&biscuit)
            .map_err(|e| TokenError::identity_error(format!("Failed to build authorizer: {e}")))?;

        match authz.authorize() {
            Ok(_) => Ok(()),
            Err(e) => Err(TokenError::identity_error(format!(
                "Identity verification failed: {e}"
            ))),
        }
    }
}

/// Verifies the token as a bearer token. This validates the expiration and the signature of the token, but does not check the identity.
pub fn verify_bearer_token(token: String, public_key: PublicKey) -> Result<(), TokenError> {
    IdentityVerifier::new(token, public_key).verify()
}

/// Verifies the token as an identity token. This validates the expiration, the signature of the token, and the identity of the token.
pub fn verify_identity_token(
    token: String,
    public_key: PublicKey,
    identity: String,
) -> Result<(), TokenError> {
    IdentityVerifier::new(token, public_key)
        .with_identity(identity)
        .verify()
}
