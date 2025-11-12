extern crate biscuit_auth as biscuit;
use biscuit::macros::{authorizer, fact, policy};
use chrono::Utc;
use hessra_token_core::{parse_check_failure, Biscuit, PublicKey, TokenError};

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
    ensure_subject_in_domain: bool,
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
            ensure_subject_in_domain: false,
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

    /// Ensures that the subject is associated with the domain.
    ///
    /// When set, the token will only verify if the subject is associated with the domain.
    ///
    /// # Arguments
    pub fn ensure_subject_in_domain(mut self) -> Self {
        self.ensure_subject_in_domain = true;
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
        // Parse and verify the token
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;
        let now = Utc::now().timestamp();

        // Store identity and domain for better error messages
        let expected_identity = self.identity.clone();
        let expected_domain = self.domain.clone();

        // Build the base authorizer depending on whether identity is specified
        let mut authz = if let Some(identity) = self.identity {
            // Identity verification: exact actor match
            authorizer!(
                r#"
                    time({now});
                    actor({identity});
                "#
            )
        } else {
            // Bearer token: no specific identity requirement
            authorizer!(
                r#"
                    time({now});
                    actor($a) <- subject($a);
                "#
            )
        };

        // Add domain fact if specified
        if let Some(domain) = self.domain {
            authz = authz.fact(fact!(r#"domain({domain});"#))?;
        }

        // Add policy to ensure that the subject is associated with the domain
        if self.ensure_subject_in_domain {
            authz = authz.policy(policy!(
                r#"
                    allow if subject($d, $s), domain($d), subject($s);
                "#
            ))?;
        } else {
            // Allow if all checks pass
            authz = authz.policy(policy!(
                r#"
                    allow if true;
                "#
            ))?;
        }

        let mut authz = authz
            .build(&biscuit)
            .map_err(|e| TokenError::internal(format!("Failed to build authorizer: {e}")))?;

        // Perform authorization and convert errors to detailed types
        match authz.authorize() {
            Ok(_) => Ok(()),
            Err(e) => Err(convert_identity_verification_error(
                e,
                expected_identity,
                expected_domain,
            )),
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

/// Convert biscuit authorization errors to detailed identity verification errors
fn convert_identity_verification_error(
    err: biscuit::error::Token,
    expected_identity: Option<String>,
    expected_domain: Option<String>,
) -> TokenError {
    use biscuit::error::{Logic, Token};

    match err {
        Token::FailedLogic(logic_err) => match &logic_err {
            Logic::Unauthorized { checks, .. } | Logic::NoMatchingPolicy { checks } => {
                // Try to parse each failed check for more specific errors
                for failed_check in checks.iter() {
                    let (block_id, check_id, rule) = match failed_check {
                        biscuit::error::FailedCheck::Block(block_check) => (
                            block_check.block_id,
                            block_check.check_id,
                            block_check.rule.clone(),
                        ),
                        biscuit::error::FailedCheck::Authorizer(auth_check) => {
                            (0, auth_check.check_id, auth_check.rule.clone())
                        }
                    };

                    // Try to parse the check for specific error types
                    let parsed_error = parse_check_failure(block_id, check_id, &rule);

                    // Enhance errors with context we have
                    let enhanced_error = match &parsed_error {
                        TokenError::DomainMismatch {
                            expected,
                            block_id,
                            check_id,
                            ..
                        } => TokenError::DomainMismatch {
                            expected: expected.clone(),
                            provided: expected_domain.clone(),
                            block_id: *block_id,
                            check_id: *check_id,
                        },
                        TokenError::IdentityMismatch { expected, .. } => {
                            if let Some(identity) = &expected_identity {
                                TokenError::IdentityMismatch {
                                    expected: expected.clone(),
                                    actual: identity.clone(),
                                }
                            } else {
                                return parsed_error;
                            }
                        }
                        TokenError::HierarchyViolation {
                            expected,
                            delegatable,
                            block_id,
                            check_id,
                            ..
                        } => {
                            if let Some(identity) = &expected_identity {
                                TokenError::HierarchyViolation {
                                    expected: expected.clone(),
                                    actual: identity.clone(),
                                    delegatable: *delegatable,
                                    block_id: *block_id,
                                    check_id: *check_id,
                                }
                            } else {
                                return parsed_error;
                            }
                        }
                        // Return first specific error we find
                        TokenError::Expired { .. } | TokenError::CheckFailed { .. } => {
                            return parsed_error
                        }
                        // For other errors, continue to next check
                        _ => continue,
                    };

                    return enhanced_error;
                }

                // If we couldn't parse any specific error, use generic conversion
                TokenError::from(Token::FailedLogic(logic_err))
            }
            other => TokenError::from(Token::FailedLogic(other.clone())),
        },
        other => TokenError::from(other),
    }
}
