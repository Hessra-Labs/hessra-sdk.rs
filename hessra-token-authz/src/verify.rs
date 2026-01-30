extern crate biscuit_auth as biscuit;

use biscuit::datalog::RunLimits;
use biscuit::macros::{authorizer, check, fact};
use biscuit::Algorithm;
use chrono::Utc;
use hessra_token_core::{
    parse_authorization_failure, parse_check_failure, Biscuit, PublicKey, ServiceChainFailure,
    TokenError,
};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceNode {
    pub component: String,
    pub public_key: String,
}

/// Verification mode for authorization tokens.
#[derive(Debug, Clone, PartialEq)]
enum VerificationMode {
    /// Identity-based verification: requires an explicit subject parameter.
    /// The authorizer will check if the token grants rights to this specific subject.
    Identity { subject: String },
    /// Capability-based verification: derives the subject from the token's rights.
    /// The authorizer will accept any token that grants the specified capability
    /// (resource + operation), regardless of the subject.
    Capability,
}

impl VerificationMode {
    /// Returns the subject if in Identity mode, None for Capability mode.
    fn subject(&self) -> Option<&str> {
        match self {
            VerificationMode::Identity { subject } => Some(subject),
            VerificationMode::Capability => None,
        }
    }

    /// Returns the subject if in Identity mode, "unknown" for Capability mode.
    /// Used for error reporting.
    fn subject_or_unknown(&self) -> &str {
        match self {
            VerificationMode::Identity { subject } => subject,
            VerificationMode::Capability => "unknown",
        }
    }
}

/// Builder for verifying Hessra authorization tokens with flexible configuration.
///
/// This builder allows you to configure various verification parameters including
/// optional domain restrictions and service chain attestation.
///
/// # Example
/// ```no_run
/// use hessra_token_authz::{AuthorizationVerifier, ServiceNode, create_token};
/// use hessra_token_core::KeyPair;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a token
/// let keypair = KeyPair::new();
/// let public_key = keypair.public();
/// let token = create_token(
///     "user123".to_string(),
///     "resource456".to_string(),
///     "read".to_string(),
///     keypair,
/// )?;
///
/// // Basic authorization verification
/// AuthorizationVerifier::new(
///     token.clone(),
///     public_key,
///     "user123".to_string(),
///     "resource456".to_string(),
///     "read".to_string(),
/// )
/// .verify()?;
///
/// // With domain restriction
/// AuthorizationVerifier::new(
///     token.clone(),
///     public_key,
///     "user123".to_string(),
///     "resource456".to_string(),
///     "read".to_string(),
/// )
/// .with_domain("example.com".to_string())
/// .verify()?;
///
/// // With service chain attestation
/// let service_nodes = vec![
///     ServiceNode {
///         component: "api-gateway".to_string(),
///         public_key: "ed25519/abcd1234...".to_string(),
///     }
/// ];
/// AuthorizationVerifier::new(
///     token,
///     public_key,
///     "user123".to_string(),
///     "resource456".to_string(),
///     "read".to_string(),
/// )
/// .with_service_chain(service_nodes, Some("api-gateway".to_string()))
/// .verify()?;
/// # Ok(())
/// # }
/// ```
pub struct AuthorizationVerifier {
    token: String,
    public_key: PublicKey,
    mode: VerificationMode,
    resource: String,
    operation: String,
    domain: Option<String>,
    prefix: Option<String>,
    service_chain: Option<(Vec<ServiceNode>, Option<String>)>,
}

impl AuthorizationVerifier {
    /// Creates a new authorization verifier for a base64-encoded token.
    ///
    /// # Arguments
    /// * `token` - The base64-encoded authorization token to verify
    /// * `public_key` - The public key used to verify the token signature
    /// * `subject` - The subject (user) identifier to verify authorization for
    /// * `resource` - The resource identifier to verify authorization against
    /// * `operation` - The operation to verify authorization for
    pub fn new(
        token: String,
        public_key: PublicKey,
        subject: String,
        resource: String,
        operation: String,
    ) -> Self {
        Self {
            token,
            public_key,
            mode: VerificationMode::Identity { subject },
            resource,
            operation,
            domain: None,
            prefix: None,
            service_chain: None,
        }
    }

    /// Creates a new authorization verifier from raw token bytes.
    ///
    /// # Arguments
    /// * `token` - The raw binary Biscuit token bytes
    /// * `public_key` - The public key used to verify the token signature
    /// * `subject` - The subject (user) identifier to verify authorization for
    /// * `resource` - The resource identifier to verify authorization against
    /// * `operation` - The operation to verify authorization for
    pub fn from_bytes(
        token: Vec<u8>,
        public_key: PublicKey,
        subject: String,
        resource: String,
        operation: String,
    ) -> Result<Self, TokenError> {
        // Convert bytes to base64 for internal storage
        let biscuit = Biscuit::from(&token, public_key)?;
        let token_string = biscuit
            .to_base64()
            .map_err(|e| TokenError::generic(format!("Failed to encode token: {e}")))?;
        Ok(Self {
            token: token_string,
            public_key,
            mode: VerificationMode::Identity { subject },
            resource,
            operation,
            domain: None,
            prefix: None,
            service_chain: None,
        })
    }

    /// Creates a new capability-based verifier (no subject required).
    ///
    /// This verifier will accept any token that grants the specified capability
    /// (resource + operation), regardless of the subject. The subject is derived
    /// from the token's rights instead of being provided explicitly.
    ///
    /// # Arguments
    /// * `token` - The base64-encoded authorization token to verify
    /// * `public_key` - The public key used to verify the token signature
    /// * `resource` - The resource identifier to verify authorization against
    /// * `operation` - The operation to verify authorization for
    pub fn new_capability(
        token: String,
        public_key: PublicKey,
        resource: String,
        operation: String,
    ) -> Self {
        Self {
            token,
            public_key,
            mode: VerificationMode::Capability,
            resource,
            operation,
            domain: None,
            prefix: None,
            service_chain: None,
        }
    }

    /// Creates a new capability-based verifier from raw token bytes.
    ///
    /// This is the binary token version of `new_capability`. It accepts any token
    /// that grants the specified capability (resource + operation), regardless of
    /// the subject.
    ///
    /// # Arguments
    /// * `token` - The raw binary Biscuit token bytes
    /// * `public_key` - The public key used to verify the token signature
    /// * `resource` - The resource identifier to verify authorization against
    /// * `operation` - The operation to verify authorization for
    pub fn from_bytes_capability(
        token: Vec<u8>,
        public_key: PublicKey,
        resource: String,
        operation: String,
    ) -> Result<Self, TokenError> {
        let biscuit = Biscuit::from(&token, public_key)?;
        let token_string = biscuit
            .to_base64()
            .map_err(|e| TokenError::generic(format!("Failed to encode token: {e}")))?;
        Ok(Self {
            token: token_string,
            public_key,
            mode: VerificationMode::Capability,
            resource,
            operation,
            domain: None,
            prefix: None,
            service_chain: None,
        })
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

    /// Adds a prefix restriction to the verification.
    ///
    /// When set, adds a prefix fact to the authorizer. This is required for
    /// verifying prefix-restricted tokens.
    ///
    /// # Arguments
    /// * `prefix` - The prefix to verify against (e.g., "tenant/TENANTID/user/USERID/")
    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Adds service chain attestation verification.
    ///
    /// When set, verifies that the token has been properly attested by the
    /// specified service chain nodes.
    ///
    /// # Arguments
    /// * `service_nodes` - The list of service nodes in the chain
    /// * `component` - Optional specific component to verify in the chain
    pub fn with_service_chain(
        mut self,
        service_nodes: Vec<ServiceNode>,
        component: Option<String>,
    ) -> Self {
        self.service_chain = Some((service_nodes, component));
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
    /// - The token does not grant the required access rights
    /// - The domain doesn't match (if domain restriction is set on token)
    /// - Service chain attestation fails (if service chain is configured)
    pub fn verify(self) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;

        if let Some((service_nodes, component)) = self.service_chain {
            // Service chain verification
            verify_raw_service_chain_biscuit(
                biscuit,
                self.mode,
                self.resource,
                self.operation,
                service_nodes,
                component,
                self.domain,
                self.prefix,
            )
        } else {
            // Basic verification
            verify_raw_biscuit(
                biscuit,
                self.mode,
                self.resource,
                self.operation,
                self.domain,
                self.prefix,
            )
        }
    }
}

pub(crate) fn build_base_authorizer(
    subject: String,
    resource: String,
    operation: String,
    domain: Option<String>,
    prefix: Option<String>,
) -> Result<biscuit::AuthorizerBuilder, TokenError> {
    let now = Utc::now().timestamp();

    let mut authz = authorizer!(
        r#"
            time({now});
            resource({resource});
            subject({subject});
            operation({operation});
            allow if true;
        "#
    );

    // Add domain fact if specified
    if let Some(domain) = domain {
        authz = authz.fact(fact!(r#"domain({domain});"#))?;
    }

    // Add prefix fact if specified
    if let Some(prefix) = prefix {
        authz = authz.fact(fact!(r#"prefix({prefix});"#))?;
    }

    Ok(authz)
}

/// Build a capability-based authorizer that derives the subject from the token's rights.
///
/// Unlike `build_base_authorizer`, this function does not require a subject parameter.
/// Instead, it uses a Datalog rule to derive the subject from any `right(subject, resource, operation)`
/// facts present in the token. This allows verification based solely on capability (resource + operation)
/// without needing to know the identity.
pub(crate) fn build_capability_authorizer(
    resource: String,
    operation: String,
    domain: Option<String>,
    prefix: Option<String>,
) -> Result<biscuit::AuthorizerBuilder, TokenError> {
    let now = Utc::now().timestamp();

    let mut authz = authorizer!(
        r#"
            time({now});
            resource({resource});
            operation({operation});
            // Derive subject from the token's rights instead of providing it explicitly
            subject($sub) <- right($sub, {resource}, {operation});
            allow if true;
        "#
    );

    // Add domain fact if specified
    if let Some(domain) = domain {
        authz = authz.fact(fact!(r#"domain({domain});"#))?;
    }

    // Add prefix fact if specified
    if let Some(prefix) = prefix {
        authz = authz.fact(fact!(r#"prefix({prefix});"#))?;
    }

    Ok(authz)
}

fn verify_raw_biscuit(
    biscuit: Biscuit,
    mode: VerificationMode,
    resource: String,
    operation: String,
    domain: Option<String>,
    prefix: Option<String>,
) -> Result<(), TokenError> {
    let authz = match &mode {
        VerificationMode::Identity { subject } => build_base_authorizer(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            domain.clone(),
            prefix.clone(),
        )?,
        VerificationMode::Capability => build_capability_authorizer(
            resource.clone(),
            operation.clone(),
            domain.clone(),
            prefix.clone(),
        )?,
    };

    match authz.build(&biscuit)?.authorize() {
        Ok(_) => Ok(()),
        Err(e) => Err(convert_authorization_error(
            e,
            mode.subject(),
            Some(&resource),
            Some(&operation),
            domain.as_deref(),
            prefix.as_deref(),
        )),
    }
}

/// Verifies a Biscuit authorization token locally without contacting the authorization server.
///
/// This function performs local verification of a Biscuit token using the provided public key.
/// It validates that the token grants access to the specified resource for the given subject.
///
/// # Arguments
///
/// * `token` - The binary Biscuit token bytes (typically decoded from Base64)
/// * `public_key` - The public key used to verify the token signature
/// * `subject` - The subject (user) identifier to verify authorization for
/// * `resource` - The resource identifier to verify authorization against
/// * `operation` - The operation to verify authorization for
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access to the resource
/// * `Err(TokenError)` - If verification fails for any reason
///
/// # Errors
///
/// Returns an error if:
/// - The token is malformed or cannot be parsed
/// - The token signature is invalid
/// - The token does not grant the required access rights
/// - The token has expired or other authorization checks fail
pub fn verify_biscuit_local(
    token: Vec<u8>,
    public_key: PublicKey,
    subject: String,
    resource: String,
    operation: String,
) -> Result<(), TokenError> {
    AuthorizationVerifier::from_bytes(token, public_key, subject, resource, operation)?.verify()
}

/// Verifies a Biscuit authorization token locally without contacting the authorization server.
///
/// This function performs local verification of a Biscuit token using the provided public key.
/// It validates that the token grants access to the specified resource for the given subject.
///
/// # Arguments
///
/// * `token` - The base64-encoded Biscuit token string
/// * `public_key` - The public key used to verify the token signature
/// * `subject` - The subject (user) identifier to verify authorization for
/// * `resource` - The resource identifier to verify authorization against
/// * `operation` - The operation to verify authorization for
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access to the resource
/// * `Err(TokenError)` - If verification fails for any reason
///
/// # Errors
///
/// Returns an error if:
/// - The token is malformed or cannot be parsed
/// - The token signature is invalid
/// - The token does not grant the required access rights
/// - The token has expired or other authorization checks fail
pub fn verify_token_local(
    token: &str,
    public_key: PublicKey,
    subject: &str,
    resource: &str,
    operation: &str,
) -> Result<(), TokenError> {
    AuthorizationVerifier::new(
        token.to_string(),
        public_key,
        subject.to_string(),
        resource.to_string(),
        operation.to_string(),
    )
    .verify()
}

/// Takes a public key encoded as a string in the format "ed25519/..." or "secp256r1/..."
/// and returns a PublicKey.
pub fn biscuit_key_from_string(key: String) -> Result<PublicKey, TokenError> {
    let parts = key.split('/').collect::<Vec<&str>>();
    if parts.len() != 2 {
        return Err(TokenError::invalid_key_format(
            "Key must be in format 'algorithm/hexkey'",
        ));
    }

    let alg = match parts[0] {
        "ed25519" => Algorithm::Ed25519,
        "secp256r1" => Algorithm::Secp256r1,
        _ => {
            return Err(TokenError::invalid_key_format(
                "Unsupported algorithm, must be ed25519 or secp256r1",
            ))
        }
    };

    // decode the key from hex
    let key_bytes = hex::decode(parts[1])?;

    // construct the public key
    let key = PublicKey::from_bytes(&key_bytes, alg)
        .map_err(|e| TokenError::invalid_key_format(e.to_string()))?;

    Ok(key)
}

#[allow(clippy::too_many_arguments)]
fn verify_raw_service_chain_biscuit(
    biscuit: Biscuit,
    mode: VerificationMode,
    resource: String,
    operation: String,
    service_nodes: Vec<ServiceNode>,
    component: Option<String>,
    domain: Option<String>,
    prefix: Option<String>,
) -> Result<(), TokenError> {
    let mut authz = match &mode {
        VerificationMode::Identity { subject } => build_base_authorizer(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            domain.clone(),
            prefix.clone(),
        )?,
        VerificationMode::Capability => {
            build_capability_authorizer(resource.clone(), operation.clone(), domain.clone(), prefix.clone())?
        }
    };

    let mut component_found = false;
    if component.is_none() {
        component_found = true;
    }
    for service_node in &service_nodes {
        if let Some(ref component) = component {
            if component == &service_node.component {
                component_found = true;
                break;
            }
        }
        let service = resource.clone();
        let node_name = service_node.component.clone();
        let node_key = biscuit_key_from_string(service_node.public_key.clone())?;
        authz = authz.check(check!(
            r#"
                check if node({service}, {node_name}) trusting authority, {node_key};
            "#
        ))?;
    }

    if let Some(ref component_name) = component {
        if !component_found {
            return Err(TokenError::ServiceChainFailed {
                component: component_name.clone(),
                reason: ServiceChainFailure::ComponentNotFound,
            });
        }
    }

    // Service chain verification evaluates additional Datalog checks for each
    // node in the chain. This can exceed default time limits on slower systems,
    // so we use extended limits here (default is 1ms, we use 10ms).
    let service_chain_limits = RunLimits {
        max_time: Duration::from_millis(10),
        ..Default::default()
    };
    match authz
        .build(&biscuit)?
        .authorize_with_limits(service_chain_limits)
    {
        Ok(_) => Ok(()),
        Err(e) => Err(convert_service_chain_error(
            e,
            mode.subject_or_unknown(),
            &resource,
            &operation,
            service_nodes,
            domain.as_deref(),
        )),
    }
}

pub fn verify_service_chain_biscuit_local(
    token: Vec<u8>,
    public_key: PublicKey,
    subject: String,
    resource: String,
    operation: String,
    service_nodes: Vec<ServiceNode>,
    component: Option<String>,
) -> Result<(), TokenError> {
    AuthorizationVerifier::from_bytes(token, public_key, subject, resource, operation)?
        .with_service_chain(service_nodes, component)
        .verify()
}

pub fn verify_service_chain_token_local(
    token: &str,
    public_key: PublicKey,
    subject: &str,
    resource: &str,
    operation: &str,
    service_nodes: Vec<ServiceNode>,
    component: Option<String>,
) -> Result<(), TokenError> {
    AuthorizationVerifier::new(
        token.to_string(),
        public_key,
        subject.to_string(),
        resource.to_string(),
        operation.to_string(),
    )
    .with_service_chain(service_nodes, component)
    .verify()
}

/// Verifies a Biscuit authorization token based on capability (resource + operation) only.
///
/// This function performs capability-based verification without requiring a subject parameter.
/// The subject is derived from the token's rights - any subject that has the specified right
/// for the resource and operation will satisfy verification.
///
/// This is useful for services that only care about authorization for an action, not identity.
/// For example, a telemetry service that only needs to verify write permission, not who is writing.
///
/// # Arguments
///
/// * `token` - The base64-encoded Biscuit token string
/// * `public_key` - The public key used to verify the token signature
/// * `resource` - The resource identifier to verify authorization against
/// * `operation` - The operation to verify authorization for
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access to the resource+operation
/// * `Err(TokenError)` - If verification fails
///
/// # Example
///
/// ```no_run
/// use hessra_token_authz::{verify_capability_token_local, create_token};
/// use hessra_token_core::{KeyPair, TokenError};
///
/// let keypair = KeyPair::new();
/// let public_key = keypair.public();
///
/// // Create a token for alice to read resource1
/// let token = create_token(
///     "alice".to_string(),
///     "resource1".to_string(),
///     "read".to_string(),
///     keypair,
/// )
/// .map_err(|e| TokenError::Generic(e.to_string()))?;
///
/// // Verify capability without caring about the subject
/// verify_capability_token_local(&token, public_key, "resource1", "read")?;
/// # Ok::<(), hessra_token_core::TokenError>(())
/// ```
pub fn verify_capability_token_local(
    token: &str,
    public_key: PublicKey,
    resource: &str,
    operation: &str,
) -> Result<(), TokenError> {
    AuthorizationVerifier::new_capability(
        token.to_string(),
        public_key,
        resource.to_string(),
        operation.to_string(),
    )
    .verify()
}

/// Verifies a Biscuit authorization token based on capability (resource + operation) only.
///
/// This is the binary token version of `verify_capability_token_local`.
///
/// # Arguments
///
/// * `token` - The binary Biscuit token bytes
/// * `public_key` - The public key used to verify the token signature
/// * `resource` - The resource identifier to verify authorization against
/// * `operation` - The operation to verify authorization for
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access to the resource+operation
/// * `Err(TokenError)` - If verification fails
pub fn verify_capability_biscuit_local(
    token: Vec<u8>,
    public_key: PublicKey,
    resource: String,
    operation: String,
) -> Result<(), TokenError> {
    AuthorizationVerifier::from_bytes_capability(token, public_key, resource, operation)?.verify()
}

/// Verifies a service chain token based on capability without requiring subject.
///
/// This combines service chain attestation verification with capability-based verification.
/// The token must have the required service chain attestations and grant the specified
/// capability (resource + operation), but the subject is derived from the token rather
/// than being provided explicitly.
///
/// # Arguments
///
/// * `token` - The base64-encoded Biscuit token string
/// * `public_key` - The public key used to verify the token signature
/// * `resource` - The resource identifier to verify authorization against
/// * `operation` - The operation to verify authorization for
/// * `service_nodes` - The list of service nodes in the chain
/// * `component` - Optional specific component to verify in the chain
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access
/// * `Err(TokenError)` - If verification fails
pub fn verify_service_chain_capability_token_local(
    token: &str,
    public_key: PublicKey,
    resource: &str,
    operation: &str,
    service_nodes: Vec<ServiceNode>,
    component: Option<String>,
) -> Result<(), TokenError> {
    AuthorizationVerifier::new_capability(
        token.to_string(),
        public_key,
        resource.to_string(),
        operation.to_string(),
    )
    .with_service_chain(service_nodes, component)
    .verify()
}

/// Binary version of `verify_service_chain_capability_token_local`.
///
/// Verifies a service chain token from raw bytes based on capability without requiring subject.
///
/// # Arguments
///
/// * `token` - The binary Biscuit token bytes
/// * `public_key` - The public key used to verify the token signature
/// * `resource` - The resource identifier to verify authorization against
/// * `operation` - The operation to verify authorization for
/// * `service_nodes` - The list of service nodes in the chain
/// * `component` - Optional specific component to verify in the chain
///
/// # Returns
///
/// * `Ok(())` - If the token is valid and grants access
/// * `Err(TokenError)` - If verification fails
pub fn verify_service_chain_capability_biscuit_local(
    token: Vec<u8>,
    public_key: PublicKey,
    resource: String,
    operation: String,
    service_nodes: Vec<ServiceNode>,
    component: Option<String>,
) -> Result<(), TokenError> {
    AuthorizationVerifier::from_bytes_capability(token, public_key, resource, operation)?
        .with_service_chain(service_nodes, component)
        .verify()
}

/// Convert biscuit authorization errors to detailed authorization errors
fn convert_authorization_error(
    err: biscuit::error::Token,
    subject: Option<&str>,
    resource: Option<&str>,
    operation: Option<&str>,
    domain: Option<&str>,
    _prefix: Option<&str>,
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

                    // Enhance domain errors with context we have
                    match parsed_error {
                        TokenError::DomainMismatch {
                            expected,
                            block_id,
                            check_id,
                            ..
                        } => {
                            return TokenError::DomainMismatch {
                                expected,
                                provided: domain.map(|s| s.to_string()),
                                block_id,
                                check_id,
                            };
                        }
                        TokenError::Expired { .. } => return parsed_error,
                        _ => {}
                    }
                }

                // Check if this looks like a rights denial (no matching policy)
                if matches!(logic_err, Logic::NoMatchingPolicy { .. }) {
                    return parse_authorization_failure(
                        subject,
                        resource,
                        operation,
                        &format!("{checks:?}"),
                    );
                }

                // If we couldn't parse any specific error, use generic conversion
                TokenError::from(Token::FailedLogic(logic_err))
            }
            other => TokenError::from(Token::FailedLogic(other.clone())),
        },
        other => TokenError::from(other),
    }
}

/// Convert biscuit authorization errors to service chain specific errors
fn convert_service_chain_error(
    err: biscuit::error::Token,
    subject: &str,
    resource: &str,
    operation: &str,
    service_nodes: Vec<ServiceNode>,
    domain: Option<&str>,
) -> TokenError {
    use biscuit::error::{Logic, Token};

    match err {
        Token::FailedLogic(logic_err) => match &logic_err {
            Logic::Unauthorized { checks, .. } | Logic::NoMatchingPolicy { checks } => {
                // Check if any failure is service chain related
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

                    // Check if this is a service chain check (contains "node(")
                    if rule.contains("node(") {
                        // Try to extract component name from the rule
                        for service_node in &service_nodes {
                            if rule.contains(&service_node.component) {
                                return TokenError::ServiceChainFailed {
                                    component: service_node.component.clone(),
                                    reason: ServiceChainFailure::MissingAttestation,
                                };
                            }
                        }

                        // Generic service chain failure
                        return TokenError::ServiceChainFailed {
                            component: resource.to_string(),
                            reason: ServiceChainFailure::Other(
                                "Service chain attestation check failed".to_string(),
                            ),
                        };
                    }

                    // Check for other specific error types
                    let parsed_error = parse_check_failure(block_id, check_id, &rule);
                    match parsed_error {
                        TokenError::DomainMismatch {
                            expected,
                            block_id,
                            check_id,
                            ..
                        } => {
                            return TokenError::DomainMismatch {
                                expected,
                                provided: domain.map(|s| s.to_string()),
                                block_id,
                                check_id,
                            };
                        }
                        TokenError::Expired { .. } => return parsed_error,
                        _ => {}
                    }
                }

                // Fallback to authorization error
                parse_authorization_failure(
                    Some(subject),
                    Some(resource),
                    Some(operation),
                    &format!("{checks:?}"),
                )
            }
            other => TokenError::from(Token::FailedLogic(other.clone())),
        },
        other => TokenError::from(other),
    }
}
