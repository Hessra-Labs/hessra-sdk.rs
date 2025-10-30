extern crate biscuit_auth as biscuit;

use biscuit::macros::{authorizer, check, fact};
use biscuit::Algorithm;
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceNode {
    pub component: String,
    pub public_key: String,
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
    subject: String,
    resource: String,
    operation: String,
    domain: Option<String>,
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
            subject,
            resource,
            operation,
            domain: None,
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
            subject,
            resource,
            operation,
            domain: None,
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
                self.subject,
                self.resource,
                self.operation,
                service_nodes,
                component,
                self.domain,
            )
        } else {
            // Basic verification
            verify_raw_biscuit(
                biscuit,
                self.subject,
                self.resource,
                self.operation,
                self.domain,
            )
        }
    }
}

pub(crate) fn build_base_authorizer(
    subject: String,
    resource: String,
    operation: String,
    domain: Option<String>,
) -> Result<biscuit::AuthorizerBuilder, TokenError> {
    let now = Utc::now().timestamp();

    let mut authz = authorizer!(
        r#"
            time({now});
            resource({resource});
            subject({subject});
            operation({operation});
            allow if subject($sub), resource($res), operation($op), right($sub, $res, $op);
        "#
    );

    // Add domain fact if specified
    if let Some(domain) = domain {
        authz = authz.fact(fact!(r#"domain({domain});"#))?;
    }

    Ok(authz)
}

fn verify_raw_biscuit(
    biscuit: Biscuit,
    subject: String,
    resource: String,
    operation: String,
    domain: Option<String>,
) -> Result<(), TokenError> {
    let authz = build_base_authorizer(subject, resource, operation, domain)?;
    if authz.build(&biscuit)?.authorize().is_ok() {
        Ok(())
    } else {
        Err(TokenError::authorization_error(
            "Token does not grant required access rights",
        ))
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

fn verify_raw_service_chain_biscuit(
    biscuit: Biscuit,
    subject: String,
    resource: String,
    operation: String,
    service_nodes: Vec<ServiceNode>,
    component: Option<String>,
    domain: Option<String>,
) -> Result<(), TokenError> {
    let mut authz = build_base_authorizer(subject, resource.clone(), operation, domain)?;

    let mut component_found = false;
    if component.is_none() {
        component_found = true;
    }
    for service_node in service_nodes {
        if let Some(ref component) = component {
            if component == &service_node.component {
                component_found = true;
                break;
            }
        }
        let service = resource.clone();
        let node_name = service_node.component;
        let node_key = biscuit_key_from_string(service_node.public_key)?;
        authz = authz.check(check!(
            r#"
                check if node({service}, {node_name}) trusting authority, {node_key};
            "#
        ))?;
    }

    if let Some(ref component) = component {
        if !component_found {
            return Err(TokenError::authorization_error(format!(
                "Token does not grant required access rights. missing {}",
                component.clone()
            )));
        }
    }

    if authz.build(&biscuit)?.authorize().is_ok() {
        Ok(())
    } else {
        Err(TokenError::authorization_error(
            "Token does not grant required access rights",
        ))
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
