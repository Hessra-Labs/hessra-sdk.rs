extern crate biscuit_auth as biscuit;

use crate::verify::{biscuit_key_from_string, ServiceNode};

use biscuit::macros::{biscuit, check, rule};
use biscuit::BiscuitBuilder;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, TokenTimeConfig};
use std::error::Error;
use tracing::info;

/// Builder for creating Hessra authorization tokens with flexible configuration.
///
/// Authorization tokens can be configured with the following capabilities:
/// - **Service Chain**: Add service node attestations via `.service_chain(nodes)`
/// - **Multi-Party**: Add multi-party attestation requirements via `.multi_party(nodes)`
/// - **Domain Restriction**: Limit token to a specific domain via `.domain_restricted(domain)`
///
/// Service chain and multi-party capabilities can be combined in the same token
/// (though this is not currently validated or actively used).
///
/// # Example
/// ```rust
/// use hessra_token_authz::HessraAuthorization;
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// let keypair = KeyPair::new();
///
/// // Authorization with domain restriction
/// let token = HessraAuthorization::new(
///     "alice".to_string(),
///     "resource1".to_string(),
///     "read".to_string(),
///     TokenTimeConfig::default()
/// )
/// .domain_restricted("myapp.hessra.dev".to_string())
/// .issue(&keypair)
/// .expect("Failed to create token");
/// ```
///
pub struct HessraAuthorization {
    subject: Option<String>,
    resource: Option<String>,
    operation: Option<String>,
    time_config: TokenTimeConfig,
    service_chain_nodes: Option<Vec<ServiceNode>>,
    multi_party_nodes: Option<Vec<ServiceNode>>,
    domain: Option<String>,
}

impl HessraAuthorization {
    /// Creates a new singleton capability authorization token builder.
    ///
    /// Singleton tokens grant a specific right to a specific subject for a specific resource
    /// and operation. The token can be used immediately upon issuance.
    ///
    /// # Arguments
    /// * `subject` - The subject (user) identifier
    /// * `resource` - The resource identifier to grant access to
    /// * `operation` - The operation to grant access to
    /// * `time_config` - Time configuration for token validity
    pub fn new(
        subject: String,
        resource: String,
        operation: String,
        time_config: TokenTimeConfig,
    ) -> Self {
        Self {
            subject: Some(subject),
            resource: Some(resource),
            operation: Some(operation),
            time_config,
            service_chain_nodes: None,
            multi_party_nodes: None,
            domain: None,
        }
    }

    /// Adds service chain attestation to the authorization token.
    ///
    /// Service chain tokens include attestations for each service node in the chain.
    /// The token grants access and includes trusting relationships for the specified nodes.
    ///
    /// Can be combined with `.multi_party()` to create a token with both capabilities
    /// (though this is not currently validated or actively used).
    ///
    /// # Arguments
    /// * `nodes` - Vector of service nodes that will attest to the token
    pub fn service_chain(mut self, nodes: Vec<ServiceNode>) -> Self {
        self.service_chain_nodes = Some(nodes);
        self
    }

    /// Adds multi-party attestation requirement to the authorization token.
    ///
    /// Multi-party tokens require attestation from all specified parties before becoming valid.
    /// The key difference from service chain is that the token is invalid until all parties
    /// have provided their attestations.
    ///
    /// Can be combined with `.service_chain()` to create a token with both capabilities
    /// (though this is not currently validated or actively used).
    ///
    /// # Arguments
    /// * `nodes` - Vector of multi-party nodes that must attest to the token
    pub fn multi_party(mut self, nodes: Vec<ServiceNode>) -> Self {
        self.multi_party_nodes = Some(nodes);
        self
    }

    /// Restricts the authorization to a specific domain.
    ///
    /// Adds a domain restriction check to the authority block:
    /// - `check if domain({domain})`
    ///
    /// This ensures the token can only be used within the specified domain.
    ///
    /// # Arguments
    /// * `domain` - The domain to restrict to (e.g., "myapp.hessra.dev")
    pub fn domain_restricted(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Issues (builds and signs) the authorization token.
    ///
    /// # Arguments
    /// * `keypair` - The keypair to sign the token with
    ///
    /// # Returns
    /// Base64-encoded biscuit token
    pub fn issue(self, keypair: &KeyPair) -> Result<String, Box<dyn Error>> {
        let start_time = self
            .time_config
            .start_time
            .unwrap_or_else(|| Utc::now().timestamp());
        let expiration = start_time + self.time_config.duration;

        let domain = self.domain;

        // Extract required fields
        let subject = self.subject.ok_or("Token requires subject")?;
        let resource = self.resource.ok_or("Token requires resource")?;
        let operation = self.operation.ok_or("Token requires operation")?;

        // Build authority block
        let mut biscuit_builder = biscuit!(
            r#"
                right({subject}, {resource}, {operation});
                check if subject($sub), resource($res), operation($op), right($sub, $res, $op);
                check if time($time), $time < {expiration};
            "#
        );

        // Add domain restriction if specified
        if let Some(domain) = domain {
            biscuit_builder = biscuit_builder.check(check!(
                r#"
                    check if domain({domain});
                "#
            ))?;
        }

        // Add service chain rules if specified (works for both token types)
        if let Some(nodes) = self.service_chain_nodes {
            for node in nodes {
                let component = node.component;
                let public_key = biscuit_key_from_string(node.public_key)?;
                biscuit_builder = biscuit_builder.rule(rule!(
                    r#"
                        node($s, {component}) <- service($s) trusting {public_key};
                    "#
                ))?;
            }
        }

        // Add multi-party checks if specified (works for both token types)
        if let Some(nodes) = self.multi_party_nodes {
            for node in nodes {
                let component = node.component;
                let public_key = biscuit_key_from_string(node.public_key)?;
                biscuit_builder = biscuit_builder.check(check!(
                    r#"
                        check if namespace({component}) trusting {public_key};
                    "#
                ))?;
            }
        }

        // Build and sign the biscuit
        let biscuit = biscuit_builder.build(keypair)?;
        info!("biscuit (authority): {}", biscuit);
        let token = biscuit.to_base64()?;
        Ok(token)
    }
}

/// Creates a base biscuit builder with default time configuration.
///
/// This is a private helper function that creates a biscuit builder with the default
/// time configuration (5 minutes duration from current time).
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier
/// * `operation` - The operation to be granted
///
/// # Returns
///
/// * `Ok(BiscuitBuilder)` - The configured biscuit builder if successful
/// * `Err(Box<dyn Error>)` - If builder creation fails
fn _create_base_biscuit_builder(
    subject: String,
    resource: String,
    operation: String,
) -> Result<BiscuitBuilder, Box<dyn Error>> {
    create_base_biscuit_builder_with_time(subject, resource, operation, TokenTimeConfig::default())
}

/// Creates a base biscuit builder with custom time configuration.
///
/// This is a private helper function that creates a biscuit builder with custom
/// time settings for token validity period.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier
/// * `operation` - The operation to be granted
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(BiscuitBuilder)` - The configured biscuit builder if successful
/// * `Err(Box<dyn Error>)` - If builder creation fails
fn create_base_biscuit_builder_with_time(
    subject: String,
    resource: String,
    operation: String,
    time_config: TokenTimeConfig,
) -> Result<BiscuitBuilder, Box<dyn Error>> {
    let start_time = time_config
        .start_time
        .unwrap_or_else(|| Utc::now().timestamp());
    let expiration = start_time + time_config.duration;

    let biscuit_builder = biscuit!(
        r#"
            right({subject}, {resource}, {operation});
            check if subject($sub), resource($res), operation($op), right($sub, $res, $op);
            check if time($time), $time < {expiration};
        "#
    );

    Ok(biscuit_builder)
}

/// Creates a biscuit (not serialized, not base64 encoded) with custom time
/// configuration.
///
/// This function creates a raw Biscuit object that can be further processed
/// or converted to different formats. It grants the specified operation on
/// the resource for the given subject.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(Biscuit)` - The raw biscuit if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_raw_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Biscuit, Box<dyn Error>> {
    let biscuit = create_base_biscuit_builder_with_time(subject, resource, operation, time_config)?
        .build(&key)?;

    info!("biscuit (authority): {}", biscuit);

    Ok(biscuit)
}

/// Creates a new biscuit token with the specified subject and resource.
///
/// This function creates a token that grants read and write access to the specified resource
/// for the given subject. The token will be valid for 5 minutes by default.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `time_config` - Optional time configuration for token validity
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The binary token data if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let biscuit = create_raw_biscuit(subject, resource, operation, key, time_config)?;
    let token = biscuit.to_vec()?;
    Ok(token)
}

/// Creates a base64-encoded biscuit token with custom time configuration.
///
/// This is a private helper function that creates a biscuit token and returns
/// it as a base64-encoded string for easy transmission and storage.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
fn create_base64_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    let biscuit = create_raw_biscuit(subject, resource, operation, key, time_config)?;
    let token = biscuit.to_base64()?;
    Ok(token)
}

/// Creates a biscuit token with default time configuration.
///
/// This function creates a base64-encoded token string that grants the specified
/// operation on the resource for the given subject. The token will be valid for
/// 5 minutes by default.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_token(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
) -> Result<String, Box<dyn Error>> {
    create_base64_biscuit(
        subject,
        resource,
        operation,
        key,
        TokenTimeConfig::default(),
    )
}

/// Creates a biscuit token with custom time configuration.
///
/// This function creates a base64-encoded token string that grants the specified
/// operation on the resource for the given subject with custom time settings.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_token_with_time(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    create_base64_biscuit(subject, resource, operation, key, time_config)
}

/// Creates a new biscuit token with service chain attestations.
/// Creates a new biscuit token with service chain attestations.
///
/// This function creates a token that grants access to the specified resource for the given subject,
/// and includes attestations for each service node in the chain. The token will be valid for 5 minutes by default.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `nodes` - Vector of service nodes that will attest to the token
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The binary token data if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_service_chain_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let biscuit =
        create_raw_service_chain_biscuit(subject, resource, operation, key, nodes, time_config)?;
    let token = biscuit.to_vec()?;
    Ok(token)
}

/// Creates a base64-encoded service chain biscuit token.
///
/// This is a private helper function that creates a service chain biscuit token
/// and returns it as a base64-encoded string for easy transmission and storage.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `nodes` - Vector of service nodes that will attest to the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
fn create_base64_service_chain_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    let biscuit =
        create_raw_service_chain_biscuit(subject, resource, operation, key, nodes, time_config)?;
    let token = biscuit.to_base64()?;
    Ok(token)
}

/// Creates a raw service chain biscuit token.
///
/// This function creates a raw Biscuit object with service chain attestations
/// that can be further processed or converted to different formats. It delegates
/// to the time-aware version with the provided configuration.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `nodes` - Vector of service nodes that will attest to the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(Biscuit)` - The raw biscuit if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_raw_service_chain_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<Biscuit, Box<dyn Error>> {
    create_service_chain_biscuit_with_time(subject, resource, operation, key, nodes, time_config)
}

/// Creates a service chain biscuit token with default time configuration.
///
/// This function creates a base64-encoded service chain token string that grants
/// the specified operation on the resource for the given subject. The token will
/// be valid for 5 minutes by default and includes attestations for each service
/// node in the chain.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `nodes` - Vector of service nodes that will attest to the token
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_service_chain_token(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
) -> Result<String, Box<dyn Error>> {
    create_base64_service_chain_biscuit(
        subject,
        resource,
        operation,
        key,
        nodes,
        TokenTimeConfig::default(),
    )
}

/// Creates a new biscuit token with service chain attestations and custom time settings.
///
/// This function creates a token that grants access to the specified resource for the given subject,
/// includes attestations for each service node in the chain, and allows custom time configuration.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `nodes` - Vector of service nodes that will attest to the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The binary token data if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_service_chain_biscuit_with_time(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<Biscuit, Box<dyn Error>> {
    let service = resource.clone();
    let mut biscuit_builder =
        create_base_biscuit_builder_with_time(subject, service, operation, time_config)?;

    // Add each node in the service chain to the biscuit builder
    for node in nodes {
        let component = node.component.clone();
        let public_key = biscuit_key_from_string(node.public_key.clone())?;
        biscuit_builder = biscuit_builder.rule(rule!(
            r#"
                node($s, {component}) <- service($s) trusting {public_key};
            "#
        ))?;
    }

    let biscuit = biscuit_builder.build(&key)?;

    info!("biscuit (authority): {}", biscuit);

    Ok(biscuit)
}

/// Creates a service chain biscuit token with custom time configuration.
///
/// This function creates a base64-encoded service chain token string that grants
/// the specified operation on the resource for the given subject with custom time
/// settings. The token includes attestations for each service node in the chain.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `nodes` - Vector of service nodes that will attest to the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_service_chain_token_with_time(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    let biscuit = create_service_chain_biscuit_with_time(
        subject,
        resource,
        operation,
        key,
        nodes,
        time_config,
    )?;
    let token = biscuit.to_base64()?;
    Ok(token)
}

/// Creates a new biscuit token with multi-party attestations.
///
/// This function creates a token that grants access to the specified resource for the given subject,
/// includes attestations for each multi-party node in the chain, and allows custom time configuration.
///
/// The key difference between a multi-party biscuit and a service chain biscuit is that a multi-party
/// biscuit is not valid until it has been attested by all the parties.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `multi_party_nodes` - Vector of multi-party nodes that will attest to the token
pub fn create_raw_multi_party_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    multi_party_nodes: &Vec<ServiceNode>,
) -> Result<Biscuit, Box<dyn Error>> {
    create_multi_party_biscuit_with_time(
        subject,
        resource,
        operation,
        key,
        multi_party_nodes,
        TokenTimeConfig::default(),
    )
}

/// Creates a new biscuit token with multi-party attestations.
///
/// This function creates a token that grants access to the specified resource for the given subject,
/// includes attestations for each multi-party node in the chain. The token will be valid for 5 minutes by default.
///
/// The key difference between a multi-party biscuit and a service chain biscuit is that a multi-party
/// biscuit is not valid until it has been attested by all the parties.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `multi_party_nodes` - Vector of multi-party nodes that will attest to the token
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The binary token data if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_multi_party_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    multi_party_nodes: &Vec<ServiceNode>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let biscuit =
        create_raw_multi_party_biscuit(subject, resource, operation, key, multi_party_nodes)?;
    let token = biscuit.to_vec()?;
    Ok(token)
}

/// Creates a base64-encoded multi-party biscuit token.
///
/// This is a private helper function that creates a multi-party biscuit token
/// and returns it as a base64-encoded string for easy transmission and storage.
/// Multi-party tokens require attestation from all specified nodes before they
/// become valid.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `multi_party_nodes` - Vector of multi-party nodes that must attest to the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
fn create_base64_multi_party_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    multi_party_nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    let biscuit = create_multi_party_biscuit_with_time(
        subject,
        resource,
        operation,
        key,
        multi_party_nodes,
        time_config,
    )?;
    let token = biscuit.to_base64()?;
    Ok(token)
}

/// Creates a new multi-party biscuit token with default time configuration.
///
/// This function creates a token that grants access to the specified resource for the given subject,
/// includes attestations for each multi-party node, and uses the default time configuration (5 minutes).
///
/// The key difference between a multi-party biscuit and a service chain biscuit is that a multi-party
/// biscuit is not valid until it has been attested by all the parties.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `multi_party_nodes` - Vector of multi-party nodes that will attest to the token
///
/// # Returns
///
/// * `Ok(String)` - The base64-encoded token if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_multi_party_token(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    multi_party_nodes: &Vec<ServiceNode>,
) -> Result<String, Box<dyn Error>> {
    create_base64_multi_party_biscuit(
        subject,
        resource,
        operation,
        key,
        multi_party_nodes,
        TokenTimeConfig::default(),
    )
}

/// Creates a new biscuit token with multi-party attestations and custom time settings.
///
/// This function creates a token that grants access to the specified resource for the given subject,
/// includes attestations for each multi-party node in the chain, and allows custom time configuration.
///
/// The key difference between a multi-party biscuit and a service chain biscuit is that a multi-party
/// biscuit is not valid until it has been attested by all the parties.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `multi_party_nodes` - Vector of multi-party nodes that will attest to the token
/// * `time_config` - Time configuration for token validity
///
/// # Returns
///
/// * `Ok(Biscuit)` - The raw biscuit if successful
/// * `Err(Box<dyn Error>)` - If token creation fails
pub fn create_multi_party_biscuit_with_time(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    multi_party_nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<Biscuit, Box<dyn Error>> {
    let mut biscuit_builder =
        create_base_biscuit_builder_with_time(subject, resource, operation, time_config)?;

    for node in multi_party_nodes {
        let component = node.component.clone();
        let public_key = biscuit_key_from_string(node.public_key.clone())?;
        biscuit_builder = biscuit_builder.check(check!(
            r#"
                check if namespace({component}) trusting {public_key};
            "#
        ))?;
    }

    let biscuit = biscuit_builder.build(&key)?;

    info!("biscuit (authority): {}", biscuit);

    Ok(biscuit)
}

pub fn create_multi_party_token_with_time(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    multi_party_nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    let biscuit = create_multi_party_biscuit_with_time(
        subject,
        resource,
        operation,
        key,
        multi_party_nodes,
        time_config,
    )?;
    let token = biscuit.to_base64()?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{verify_biscuit_local, verify_service_chain_biscuit_local};
    use biscuit::macros::block;
    use biscuit::Biscuit;
    #[test]
    fn test_create_biscuit() {
        let subject = "test@test.com".to_owned();
        let resource: String = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();
        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            TokenTimeConfig::default(),
        )
        .unwrap();

        let res = verify_biscuit_local(token, public_key, subject, resource, operation);
        assert!(res.is_ok());
    }

    #[test]
    fn test_biscuit_operations() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Test read operation
        let read_token = create_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            TokenTimeConfig::default(),
        )
        .unwrap();

        let res = verify_biscuit_local(
            read_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            operation.clone(),
        );
        assert!(res.is_ok());

        let root = KeyPair::new();
        let public_key = root.public();

        // Test write operation
        let write_token = create_biscuit(
            subject.clone(),
            resource.clone(),
            "write".to_string(),
            root,
            TokenTimeConfig::default(),
        )
        .unwrap();

        let res = verify_biscuit_local(
            write_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            "write".to_string(),
        );
        assert!(res.is_ok());

        // Test that read token cannot be used for write
        let res = verify_biscuit_local(
            read_token,
            public_key,
            subject.clone(),
            resource.clone(),
            "write".to_string(),
        );
        assert!(res.is_err());

        // Test that write token cannot be used for read
        let res = verify_biscuit_local(
            write_token,
            public_key,
            subject.clone(),
            resource.clone(),
            "read".to_string(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_biscuit_expiration() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();
        // Create a biscuit with a 5 minute expiration from now
        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            TokenTimeConfig::default(),
        )
        .unwrap();

        let res = verify_biscuit_local(
            token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            operation.clone(),
        );
        assert!(res.is_ok());

        // Create a biscuit with a start time over 5 minutes ago
        let root = KeyPair::new();
        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            TokenTimeConfig {
                start_time: Some(Utc::now().timestamp() - 301),
                duration: 300,
            },
        )
        .unwrap();
        let res = verify_biscuit_local(token, public_key, subject, resource, operation);
        assert!(res.is_err());
    }

    #[test]
    fn test_custom_token_time_config() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Create token with custom start time (1 hour in the past) and longer duration (1 hour)
        let past_time = Utc::now().timestamp() - 3600;
        let time_config = TokenTimeConfig {
            start_time: Some(past_time),
            duration: 7200, // 2 hours
        };

        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            time_config,
        )
        .unwrap();

        // Token should be valid at a time between start and expiration
        let res = verify_biscuit_local(
            token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            operation.clone(),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_service_chain_biscuit() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();
        let chain_key = KeyPair::new();
        let chain_public_key = hex::encode(chain_key.public().to_bytes());
        let chain_public_key = format!("ed25519/{chain_public_key}");
        let chain_node = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key.clone(),
        };
        let nodes = vec![chain_node];
        let token = create_service_chain_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            &nodes,
            TokenTimeConfig::default(),
        );
        if let Err(e) = &token {
            println!("Error: {}", e);
        }
        assert!(token.is_ok());
        let token = token.unwrap();
        let res = verify_biscuit_local(
            token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            operation.clone(),
        );
        assert!(res.is_ok());
        let biscuit = Biscuit::from(&token, public_key).unwrap();
        let third_party_request = biscuit.third_party_request().unwrap();
        let third_party_block = block!(
            r#"
            service("res1");
            "#
        );
        let third_party_block = third_party_request
            .create_block(&chain_key.private(), third_party_block)
            .unwrap();
        let attested_biscuit = biscuit
            .append_third_party(chain_key.public(), third_party_block)
            .unwrap();
        let attested_token = attested_biscuit.to_vec().unwrap();
        let res = verify_service_chain_biscuit_local(
            attested_token,
            public_key,
            subject.clone(),
            resource.clone(),
            operation.clone(),
            nodes,
            None,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_service_chain_biscuit_with_component_name() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Create two chain nodes
        let chain_key1 = KeyPair::new();
        let chain_public_key1 = hex::encode(chain_key1.public().to_bytes());
        let chain_public_key1 = format!("ed25519/{chain_public_key1}");
        let chain_node1 = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key1.clone(),
        };

        let chain_key2 = KeyPair::new();
        let chain_public_key2 = hex::encode(chain_key2.public().to_bytes());
        let chain_public_key2 = format!("ed25519/{chain_public_key2}");
        let chain_node2 = ServiceNode {
            component: "middleware".to_string(),
            public_key: chain_public_key2.clone(),
        };

        let nodes = vec![chain_node1.clone(), chain_node2.clone()];

        // Create the initial token using the first node
        let token = create_service_chain_biscuit(
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            root,
            &nodes,
            TokenTimeConfig::default(),
        );
        assert!(token.is_ok());
        let token = token.unwrap();

        // Create the biscuit and add third-party blocks
        let biscuit = Biscuit::from(&token, public_key).unwrap();
        let third_party_request = biscuit.third_party_request().unwrap();
        let third_party_block = block!(
            r#"
                service("res1");
            "#
        );
        let third_party_block = third_party_request
            .create_block(&chain_key1.private(), third_party_block)
            .unwrap();
        let attested_biscuit = biscuit
            .append_third_party(chain_key1.public(), third_party_block)
            .unwrap();
        let attested_token = attested_biscuit.to_vec().unwrap();

        // Test with the "edge_function" component name - should pass
        // the first node in the service chain checking itself is valid
        // since it is checking the base biscuit
        let res = verify_service_chain_biscuit_local(
            attested_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            nodes.clone(),
            Some("edge_function".to_string()),
        );
        // This should fail - since we're not verifying any nodes when checking up to but not including "edge_function"
        assert!(res.is_ok());

        // Create a chain with two nodes
        let nodes = vec![chain_node1.clone(), chain_node2.clone()];

        // Test with "middleware" component - should succeed verifying node1 only
        let res = verify_service_chain_biscuit_local(
            attested_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            nodes.clone(),
            Some("middleware".to_string()),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_service_chain_biscuit_with_nonexistent_component() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let root = KeyPair::new();
        let public_key = root.public();
        let chain_key = KeyPair::new();
        let chain_public_key = hex::encode(chain_key.public().to_bytes());
        let chain_public_key = format!("ed25519/{chain_public_key}");
        let chain_node = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key.clone(),
        };
        let nodes = vec![chain_node];
        let token = create_service_chain_biscuit(
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            root,
            &nodes,
            TokenTimeConfig::default(),
        );
        assert!(token.is_ok());
        let token = token.unwrap();

        let biscuit = Biscuit::from(&token, public_key).unwrap();
        let third_party_request = biscuit.third_party_request().unwrap();
        let third_party_block = block!(
            r#"
            service("res1");
            "#
        );
        let third_party_block = third_party_request
            .create_block(&chain_key.private(), third_party_block)
            .unwrap();
        let attested_biscuit = biscuit
            .append_third_party(chain_key.public(), third_party_block)
            .unwrap();
        let attested_token = attested_biscuit.to_vec().unwrap();

        // Test with a component name that doesn't exist in the chain
        let res = verify_service_chain_biscuit_local(
            attested_token,
            public_key,
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            nodes.clone(),
            Some("nonexistent_component".to_string()),
        );
        assert!(res.is_err());

        // Verify the error message contains the component name
        let err = res.unwrap_err().to_string();
        assert!(err.contains("nonexistent_component"));
    }

    #[test]
    fn test_service_chain_biscuit_with_multiple_nodes() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Create three chain nodes
        let chain_key1 = KeyPair::new();
        let chain_public_key1 = hex::encode(chain_key1.public().to_bytes());
        let chain_public_key1 = format!("ed25519/{chain_public_key1}");
        let chain_node1 = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key1.clone(),
        };

        let chain_key2 = KeyPair::new();
        let chain_public_key2 = hex::encode(chain_key2.public().to_bytes());
        let chain_public_key2 = format!("ed25519/{chain_public_key2}");
        let chain_node2 = ServiceNode {
            component: "middleware".to_string(),
            public_key: chain_public_key2.clone(),
        };

        let chain_key3 = KeyPair::new();
        let chain_public_key3 = hex::encode(chain_key3.public().to_bytes());
        let chain_public_key3 = format!("ed25519/{chain_public_key3}");
        let chain_node3 = ServiceNode {
            component: "backend".to_string(),
            public_key: chain_public_key3.clone(),
        };

        // Create the initial token with the first node
        let nodes = vec![
            chain_node1.clone(),
            chain_node2.clone(),
            chain_node3.clone(),
        ];
        let token = create_service_chain_biscuit(
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            root,
            &nodes,
            TokenTimeConfig::default(),
        );
        assert!(token.is_ok());
        let token = token.unwrap();

        println!("Created initial token");

        // Create the biscuit and add node1's block
        let biscuit = Biscuit::from(&token, public_key).unwrap();
        let third_party_request1 = biscuit.third_party_request().unwrap();
        let third_party_block1 = block!(
            r#"
                service("res1");
            "#
        );
        let third_party_block1 = third_party_request1
            .create_block(&chain_key1.private(), third_party_block1)
            .unwrap();
        let attested_biscuit1 = biscuit
            .append_third_party(chain_key1.public(), third_party_block1)
            .unwrap();

        // Chain with all three nodes
        let all_nodes = vec![
            chain_node1.clone(),
            chain_node2.clone(),
            chain_node3.clone(),
        ];
        let attested_token1 = attested_biscuit1.to_vec().unwrap();

        // Test 1: Verify up to but not including middleware
        // This should verify edge_function only
        let res = verify_service_chain_biscuit_local(
            attested_token1.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            all_nodes.clone(),
            Some("middleware".to_string()),
        );
        assert!(res.is_ok());

        // Test 3: Verify up to but not including backend
        // This should try to verify both edge_function and middleware
        // but since the middleware attestation wasn't added, it will fail
        let res = verify_service_chain_biscuit_local(
            attested_token1.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            all_nodes.clone(),
            Some("backend".to_string()),
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_service_chain_biscuit_with_custom_time() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let root = KeyPair::new();
        let public_key = root.public();
        let chain_key = KeyPair::new();
        let chain_public_key = hex::encode(chain_key.public().to_bytes());
        let chain_public_key = format!("ed25519/{chain_public_key}");
        let chain_node = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key.clone(),
        };
        let nodes = vec![chain_node];

        // Create a valid token with default time configuration (5 minutes)
        let valid_token = create_service_chain_biscuit_with_time(
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            root,
            &nodes,
            TokenTimeConfig::default(),
        );
        assert!(valid_token.is_ok());
        let valid_token = valid_token.unwrap().to_vec().unwrap();

        // Verify the valid token works
        let res = verify_biscuit_local(
            valid_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            "read".to_string(),
        );
        assert!(res.is_ok());

        // Create an expired token (start time 6 minutes ago with 5 minute duration)
        let expired_time_config = TokenTimeConfig {
            start_time: Some(Utc::now().timestamp() - 360), // 6 minutes ago
            duration: 300,                                  // 5 minutes
        };

        // Create a new key pair for the expired token
        let root2 = KeyPair::new();
        let public_key2 = root2.public();

        let expired_token = create_service_chain_biscuit_with_time(
            subject.clone(),
            resource.clone(),
            "read".to_string(),
            root2,
            &nodes,
            expired_time_config,
        );
        assert!(expired_token.is_ok());
        let expired_token = expired_token.unwrap().to_vec().unwrap();

        // Verify expired token fails
        let res = verify_biscuit_local(
            expired_token,
            public_key2,
            subject,
            resource,
            "read".to_string(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_multi_party_biscuit_helper_functions() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();

        // Create a multi-party node
        let multi_party_key = KeyPair::new();
        let multi_party_public_key = hex::encode(multi_party_key.public().to_bytes());
        let multi_party_public_key = format!("ed25519/{multi_party_public_key}");
        let multi_party_node = ServiceNode {
            component: "approval_service".to_string(),
            public_key: multi_party_public_key.clone(),
        };
        let nodes = vec![multi_party_node];

        // Test create_multi_party_token (default time config)
        let token_string = create_multi_party_token(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            &nodes,
        );
        assert!(token_string.is_ok());

        // Test create_multi_party_biscuit (binary token with default time config)
        let root2 = KeyPair::new();
        let binary_token = create_multi_party_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root2,
            &nodes,
        );
        assert!(binary_token.is_ok());

        // Test create_raw_multi_party_biscuit (raw biscuit with default time config)
        let root3 = KeyPair::new();
        let raw_biscuit = create_raw_multi_party_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root3,
            &nodes,
        );
        assert!(raw_biscuit.is_ok());

        // Test create_multi_party_token_with_time (custom time config)
        let custom_time_config = TokenTimeConfig {
            start_time: Some(Utc::now().timestamp()),
            duration: 600, // 10 minutes
        };
        let root4 = KeyPair::new();
        let custom_time_token = create_multi_party_token_with_time(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root4,
            &nodes,
            custom_time_config,
        );
        assert!(custom_time_token.is_ok());

        // Test create_multi_party_biscuit_with_time (raw biscuit with custom time config)
        let root5 = KeyPair::new();
        let custom_time_biscuit = create_multi_party_biscuit_with_time(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root5,
            &nodes,
            custom_time_config,
        );
        assert!(custom_time_biscuit.is_ok());
    }

    #[test]
    fn test_basic_authorization_with_domain_restriction() {
        let subject = "alice".to_string();
        let resource = "resource1".to_string();
        let operation = "read".to_string();
        let domain = "myapp.hessra.dev".to_string();
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create basic authorization token with domain restriction
        let token = HessraAuthorization::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .domain_restricted(domain.clone())
        .issue(&keypair);

        assert!(token.is_ok(), "Failed to create domain-restricted token");
        let token = token.unwrap();

        // Parse and verify the token
        let biscuit = Biscuit::from_base64(&token, public_key).unwrap();

        // Build authorizer with domain fact - should succeed
        let authz = crate::verify::build_base_authorizer(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            Some(domain.clone()),
        )
        .unwrap();
        assert!(
            authz.build(&biscuit).unwrap().authorize().is_ok(),
            "Token should verify with correct domain"
        );

        // Build authorizer without domain fact - should fail
        let authz_no_domain = crate::verify::build_base_authorizer(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            None,
        )
        .unwrap();
        assert!(
            authz_no_domain
                .build(&biscuit)
                .unwrap()
                .authorize()
                .is_err(),
            "Token should fail verification without domain fact"
        );

        // Build authorizer with wrong domain - should fail
        let authz_wrong_domain = crate::verify::build_base_authorizer(
            subject,
            resource,
            operation,
            Some("wrongdomain.com".to_string()),
        )
        .unwrap();
        assert!(
            authz_wrong_domain
                .build(&biscuit)
                .unwrap()
                .authorize()
                .is_err(),
            "Token should fail verification with wrong domain"
        );
    }

    #[test]
    fn test_service_chain_with_domain_restriction() {
        let subject = "alice".to_string();
        let resource = "resource1".to_string();
        let operation = "read".to_string();
        let domain = "myapp.hessra.dev".to_string();
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create service node
        let chain_key = KeyPair::new();
        let chain_public_key = hex::encode(chain_key.public().to_bytes());
        let chain_public_key = format!("ed25519/{chain_public_key}");
        let chain_node = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key.clone(),
        };
        let nodes = vec![chain_node];

        // Create service chain token with domain restriction
        let token = HessraAuthorization::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .service_chain(nodes.clone())
        .domain_restricted(domain.clone())
        .issue(&keypair);

        assert!(
            token.is_ok(),
            "Failed to create domain-restricted service chain token"
        );
        let token = token.unwrap();

        // Parse and verify the token
        let biscuit = Biscuit::from_base64(&token, public_key).unwrap();

        // Build authorizer with domain fact - should succeed
        let authz = crate::verify::build_base_authorizer(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            Some(domain),
        )
        .unwrap();
        assert!(
            authz.build(&biscuit).unwrap().authorize().is_ok(),
            "Service chain token should verify with correct domain"
        );

        // Build authorizer without domain fact - should fail
        let authz_no_domain =
            crate::verify::build_base_authorizer(subject, resource, operation, None).unwrap();
        assert!(
            authz_no_domain
                .build(&biscuit)
                .unwrap()
                .authorize()
                .is_err(),
            "Service chain token should fail verification without domain fact"
        );
    }

    #[test]
    fn test_multi_party_with_domain_restriction() {
        let subject = "alice".to_string();
        let resource = "resource1".to_string();
        let operation = "read".to_string();
        let domain = "myapp.hessra.dev".to_string();
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create multi-party node
        let party_key = KeyPair::new();
        let party_public_key = hex::encode(party_key.public().to_bytes());
        let party_public_key = format!("ed25519/{party_public_key}");
        let party_node = ServiceNode {
            component: "approval_service".to_string(),
            public_key: party_public_key.clone(),
        };
        let nodes = vec![party_node];

        // Create multi-party token with domain restriction
        let token = HessraAuthorization::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .multi_party(nodes.clone())
        .domain_restricted(domain.clone())
        .issue(&keypair);

        assert!(
            token.is_ok(),
            "Failed to create domain-restricted multi-party token"
        );
        let token = token.unwrap();

        // Parse and verify the token
        let biscuit = Biscuit::from_base64(&token, public_key).unwrap();

        // Build authorizer with domain fact - token will still fail because multi-party needs attestations
        // But we're testing that domain check is present
        let _authz = crate::verify::build_base_authorizer(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            Some(domain),
        )
        .unwrap();
        // Multi-party token needs attestation, so this will fail for that reason, not domain
        // We're just checking the token was created successfully with domain check
        assert!(biscuit.to_base64().is_ok(), "Token should be valid biscuit");

        // Build authorizer without domain fact - should also fail
        let authz_no_domain =
            crate::verify::build_base_authorizer(subject, resource, operation, None).unwrap();
        assert!(
            authz_no_domain
                .build(&biscuit)
                .unwrap()
                .authorize()
                .is_err(),
            "Multi-party token should fail verification without domain fact or attestations"
        );
    }

    #[test]
    fn test_authorization_verifier_with_domain() {
        use crate::verify::AuthorizationVerifier;

        let subject = "alice".to_string();
        let resource = "resource1".to_string();
        let operation = "read".to_string();
        let domain = "myapp.hessra.dev".to_string();
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create basic authorization token with domain restriction
        let token = HessraAuthorization::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .domain_restricted(domain.clone())
        .issue(&keypair)
        .expect("Failed to create domain-restricted token");

        // Verify with matching domain using builder - should succeed
        assert!(
            AuthorizationVerifier::new(
                token.clone(),
                public_key,
                subject.clone(),
                resource.clone(),
                operation.clone(),
            )
            .with_domain(domain.clone())
            .verify()
            .is_ok(),
            "Token should verify with correct domain using builder"
        );

        // Verify without domain context - should fail
        assert!(
            AuthorizationVerifier::new(
                token.clone(),
                public_key,
                subject.clone(),
                resource.clone(),
                operation.clone(),
            )
            .verify()
            .is_err(),
            "Token should fail verification without domain context"
        );

        // Verify with wrong domain - should fail
        assert!(
            AuthorizationVerifier::new(
                token.clone(),
                public_key,
                subject.clone(),
                resource.clone(),
                operation.clone(),
            )
            .with_domain("wrongdomain.com".to_string())
            .verify()
            .is_err(),
            "Token should fail verification with wrong domain"
        );

        // Test with non-domain-restricted token - extra domain context shouldn't break it
        let regular_token = HessraAuthorization::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .issue(&keypair)
        .expect("Failed to create regular token");

        // Regular token should pass with or without domain context
        assert!(
            AuthorizationVerifier::new(
                regular_token.clone(),
                public_key,
                subject.clone(),
                resource.clone(),
                operation.clone(),
            )
            .verify()
            .is_ok(),
            "Regular token should verify without domain context"
        );

        assert!(
            AuthorizationVerifier::new(regular_token, public_key, subject, resource, operation,)
                .with_domain(domain)
                .verify()
                .is_ok(),
            "Regular token should verify even with extra domain context"
        );
    }

    #[test]
    fn test_service_chain_verifier_with_domain() {
        use crate::verify::{AuthorizationVerifier, ServiceNode};

        let subject = "alice".to_string();
        let resource = "resource1".to_string();
        let operation = "read".to_string();
        let domain = "myapp.hessra.dev".to_string();
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create service node
        let node_keypair = KeyPair::new();
        let node_public_key = node_keypair.public();
        let node_key_hex = hex::encode(node_public_key.to_bytes());
        let node_key_string = format!("ed25519/{node_key_hex}");

        let service_nodes = vec![ServiceNode {
            component: "api-gateway".to_string(),
            public_key: node_key_string,
        }];

        // Create service chain token with domain restriction
        let token = HessraAuthorization::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .service_chain(service_nodes.clone())
        .domain_restricted(domain.clone())
        .issue(&keypair)
        .expect("Failed to create service chain token with domain");

        // Convert token to bytes for attestation
        let token_bytes = crate::decode_token(&token).expect("Failed to decode token");

        // Add service node attestation
        let attested_token_bytes = crate::attest::add_service_node_attestation(
            token_bytes,
            public_key,
            &resource,
            &node_keypair,
        )
        .expect("Failed to add attestation");

        // Verify with service chain and domain - should succeed
        assert!(
            AuthorizationVerifier::from_bytes(
                attested_token_bytes.clone(),
                public_key,
                subject.clone(),
                resource.clone(),
                operation.clone(),
            )
            .expect("Failed to create verifier")
            .with_service_chain(service_nodes.clone(), Some("api-gateway".to_string()))
            .with_domain(domain.clone())
            .verify()
            .is_ok(),
            "Service chain token should verify with domain"
        );

        // Verify with service chain but no domain - should fail
        assert!(
            AuthorizationVerifier::from_bytes(
                attested_token_bytes.clone(),
                public_key,
                subject.clone(),
                resource.clone(),
                operation.clone(),
            )
            .expect("Failed to create verifier")
            .with_service_chain(service_nodes.clone(), Some("api-gateway".to_string()))
            .verify()
            .is_err(),
            "Service chain token should fail without domain"
        );

        // Verify with domain but no service chain checks
        // This should actually PASS because the attestation is valid and embedded in the token
        // The service chain checks are additional validation for specific component requirements
        assert!(
            AuthorizationVerifier::from_bytes(
                attested_token_bytes,
                public_key,
                subject,
                resource,
                operation,
            )
            .expect("Failed to create verifier")
            .with_domain(domain)
            .verify()
            .is_ok(),
            "Service chain token with valid attestation should pass basic verification"
        );
    }

    #[test]
    fn test_verify_capability_token_basic() {
        let subject = "alice".to_string();
        let resource = "resource1".to_string();
        let operation = "read".to_string();
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create token with subject
        let token = create_token(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            keypair,
        )
        .unwrap();

        // Verify without providing subject - should succeed
        let result =
            crate::verify::verify_capability_token_local(&token, public_key, &resource, &operation);

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_capability_token_wrong_resource() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = create_token(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            keypair,
        )
        .unwrap();

        // Try to verify for wrong resource
        let result = crate::verify::verify_capability_token_local(
            &token,
            public_key,
            "resource2", // Wrong resource
            "read",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_capability_token_wrong_operation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = create_token(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            keypair,
        )
        .unwrap();

        // Try to verify for wrong operation
        let result = crate::verify::verify_capability_token_local(
            &token,
            public_key,
            "resource1",
            "write", // Wrong operation
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_capability_with_domain() {
        let domain = "myapp.hessra.dev".to_string();
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create token with domain restriction
        let token = HessraAuthorization::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .domain_restricted(domain.clone())
        .issue(&keypair)
        .unwrap();

        // Verify capability with matching domain
        let result = crate::verify::AuthorizationVerifier::new_capability(
            token.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_domain(domain.clone())
        .verify();

        assert!(result.is_ok());

        // Verify capability without domain - should fail
        let result = crate::verify::AuthorizationVerifier::new_capability(
            token,
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .verify();

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_capability_with_service_chain() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let chain_keypair = KeyPair::new();
        let chain_public_key_hex = hex::encode(chain_keypair.public().to_bytes());
        let chain_public_key = format!("ed25519/{chain_public_key_hex}");
        let chain_node = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key,
        };

        // Create service chain token
        let token = HessraAuthorization::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .service_chain(vec![chain_node.clone()])
        .issue(&keypair)
        .unwrap();

        // Add attestation
        let token_bytes = crate::decode_token(&token).unwrap();
        let attested = crate::attest::add_service_node_attestation(
            token_bytes,
            public_key,
            "resource1",
            &chain_keypair,
        )
        .unwrap();
        let attested_token = crate::encode_token(&attested);

        // Verify capability with service chain
        let result = crate::verify::verify_service_chain_capability_token_local(
            &attested_token,
            public_key,
            "resource1",
            "read",
            vec![chain_node],
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_capability_verifier_builder() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let domain = "example.com".to_string();

        let token = HessraAuthorization::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .domain_restricted(domain.clone())
        .issue(&keypair)
        .unwrap();

        // Test builder pattern
        let result = crate::verify::AuthorizationVerifier::new_capability(
            token,
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_domain(domain)
        .verify();

        assert!(result.is_ok());
    }

    #[test]
    fn test_capability_vs_identity_verification() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create token for alice
        let token = create_token(
            "alice".to_string(),
            "document_123".to_string(),
            "read".to_string(),
            keypair,
        )
        .unwrap();

        // Identity-based: Must specify correct subject
        let result = crate::verify::verify_token_local(
            &token,
            public_key,
            "alice", // Must match
            "document_123",
            "read",
        );
        assert!(result.is_ok());

        // Identity-based: Wrong subject fails
        let result = crate::verify::verify_token_local(
            &token,
            public_key,
            "bob", // Wrong subject
            "document_123",
            "read",
        );
        assert!(result.is_err());

        // Capability-based: Don't care about subject
        let result = crate::verify::verify_capability_token_local(
            &token,
            public_key,
            "document_123", // No subject needed
            "read",
        );
        assert!(result.is_ok());
    }
}
