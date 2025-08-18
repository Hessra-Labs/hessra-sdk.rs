extern crate biscuit_auth as biscuit;

use crate::verify::{biscuit_key_from_string, ServiceNode};

use biscuit::macros::{biscuit, check, rule};
use biscuit::BiscuitBuilder;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, TokenTimeConfig};
use std::error::Error;
use tracing::info;

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
        let chain_public_key = format!("ed25519/{}", chain_public_key);
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
        let chain_public_key1 = format!("ed25519/{}", chain_public_key1);
        let chain_node1 = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key1.clone(),
        };

        let chain_key2 = KeyPair::new();
        let chain_public_key2 = hex::encode(chain_key2.public().to_bytes());
        let chain_public_key2 = format!("ed25519/{}", chain_public_key2);
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
        let chain_public_key = format!("ed25519/{}", chain_public_key);
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
        let chain_public_key1 = format!("ed25519/{}", chain_public_key1);
        let chain_node1 = ServiceNode {
            component: "edge_function".to_string(),
            public_key: chain_public_key1.clone(),
        };

        let chain_key2 = KeyPair::new();
        let chain_public_key2 = hex::encode(chain_key2.public().to_bytes());
        let chain_public_key2 = format!("ed25519/{}", chain_public_key2);
        let chain_node2 = ServiceNode {
            component: "middleware".to_string(),
            public_key: chain_public_key2.clone(),
        };

        let chain_key3 = KeyPair::new();
        let chain_public_key3 = hex::encode(chain_key3.public().to_bytes());
        let chain_public_key3 = format!("ed25519/{}", chain_public_key3);
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
        let chain_public_key = format!("ed25519/{}", chain_public_key);
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
        let multi_party_public_key = format!("ed25519/{}", multi_party_public_key);
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
}
