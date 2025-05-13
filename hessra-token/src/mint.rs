extern crate biscuit_auth as biscuit;

use crate::verify::{biscuit_key_from_string, ServiceNode};

use biscuit::macros::{biscuit, rule};
use biscuit::{BiscuitBuilder, KeyPair};
use chrono::Utc;
use std::error::Error;
use tracing::info;

/// TokenTimeConfig allows control over token creation times and durations
#[derive(Debug, Clone, Copy)]
pub struct TokenTimeConfig {
    /// Optional custom start time (now time override)
    pub start_time: Option<i64>,
    /// Duration in seconds (default: 300 seconds = 5 minutes)
    pub duration: i64,
}

impl Default for TokenTimeConfig {
    fn default() -> Self {
        Self {
            start_time: None,
            duration: 300, // 5 minutes in seconds
        }
    }
}

pub fn _create_base_biscuit_builder(
    subject: String,
    resource: String,
) -> Result<BiscuitBuilder, Box<dyn Error>> {
    create_base_biscuit_builder_with_time(subject, resource, TokenTimeConfig::default())
}

pub fn create_base_biscuit_builder_with_time(
    subject: String,
    resource: String,
    time_config: TokenTimeConfig,
) -> Result<BiscuitBuilder, Box<dyn Error>> {
    let start_time = time_config
        .start_time
        .unwrap_or_else(|| Utc::now().timestamp());
    let expiration = start_time + time_config.duration;

    let biscuit_builder = biscuit!(
        r#"
            right({subject}, {resource}, "read");
            right({subject}, {resource}, "write");
            check if time($time), $time < {expiration};
        "#
    );

    Ok(biscuit_builder)
}

pub fn create_biscuit(
    subject: String,
    resource: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let token = {
        let biscuit =
            create_base_biscuit_builder_with_time(subject, resource, time_config)?.build(&key)?;

        info!("biscuit (authority): {}", biscuit);

        biscuit.to_vec()?
    };
    Ok(token)
}

pub fn create_service_chain_biscuit(
    subject: String,
    resource: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    create_service_chain_biscuit_with_time(
        subject,
        resource,
        key,
        nodes,
        TokenTimeConfig::default(),
    )
}

pub fn create_service_chain_biscuit_with_time(
    subject: String,
    resource: String,
    key: KeyPair,
    nodes: &Vec<ServiceNode>,
    time_config: TokenTimeConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let service = resource.clone();
    let mut biscuit_builder = create_base_biscuit_builder_with_time(subject, service, time_config)?;

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

    let token = {
        let biscuit = biscuit_builder.build(&key)?;

        info!("biscuit (authority): {}", biscuit);

        biscuit.to_vec()?
    };
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
        let root = KeyPair::new();
        let public_key = root.public();
        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            root,
            TokenTimeConfig::default(),
        )
        .unwrap();

        let res = verify_biscuit_local(token, public_key, subject, resource);
        assert!(res.is_ok());
    }

    #[test]
    fn test_biscuit_expiration() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let root = KeyPair::new();
        let public_key = root.public();
        // Create a biscuit with a 5 minute expiration from now
        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            root,
            TokenTimeConfig::default(),
        )
        .unwrap();

        let res =
            verify_biscuit_local(token.clone(), public_key, subject.clone(), resource.clone());
        assert!(res.is_ok());

        // Create a biscuit with a start time over 5 minutes ago
        let root = KeyPair::new();
        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            root,
            TokenTimeConfig {
                start_time: Some(Utc::now().timestamp() - 301),
                duration: 300,
            },
        )
        .unwrap();
        let res = verify_biscuit_local(token, public_key, subject, resource);
        assert!(res.is_err());
    }

    #[test]
    fn test_custom_token_time_config() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Create token with custom start time (1 hour in the past) and longer duration (1 hour)
        let past_time = Utc::now().timestamp() - 3600;
        let time_config = TokenTimeConfig {
            start_time: Some(past_time),
            duration: 7200, // 2 hours
        };

        let token = create_biscuit(subject.clone(), resource.clone(), root, time_config).unwrap();

        // Token should be valid at a time between start and expiration
        let res =
            verify_biscuit_local(token.clone(), public_key, subject.clone(), resource.clone());
        assert!(res.is_ok());
    }

    #[test]
    fn test_service_chain_biscuit() {
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
        let token = create_service_chain_biscuit(subject.clone(), resource.clone(), root, &nodes);
        if let Err(e) = &token {
            println!("Error: {}", e);
        }
        assert!(token.is_ok());
        let token = token.unwrap();
        let res =
            verify_biscuit_local(token.clone(), public_key, subject.clone(), resource.clone());
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
        let attenuated_biscuit = biscuit
            .append_third_party(chain_key.public(), third_party_block)
            .unwrap();
        let attenuated_token = attenuated_biscuit.to_vec().unwrap();
        let res = verify_service_chain_biscuit_local(
            attenuated_token,
            public_key,
            subject.clone(),
            resource.clone(),
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
        let token = create_service_chain_biscuit(subject.clone(), resource.clone(), root, &nodes);
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
        let attenuated_biscuit = biscuit
            .append_third_party(chain_key1.public(), third_party_block)
            .unwrap();
        let attenuated_token = attenuated_biscuit.to_vec().unwrap();

        // Test with the "edge_function" component name - should pass
        // the first node in the service chain checking itself is valid
        // since it is checking the base biscuit
        let res = verify_service_chain_biscuit_local(
            attenuated_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            nodes.clone(),
            Some("edge_function".to_string()),
        );
        // This should fail - since we're not verifying any nodes when checking up to but not including "edge_function"
        assert!(res.is_ok());

        // Create a chain with two nodes
        let nodes = vec![chain_node1.clone(), chain_node2.clone()];

        // Test with "middleware" component - should succeed verifying node1 only
        let res = verify_service_chain_biscuit_local(
            attenuated_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
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
        let token = create_service_chain_biscuit(subject.clone(), resource.clone(), root, &nodes);
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
        let attenuated_biscuit = biscuit
            .append_third_party(chain_key.public(), third_party_block)
            .unwrap();
        let attenuated_token = attenuated_biscuit.to_vec().unwrap();

        // Test with a component name that doesn't exist in the chain
        let res = verify_service_chain_biscuit_local(
            attenuated_token,
            public_key,
            subject.clone(),
            resource.clone(),
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
        let token = create_service_chain_biscuit(subject.clone(), resource.clone(), root, &nodes);
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
        let attenuated_biscuit1 = biscuit
            .append_third_party(chain_key1.public(), third_party_block1)
            .unwrap();

        // Chain with all three nodes
        let all_nodes = vec![
            chain_node1.clone(),
            chain_node2.clone(),
            chain_node3.clone(),
        ];
        let attenuated_token1 = attenuated_biscuit1.to_vec().unwrap();

        // Test 1: Verify up to but not including middleware
        // This should verify edge_function only
        let res = verify_service_chain_biscuit_local(
            attenuated_token1.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
            all_nodes.clone(),
            Some("middleware".to_string()),
        );
        assert!(res.is_ok());

        // Test 3: Verify up to but not including backend
        // This should try to verify both edge_function and middleware
        // but since the middleware attenuation wasn't added, it will fail
        let res = verify_service_chain_biscuit_local(
            attenuated_token1.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
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
            root,
            &nodes,
            TokenTimeConfig::default(),
        );
        assert!(valid_token.is_ok());
        let valid_token = valid_token.unwrap();

        // Verify the valid token works
        let res = verify_biscuit_local(
            valid_token.clone(),
            public_key,
            subject.clone(),
            resource.clone(),
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
            root2,
            &nodes,
            expired_time_config,
        );
        assert!(expired_token.is_ok());
        let expired_token = expired_token.unwrap();

        // Verify expired token fails
        let res = verify_biscuit_local(expired_token, public_key2, subject, resource);
        assert!(res.is_err());
    }
}
