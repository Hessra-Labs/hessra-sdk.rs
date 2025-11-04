use hessra_token_authz::{
    activate_latent_token_from_string, add_multi_party_attestation_to_token,
    add_service_node_attestation, verify_service_chain_token_local, verify_token_local,
    AuthorizationVerifier, HessraAuthorization, ServiceNode,
};
use hessra_token_core::{decode_token, encode_token, KeyPair, TokenError, TokenTimeConfig};

fn main() -> Result<(), TokenError> {
    println!("=== Latent Capability Token Examples ===\n");

    // Setup: Create keypairs
    let root_keypair = KeyPair::new();
    let root_public_key = root_keypair.public();

    let activator_keypair = KeyPair::new();
    let activator_public_key = format!(
        "ed25519/{}",
        hex::encode(activator_keypair.public().to_bytes())
    );

    println!("Example 1: Basic latent token creation and activation");
    println!("------------------------------------------------------");

    // Create a latent token with multiple latent rights
    let latent_rights = vec![
        ("resource1".to_string(), "read".to_string()),
        ("resource1".to_string(), "write".to_string()),
        ("resource2".to_string(), "read".to_string()),
        ("resource3".to_string(), "execute".to_string()),
    ];

    println!(
        "Creating latent token with {} rights...",
        latent_rights.len()
    );
    let latent_token = HessraAuthorization::new_latent(
        latent_rights.clone(),
        activator_public_key.clone(),
        TokenTimeConfig::default(),
    )
    .issue(&root_keypair)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Latent token created successfully\n");

    // Activate the latent token for different subjects and rights
    println!("Activating latent token for Alice to read resource1...");
    let activated_token_alice = activate_latent_token_from_string(
        latent_token.clone(),
        root_public_key,
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
        &activator_keypair,
        TokenTimeConfig::default(), // 5 minute expiration
    )?;

    verify_token_local(
        &activated_token_alice,
        root_public_key,
        "alice",
        "resource1",
        "read",
    )?;
    println!("✅ Activated token for Alice verified successfully\n");

    println!("Example 2: Multiple activations from same latent token");
    println!("-------------------------------------------------------");

    // Demonstrate reusability: activate the same latent token for different subjects
    let activations = vec![
        ("bob", "resource1", "write"),
        ("charlie", "resource2", "read"),
        ("dave", "resource3", "execute"),
    ];

    for (subject, resource, operation) in activations {
        println!(
            "Activating for {} to {} {}...",
            subject, operation, resource
        );
        let activated_token = activate_latent_token_from_string(
            latent_token.clone(),
            root_public_key,
            subject.to_string(),
            resource.to_string(),
            operation.to_string(),
            &activator_keypair,
            TokenTimeConfig::default(), // 5 minute expiration
        )?;

        verify_token_local(
            &activated_token,
            root_public_key,
            subject,
            resource,
            operation,
        )?;
        println!("✅ Verified successfully");
    }
    println!();

    println!("Example 3: Latent token with domain restriction");
    println!("------------------------------------------------");

    let domain = "myapp.hessra.dev".to_string();
    let latent_token_with_domain = HessraAuthorization::new_latent(
        vec![("resource1".to_string(), "read".to_string())],
        activator_public_key.clone(),
        TokenTimeConfig::default(),
    )
    .domain_restricted(domain.clone())
    .issue(&root_keypair)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Created latent token with domain restriction: {}", domain);

    let activated_with_domain = activate_latent_token_from_string(
        latent_token_with_domain,
        root_public_key,
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
        &activator_keypair,
        TokenTimeConfig::default(), // 5 minute expiration
    )?;

    AuthorizationVerifier::new(
        activated_with_domain,
        root_public_key,
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
    )
    .with_domain(domain.clone())
    .verify()?;

    println!("✅ Domain-restricted latent token verified successfully\n");

    println!("Example 4: Multi-party latent token (multi-party before activation)");
    println!("--------------------------------------------------------------------");

    // Create multi-party keypair
    let party_keypair = KeyPair::new();
    let party_public_key = format!("ed25519/{}", hex::encode(party_keypair.public().to_bytes()));
    let party_node = ServiceNode {
        component: "approval_service".to_string(),
        public_key: party_public_key,
    };

    // Create latent token with multi-party requirement
    let latent_token_multiparty = HessraAuthorization::new_latent(
        vec![("resource1".to_string(), "read".to_string())],
        activator_public_key.clone(),
        TokenTimeConfig::default(),
    )
    .multi_party(vec![party_node])
    .issue(&root_keypair)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Created latent token with multi-party requirement");

    // Add multi-party attestation BEFORE activation
    println!("Adding multi-party attestation from approval_service...");
    let attested_latent = add_multi_party_attestation_to_token(
        latent_token_multiparty,
        root_public_key,
        "approval_service".to_string(),
        party_keypair,
    )?;

    println!("Activating the attested latent token...");
    let activated_multiparty = activate_latent_token_from_string(
        attested_latent,
        root_public_key,
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
        &activator_keypair,
        TokenTimeConfig::default(), // 5 minute expiration
    )?;

    verify_token_local(
        &activated_multiparty,
        root_public_key,
        "alice",
        "resource1",
        "read",
    )?;

    println!("✅ Multi-party latent token verified successfully\n");

    println!("Example 5: Service chain after activation");
    println!("------------------------------------------");

    // Create service chain keypair
    let chain_keypair = KeyPair::new();
    let chain_public_key = format!("ed25519/{}", hex::encode(chain_keypair.public().to_bytes()));
    let chain_node = ServiceNode {
        component: "edge_function".to_string(),
        public_key: chain_public_key,
    };

    // Create latent token with service chain
    let latent_token_chain = HessraAuthorization::new_latent(
        vec![("resource1".to_string(), "read".to_string())],
        activator_public_key.clone(),
        TokenTimeConfig::default(),
    )
    .service_chain(vec![chain_node.clone()])
    .issue(&root_keypair)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Created latent token with service chain requirement");

    // Activate first, then add service chain attestation
    println!("Activating the latent token...");
    let activated_chain = activate_latent_token_from_string(
        latent_token_chain,
        root_public_key,
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
        &activator_keypair,
        TokenTimeConfig::default(), // 5 minute expiration
    )?;

    println!("Adding service chain attestation AFTER activation...");
    let activated_chain_bytes = decode_token(&activated_chain)?;
    let attested_chain = add_service_node_attestation(
        activated_chain_bytes,
        root_public_key,
        "resource1",
        &chain_keypair,
    )?;

    verify_service_chain_token_local(
        &encode_token(&attested_chain),
        root_public_key,
        "alice",
        "resource1",
        "read",
        vec![chain_node],
        None,
    )?;

    println!("✅ Service chain with activated latent token verified successfully\n");

    println!("Example 6: Delegation use case");
    println!("-------------------------------");
    println!("Scenario: Alice requests a latent token for her agent to use on her behalf");
    println!();

    // Alice's organization creates a latent token for Alice
    let alice_latent_token = HessraAuthorization::new_latent(
        vec![
            ("alice_data".to_string(), "read".to_string()),
            ("alice_data".to_string(), "write".to_string()),
            ("shared_resource".to_string(), "read".to_string()),
        ],
        activator_public_key.clone(),
        TokenTimeConfig::default(),
    )
    .issue(&root_keypair)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Organization issued latent token for Alice");

    // Alice (holder of activator key) activates it for her AI agent
    println!("Alice activates token for her AI agent 'alice_agent'...");
    let agent_token = activate_latent_token_from_string(
        alice_latent_token.clone(),
        root_public_key,
        "alice_agent".to_string(),
        "alice_data".to_string(),
        "read".to_string(),
        &activator_keypair,
        TokenTimeConfig::default(), // 5 minute expiration
    )?;

    verify_token_local(
        &agent_token,
        root_public_key,
        "alice_agent",
        "alice_data",
        "read",
    )?;

    println!("✅ Agent can now act on Alice's behalf with read access");

    // Alice activates it again for herself with write access
    println!("Alice activates token for herself with write access...");
    let alice_token = activate_latent_token_from_string(
        alice_latent_token,
        root_public_key,
        "alice".to_string(),
        "alice_data".to_string(),
        "write".to_string(),
        &activator_keypair,
        TokenTimeConfig::default(), // 5 minute expiration
    )?;

    verify_token_local(
        &alice_token,
        root_public_key,
        "alice",
        "alice_data",
        "write",
    )?;

    println!("✅ Alice can access her data with write permissions");
    println!();

    println!("Example 7: Time attenuation (30min latent → 5min activated)");
    println!("-------------------------------------------------------------");
    println!("Scenario: Long-lived latent token with short-lived activations for security");
    println!();

    // Create a long-lived latent token (30 minutes)
    let long_lived_latent = HessraAuthorization::new_latent(
        vec![
            ("sensitive_resource".to_string(), "read".to_string()),
            ("sensitive_resource".to_string(), "write".to_string()),
        ],
        activator_public_key.clone(),
        TokenTimeConfig {
            start_time: Some(chrono::Utc::now().timestamp()),
            duration: 1800, // 30 minutes
        },
    )
    .issue(&root_keypair)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Created long-lived latent token (30 minutes expiration)");

    // Activate with a much shorter expiration (5 minutes)
    let short_lived_activation = activate_latent_token_from_string(
        long_lived_latent.clone(),
        root_public_key,
        "secure_service".to_string(),
        "sensitive_resource".to_string(),
        "read".to_string(),
        &activator_keypair,
        TokenTimeConfig {
            start_time: Some(chrono::Utc::now().timestamp()),
            duration: 300, // 5 minutes - much shorter!
        },
    )?;

    println!("Activated with short expiration (5 minutes)");

    verify_token_local(
        &short_lived_activation,
        root_public_key,
        "secure_service",
        "sensitive_resource",
        "read",
    )?;

    println!("✅ Short-lived activation verified successfully");
    println!();
    println!("The latent token is still valid for 30 minutes, but this");
    println!("particular activation will expire in 5 minutes.");
    println!("The entity can activate the latent token again later with");
    println!("a fresh 5-minute expiration, as long as the latent token hasn't expired.");
    println!();

    println!("=== All examples completed successfully! ===");

    Ok(())
}
