use hessra_token_authz::{
    add_service_node_attestation, create_token, verify_capability_token_local,
    verify_service_chain_capability_token_local, verify_token_local, AuthorizationVerifier,
    HessraAuthorization, ServiceNode,
};
use hessra_token_core::{decode_token, encode_token, KeyPair, TokenError, TokenTimeConfig};

fn main() -> Result<(), TokenError> {
    println!("=== Capability-Based Token Verification ===\n");
    println!("Capability verification allows services to verify tokens");
    println!("based on resource+operation only, without requiring the subject.\n");

    let keypair = KeyPair::new();
    let public_key = keypair.public();

    // Example 1: Basic capability verification
    println!("Example 1: Basic Capability Verification");
    println!("------------------------------------------");

    let token = create_token(
        "alice".to_string(),
        "document_123".to_string(),
        "read".to_string(),
        keypair,
    )
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Created token for alice to read document_123");

    // Identity-based: Need to know the subject
    println!("\nIdentity-based verification (traditional):");
    verify_token_local(
        &token,
        public_key,
        "alice", // Must provide subject
        "document_123",
        "read",
    )?;
    println!("  Verified: alice can read document_123");

    // Capability-based: Don't need to know the subject
    println!("\nCapability-based verification (new):");
    verify_capability_token_local(
        &token,
        public_key,
        "document_123", // No subject needed!
        "read",
    )?;
    println!("  Verified: token grants read access to document_123");
    println!("  (Subject is derived from token, not provided)\n");

    // Example 2: Use case - API Gateway
    println!("Example 2: API Gateway Use Case");
    println!("--------------------------------");
    println!("Scenario: API gateway doesn't care WHO is making the request,");
    println!("only that they have authorization for the requested operation.\n");

    let keypair2 = KeyPair::new();
    let public_key2 = keypair2.public();

    let token2 = create_token(
        "service_account_xyz".to_string(),
        "/api/users".to_string(),
        "GET".to_string(),
        keypair2,
    )
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Client sends token to: GET /api/users");
    println!("Gateway extracts resource='/api/users' and operation='GET'");

    verify_capability_token_local(&token2, public_key2, "/api/users", "GET")?;

    println!("  Gateway allows request (subject irrelevant)\n");

    // Example 3: Domain restriction with capability
    println!("Example 3: Domain Restriction");
    println!("------------------------------");

    let keypair4 = KeyPair::new();
    let public_key4 = keypair4.public();

    let domain = "api.example.com".to_string();
    let token_with_domain = HessraAuthorization::new(
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
        TokenTimeConfig::default(),
    )
    .domain_restricted(domain.clone())
    .issue(&keypair4)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Token restricted to domain: {}", domain);

    AuthorizationVerifier::new_capability(
        token_with_domain,
        public_key4,
        "resource1".to_string(),
        "read".to_string(),
    )
    .with_domain(domain)
    .verify()?;

    println!("  Capability verified with domain restriction\n");

    // Example 4: Service chain with capability
    println!("Example 4: Service Chain");
    println!("------------------------");

    let keypair5 = KeyPair::new();
    let public_key5 = keypair5.public();

    let chain_keypair = KeyPair::new();
    let chain_public_key = format!("ed25519/{}", hex::encode(chain_keypair.public().to_bytes()));
    let chain_node = ServiceNode {
        component: "edge_function".to_string(),
        public_key: chain_public_key,
    };

    let chain_token = HessraAuthorization::new(
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
        TokenTimeConfig::default(),
    )
    .service_chain(vec![chain_node.clone()])
    .issue(&keypair5)
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Token with service chain requirement");

    let token_bytes = decode_token(&chain_token)?;
    let attested =
        add_service_node_attestation(token_bytes, public_key5, "resource1", &chain_keypair)?;

    println!("Added attestation from edge_function");

    verify_service_chain_capability_token_local(
        &encode_token(&attested),
        public_key5,
        "resource1",
        "read",
        vec![chain_node],
        None,
    )?;

    println!("  Service chain and capability both verified\n");

    // Example 5: Comparison - Identity vs Capability
    println!("Example 5: Identity vs Capability Comparison");
    println!("---------------------------------------------");

    let keypair6 = KeyPair::new();
    let public_key6 = keypair6.public();

    let token6 = create_token(
        "alice".to_string(),
        "resource1".to_string(),
        "read".to_string(),
        keypair6,
    )
    .map_err(|e| TokenError::Generic(e.to_string()))?;

    println!("Token created for alice to read resource1\n");

    println!("Identity-based verification:");
    println!("  verify_token_local(&token, public_key, \"alice\", \"resource1\", \"read\")");
    verify_token_local(&token6, public_key6, "alice", "resource1", "read")?;
    println!("  Result: Success (alice matches)\n");

    println!("  verify_token_local(&token, public_key, \"bob\", \"resource1\", \"read\")");
    let result = verify_token_local(&token6, public_key6, "bob", "resource1", "read");
    println!(
        "  Result: {} (subject mismatch)\n",
        if result.is_err() { "Failed" } else { "Success" }
    );

    println!("Capability-based verification:");
    println!("  verify_capability_token_local(&token, public_key, \"resource1\", \"read\")");
    verify_capability_token_local(&token6, public_key6, "resource1", "read")?;
    println!("  Result: Success (subject not checked)\n");

    println!("Use identity-based when: You need to verify a specific user's access");
    println!("Use capability-based when: You only care about permission, not identity");

    println!("\n=== All examples completed successfully! ===");
    Ok(())
}
