use hessra_token_authz::{
    create_biscuit, get_authorization_revocation_id, KeyPair, TokenTimeConfig,
};
use hessra_token_core::encode_token;

fn main() {
    println!("=== Hessra Authorization Token Revocation Demo ===\n");

    // Create keypairs for signing tokens
    let keypair1 = KeyPair::new();
    let public_key1 = keypair1.public();

    let keypair2 = KeyPair::new();
    let public_key2 = keypair2.public();

    // Example 1: Short-lived authorization token
    println!("1. Creating a short-lived authorization token (5 minutes)");
    let token1 = create_biscuit(
        "user123".to_string(),
        "api/orders".to_string(),
        "read".to_string(),
        keypair1,
        TokenTimeConfig {
            start_time: None,
            duration: 300, // 5 minutes
        },
    )
    .expect("Failed to create token");

    let token1_string = encode_token(&token1);
    let rev_id1 = get_authorization_revocation_id(token1_string.clone(), public_key1)
        .expect("Failed to get revocation ID");

    println!("   Token 1 details:");
    println!("   - Subject: user123");
    println!("   - Resource: api/orders");
    println!("   - Operation: read");
    println!("   - Duration: 5 minutes");
    println!("   - Revocation ID: {}", rev_id1.to_hex());
    println!();

    // Example 2: Another token with same content but different revocation ID
    println!("2. Creating another token with identical content");
    let token2 = create_biscuit(
        "user123".to_string(),
        "api/orders".to_string(),
        "read".to_string(),
        keypair2,
        TokenTimeConfig {
            start_time: None,
            duration: 300, // 5 minutes
        },
    )
    .expect("Failed to create token");

    let token2_string = encode_token(&token2);
    let rev_id2 = get_authorization_revocation_id(token2_string.clone(), public_key2)
        .expect("Failed to get revocation ID");

    println!("   Token 2 details:");
    println!("   - Subject: user123");
    println!("   - Resource: api/orders");
    println!("   - Operation: read");
    println!("   - Duration: 5 minutes");
    println!("   - Revocation ID: {}", rev_id2.to_hex());
    println!();

    println!("   Note: Even with identical content, revocation IDs are unique!");
    println!("   Token 1 ID: {}", rev_id1.to_hex());
    println!("   Token 2 ID: {}", rev_id2.to_hex());
    println!();

    // Demonstrate revocation use cases
    println!("=== Revocation Use Cases ===\n");

    println!("Emergency revocation scenarios:");
    println!("1. Compromised credentials detected");
    println!("2. Suspicious activity from a user");
    println!("3. Permission changes that take effect immediately");
    println!("4. Token issued with wrong permissions");
    println!();

    println!("Example revocation check:");
    println!("```rust");
    println!("// In your authorization service:");
    println!("let revoked_ids = HashSet::from([");
    println!(
        "    \"{}\".to_string(), // Revoked due to suspicious activity",
        rev_id1.to_hex()
    );
    println!("]);");
    println!();
    println!("// When verifying a token:");
    println!("let token_rev_id = get_authorization_revocation_id(token, public_key)?;");
    println!("if revoked_ids.contains(&token_rev_id.to_hex()) {{");
    println!("    return Err(\"Token has been revoked\");");
    println!("}}");
    println!("```");
    println!();

    println!("Best practices:");
    println!("- Keep authorization tokens short-lived (< 5 minutes)");
    println!("- Only revoke when absolutely necessary (emergency scenarios)");
    println!("- Clean up revocation lists periodically (remove expired token IDs)");
    println!("- Store revocation IDs in a fast cache (Redis, in-memory)");
}
