use hessra_token_core::{KeyPair, TokenTimeConfig};
use hessra_token_identity::{
    create_identity_token, inspect_identity_token, verify_bearer_token, verify_identity_token,
};

fn main() {
    // Create a keypair for signing tokens
    let keypair = KeyPair::new();
    let public_key = keypair.public();

    // Create an identity token for Alice
    let alice_identity = "urn:hessra:alice".to_string();
    let token = create_identity_token(
        alice_identity.clone(),
        keypair,
        TokenTimeConfig {
            start_time: None,
            duration: 3600, // 1 hour
        },
    )
    .expect("Failed to create token");

    println!("Created identity token for: {alice_identity}");
    println!("Token: {token}\n");

    // Inspect the token to extract information without verification
    let inspect_result =
        inspect_identity_token(token.clone(), public_key).expect("Failed to inspect token");

    println!("Token Inspection Results:");
    println!("  Identity: {}", inspect_result.identity);
    println!("  Is Delegated: {}", inspect_result.is_delegated);
    println!("  Is Expired: {}", inspect_result.is_expired);
    if let Some(expiry) = inspect_result.expiry {
        println!("  Expires at: {expiry} (Unix timestamp)");
    }
    println!();

    // Demonstrate different verification modes
    println!("Verification Tests:");

    // 1. Verify as a bearer token (no identity check)
    match verify_bearer_token(token.clone(), public_key) {
        Ok(_) => println!("  ✓ Valid as bearer token"),
        Err(e) => println!("  ✗ Invalid as bearer token: {e}"),
    }

    // 2. Verify with correct identity
    match verify_identity_token(token.clone(), public_key, alice_identity.clone()) {
        Ok(_) => println!("  ✓ Valid for identity: {alice_identity}"),
        Err(e) => println!("  ✗ Invalid for identity {alice_identity}: {e}"),
    }

    // 3. Verify with wrong identity (should fail)
    let wrong_identity = "urn:hessra:bob".to_string();
    match verify_identity_token(token.clone(), public_key, wrong_identity.clone()) {
        Ok(_) => println!("  ✗ Unexpectedly valid for: {wrong_identity}"),
        Err(_) => println!("  ✓ Correctly rejected for wrong identity: {wrong_identity}"),
    }

    println!("\n--- Bearer Token Use Case ---");
    println!("The bearer token verification is perfect for:");
    println!("• API keys that just need to be valid and not expired");
    println!("• Refresh tokens where you just need to know they're legitimate");
    println!("• Simple access tokens where the identity is determined after validation");
    println!("\nThe inspect function lets you extract the subject/actor without verification,");
    println!("useful for logging, debugging, or determining who owns an expired token.");
}
