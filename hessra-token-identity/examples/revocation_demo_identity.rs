use hessra_token_core::{KeyPair, TokenTimeConfig};
use hessra_token_identity::{
    add_identity_attenuation_to_token, create_identity_token, get_identity_revocations,
};

fn main() {
    println!("=== Hessra Identity Token Revocation Demo ===\n");

    // Create a keypair for signing tokens
    let keypair = KeyPair::new();
    let public_key = keypair.public();

    // Example 1: Base Identity Token
    println!("1. Creating a base identity token for 'urn:hessra:alice'");
    let alice_identity = "urn:hessra:alice".to_string();
    let base_token = create_identity_token(
        alice_identity.clone(),
        keypair,
        TokenTimeConfig {
            start_time: None,
            duration: 3600, // 1 hour
        },
    )
    .expect("Failed to create token");

    let base_revocations = get_identity_revocations(base_token.clone(), public_key)
        .expect("Failed to get revocations");

    println!("   Base token revocations:");
    for rev in &base_revocations {
        println!("   - {rev}");
    }
    println!();

    // Example 2: Delegated Identity Token
    println!("2. Delegating to 'urn:hessra:alice:laptop'");
    let laptop_identity = "urn:hessra:alice:laptop".to_string();
    let delegated_token = add_identity_attenuation_to_token(
        base_token.clone(),
        laptop_identity.clone(),
        public_key,
        TokenTimeConfig::default(),
    )
    .expect("Failed to delegate token");

    let delegated_revocations = get_identity_revocations(delegated_token.clone(), public_key)
        .expect("Failed to get revocations");

    println!("   Delegated token revocations:");
    for rev in &delegated_revocations {
        println!("   - {rev}");
    }
    println!();

    // Example 3: Multi-level Delegation
    println!("3. Further delegating to 'urn:hessra:alice:laptop:browser'");
    let browser_identity = "urn:hessra:alice:laptop:browser".to_string();
    let browser_token = add_identity_attenuation_to_token(
        delegated_token.clone(),
        browser_identity.clone(),
        public_key,
        TokenTimeConfig::default(),
    )
    .expect("Failed to delegate token");

    let browser_revocations = get_identity_revocations(browser_token.clone(), public_key)
        .expect("Failed to get revocations");

    println!("   Multi-level delegated token revocations:");
    for rev in &browser_revocations {
        println!("   - {rev}");
    }
    println!();

    // Demonstrate revocation use cases
    println!("=== Revocation Use Cases ===\n");

    println!("Tree-based revocation:");
    println!("- Revoking alice's base token (block 0) would invalidate ALL delegations");
    println!("- Revoking laptop delegation (block 1) would invalidate laptop and browser tokens");
    println!("- Revoking browser delegation (block 2) would only invalidate the browser token");
    println!();

    println!("Example revocation list that would block the browser token:");
    println!("  revoked_ids: [");
    for rev in &browser_revocations {
        println!(
            "    \"{}\",  // {}",
            rev.revocation_id.to_hex(),
            rev.identity
        );
    }
    println!("  ]");
    println!();

    println!("To check if a token is revoked:");
    println!("1. Extract all revocation IDs from the token");
    println!("2. Check if ANY of them are in your revocation list");
    println!("3. If yes, reject the token");
}
