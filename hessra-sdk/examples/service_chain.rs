use hessra_sdk::{fetch_public_key, Hessra, Protocol, ServiceChain, ServiceNode};
use std::error::Error;

static BASE_URL: &str = "test.hessra.net";
static PORT: u16 = 443;
static CA_CERT: &str = include_str!("../../certs/ca-2030.pem");
/// This example demonstrates how to use service chains to attest and verify
/// the flow of a token through multiple services.
///
/// The example simulates a service chain with three nodes:
/// 1. auth-service: The authentication service that issues the token
/// 2. payment-service: A payment processing service
/// 3. order-service: An order management service
///
/// Each service verifies that previous services in the chain have attested
/// the token before adding its own attestation.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Personal keypairs for each node (in a real scenario, these would be generated and stored securely)
    let auth_keypair = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIBnMQ6SB/juVEWCLh/08eSiw5EXeClS4uUq1gFNpkK1I\ngSEA5XYYBYsdLgOBqYE8FAWDDV7X1gNxc4TvVV2cwM+mXYM=\n-----END PRIVATE KEY-----";
    let payment_keypair = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIAzPrr2kfWdHnkNwqEwBKokMg/IFX97w8eD5LvSdDC1W\ngSEAeO9CVcTJq1xxhtbbR2B1iwZhbAQqJTgyOuOwWAlANLY=\n-----END PRIVATE KEY-----";
    let order_keypair = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIBGKjvJA+jpBYyKl/wWOa81fORZdQtkMHwahnevMiTd/\ngSEAGuvFpu78VpBRkmpqr1VWjlPttHXy8uuQRSJgk5HYgRM=\n-----END PRIVATE KEY-----";
    let public_key = fetch_public_key(BASE_URL, Some(PORT), CA_CERT).await?;

    let auth_service_node = ServiceNode {
        component: "auth_service".to_string(),
        public_key: "ed25519/e57618058b1d2e0381a9813c1405830d5ed7d603717384ef555d9cc0cfa65d83"
            .to_string(), // derived from auth_keypair
    };

    let payment_service_node = ServiceNode {
        component: "payment_service".to_string(),
        public_key: "ed25519/78ef4255c4c9ab5c7186d6db4760758b06616c042a2538323ae3b058094034b6"
            .to_string(), // derived from payment_keypair
    };

    let order_service_node = ServiceNode {
        component: "order_service".to_string(),
        public_key: "ed25519/1aebc5a6eefc569051926a6aaf55568e53edb475f2f2eb904522609391d88113"
            .to_string(), // derived from order_keypair
    };

    // Initialize the service chain with public keys of each node
    // Note: In a real implementation, these public keys would be extracted from the keypairs
    // and registered or configured with the authorization server
    let full_service_chain = ServiceChain::new()
        .with_node(auth_service_node)
        .with_node(payment_service_node)
        .with_node(order_service_node);

    println!("=== Service Chain Example ===");
    println!(
        "Service chain has {} nodes",
        full_service_chain.nodes().len()
    );

    // Actual client
    let client = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../../certs/client.crt"))
        .mtls_key(include_str!("../../certs/client.key"))
        .server_ca(CA_CERT)
        .public_key(public_key.clone())
        .build()?;

    println!("Client constructed successfully");

    // Request a token for a specific resource
    let resource = "order_service".to_string();
    let token_response = client
        .request_token(resource.clone(), "read".to_string())
        .await?;

    if let Some(pending) = &token_response.pending_signoffs {
        println!("Token has {} pending signoffs", pending.len());
    }

    let token = token_response.token.ok_or("No token in response")?;
    println!(
        "Received token: {}...",
        &token[..std::cmp::min(50, token.len())]
    );

    // --- AUTH SERVICE ---
    println!("\n=== Auth Service (Node 1) ===");

    // Create a client for the auth service
    let auth_client = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../../certs/client.crt"))
        .mtls_key(include_str!("../../certs/client.key"))
        .server_ca(CA_CERT)
        .public_key(public_key.clone())
        .personal_keypair(auth_keypair)
        .build()?;

    // The auth service is the first in the chain, so it doesn't need to verify
    // any previous attestations - it only adds its own
    println!("Adding auth-service attestation to token");
    let token_with_auth = auth_client.attest_service_chain_token(token, resource.clone())?;

    // --- PAYMENT SERVICE ---
    println!("\n=== Payment Service (Node 2) ===");

    // Create a client for the payment service
    let payment_client = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../../certs/client.crt"))
        .mtls_key(include_str!("../../certs/client.key"))
        .server_ca(CA_CERT)
        .public_key(public_key.clone())
        .personal_keypair(payment_keypair)
        .build()?;

    // Payment service verifies the token has passed through auth service
    println!("Verifying token has attestation from auth-service");

    // We specify this node's name so the verification only checks nodes up to payment-service
    payment_client.verify_service_chain_token_local(
        token_with_auth.clone(),
        "uri:urn:test:argo-cli0",
        resource.clone(),
        "read".to_string(),
        &full_service_chain,
        Some("payment_service".to_string()),
    )?;
    println!("Verification result: {:?}", ());

    // Add payment service attestation to the token
    println!("Adding payment_service attestation to token");
    let token_with_payment =
        payment_client.attest_service_chain_token(token_with_auth, resource.clone())?;

    // --- ORDER SERVICE ---
    println!("\n=== Order Service (Node 3) ===");

    // Create a client for the order service
    let order_client = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../../certs/client.crt"))
        .mtls_key(include_str!("../../certs/client.key"))
        .server_ca(CA_CERT)
        .public_key(public_key.clone())
        .personal_keypair(order_keypair)
        .build()?;

    // Order service verifies the token has passed through both auth and payment
    println!("Verifying token has attestations from auth-service and payment-service");

    // As the last service in the chain, we specify our name to verify all previous nodes
    order_client.verify_service_chain_token_local(
        token_with_payment.clone(),
        "uri:urn:test:argo-cli0",
        resource.clone(),
        "read".to_string(),
        &full_service_chain,
        Some("order_service".to_string()),
    )?;
    println!("Verification result: {:?}", ());

    // Add order service attestation (though no service will need to verify this)
    println!("Adding order-service attestation to token");
    let final_token =
        order_client.attest_service_chain_token(token_with_payment, resource.clone())?;

    // A hypothetical verification of the complete chain by a client
    println!("\n=== Final Verification ===");
    println!("Verifying the complete chain");

    // To verify the entire chain, we don't specify a component name (or use None)
    order_client.verify_service_chain_token_local(
        final_token,
        "uri:urn:test:argo-cli0",
        resource.clone(),
        "read".to_string(),
        &full_service_chain,
        None, // Verify the entire chain
    )?;
    println!("Final verification result: {:?}", ());

    println!("\nService chain attestation example completed successfully!");

    Ok(())
}
