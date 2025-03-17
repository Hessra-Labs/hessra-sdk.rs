use hessra_sdk::{HessraClient, Protocol, ServiceChain, ServiceNode};
use std::error::Error;

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
    // Personal keypairs for each node (in a real scenario, these would be generated securely)
    let auth_keypair = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIBnMQ6SB/juVEWCLh/08eSiw5EXeClS4uUq1gFNpkK1I\ngSEA5XYYBYsdLgOBqYE8FAWDDV7X1gNxc4TvVV2cwM+mXYM=\n-----END PRIVATE KEY-----";
    let payment_keypair = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIAzPrr2kfWdHnkNwqEwBKokMg/IFX97w8eD5LvSdDC1W\ngSEAeO9CVcTJq1xxhtbbR2B1iwZhbAQqJTgyOuOwWAlANLY=\n-----END PRIVATE KEY-----";
    let order_keypair = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIBGKjvJA+jpBYyKl/wWOa81fORZdQtkMHwahnevMiTd/\ngSEAGuvFpu78VpBRkmpqr1VWjlPttHXy8uuQRSJgk5HYgRM=-----END PRIVATE KEY-----";
    let public_key =
        HessraClient::fetch_public_key("127.0.0.1", Some(4433), include_str!("../certs/ca.crt"))
            .await?;

    // Initialize the service chain with public keys of each node
    // Note: In a real implementation, these public keys would be extracted from the keypairs
    // and registered with the authorization server
    let service_chain = ServiceChain::new()
        .with_node(ServiceNode::new(
            "auth_service",
            "ed25519/e57618058b1d2e0381a9813c1405830d5ed7d603717384ef555d9cc0cfa65d83", // derived from auth_keypair
        ))
        .with_node(ServiceNode::new(
            "payment_service",
            "ed25519/78ef4255c4c9ab5c7186d6db4760758b06616c042a2538323ae3b058094034b6", // derived from payment_keypair
        ))
        .with_node(ServiceNode::new(
            "order_service",
            "ed25519/1aebc5a6eefc569051926a6aaf55568e53edb475f2f2eb904522609391d88113", // derived from order_keypair
        ));

    println!("=== Service Chain Example ===");
    println!("Service chain has {} nodes", service_chain.nodes().len());

    // Actual client
    let client = HessraClient::builder()
        .base_url("127.0.0.1")
        .port(4433)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../certs/client.crt"))
        .mtls_key(include_str!("../certs/client.key"))
        .server_ca(include_str!("../certs/ca.crt"))
        .build()?;

    // Request a token for a specific resource
    let resource = "order_service".to_string();
    let token = client.request_token(resource.clone()).await?;
    println!("Received token: {}", token);

    // --- AUTH SERVICE ---
    println!("\n=== Auth Service (Node 1) ===");

    // Create a client for the auth service
    let auth_client = HessraClient::builder()
        .base_url("127.0.0.1")
        .port(4433)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../certs/client.crt"))
        .mtls_key(include_str!("../certs/client.key"))
        .server_ca(include_str!("../certs/ca.crt"))
        .public_key(public_key.clone())
        .personal_keypair(auth_keypair)
        .build()?;

    // The auth service is the first in the chain, so it doesn't need to verify
    // any previous attestations - it only adds its own
    println!("Adding auth-service attestation to token");
    let token_with_auth = auth_client.attenuate_service_chain_token(token, resource.clone())?;

    // --- PAYMENT SERVICE ---
    println!("\n=== Payment Service (Node 2) ===");

    // Create a client for the payment service
    let payment_client = HessraClient::builder()
        .base_url("127.0.0.1")
        .port(4433)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../certs/client.crt"))
        .mtls_key(include_str!("../certs/client.key"))
        .server_ca(include_str!("../certs/ca.crt"))
        .public_key(public_key.clone())
        .personal_keypair(payment_keypair)
        .build()?;

    // Payment service verifies the token has passed through auth service
    println!("Verifying token has attestation from auth-service");

    // We specify this node's name so the verification only checks nodes up to payment-service
    let verification_result = payment_client
        .verify_service_chain_token(
            token_with_auth.clone(),
            Some("uri:urn:test:argo-cli0".to_string()),
            resource.clone(),
            Some("payment_service".to_string()),
            Some(&service_chain),
        )
        .await?;
    println!("Verification result: {}", verification_result);

    // Add payment service attestation to the token
    println!("Adding payment_service attestation to token");
    let token_with_payment =
        payment_client.attenuate_service_chain_token(token_with_auth, resource.clone())?;

    // --- ORDER SERVICE ---
    println!("\n=== Order Service (Node 3) ===");

    // Create a client for the order service
    let order_client = HessraClient::builder()
        .base_url("127.0.0.1")
        .port(4433)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../certs/client.crt"))
        .mtls_key(include_str!("../certs/client.key"))
        .server_ca(include_str!("../certs/ca.crt"))
        .public_key(public_key.clone())
        .personal_keypair(order_keypair)
        .build()?;

    // Order service verifies the token has passed through both auth and payment
    println!("Verifying token has attestations from auth-service and payment-service");

    // As the last service in the chain, we specify our name to verify all previous nodes
    let verification_result = order_client
        .verify_service_chain_token(
            token_with_payment.clone(),
            Some("uri:urn:test:argo-cli0".to_string()),
            resource.clone(),
            Some("order_service".to_string()),
            Some(&service_chain),
        )
        .await?;
    println!("Verification result: {}", verification_result);

    // Add order service attestation (though no service will need to verify this)
    println!("Adding order-service attestation to token");
    let final_token =
        order_client.attenuate_service_chain_token(token_with_payment, resource.clone())?;

    // A hypothetical verification of the complete chain by a client
    println!("\n=== Final Verification ===");
    println!("Verifying the complete chain");

    // To verify the entire chain, we don't specify a component name (or use None)
    let final_verification = order_client
        .verify_service_chain_token(
            final_token,
            Some("uri:urn:test:argo-cli0".to_string()),
            resource.clone(),
            None, // Verify the entire chain
            Some(&service_chain),
        )
        .await?;
    println!("Final verification result: {}", final_verification);

    println!("\nService chain attestation example completed successfully!");

    Ok(())
}
