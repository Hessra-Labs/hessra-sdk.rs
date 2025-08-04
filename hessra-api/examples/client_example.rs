//! Example of using the Hessra API client
//!
//! This example demonstrates how to create and use the Hessra API client
//! to request and verify tokens.

use hessra_api::HessraClient;
use hessra_config::HessraConfig;

static BASE_URL: &str = "test.hessra.net";
static PORT: u16 = 443;
static MTLS_CERT: &str = include_str!("../../certs/client.crt");
static MTLS_KEY: &str = include_str!("../../certs/client.key");
static SERVER_CA: &str = include_str!("../../certs/ca-2030.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    // Create a configuration
    let config = HessraConfig::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .mtls_cert(MTLS_CERT)
        .mtls_key(MTLS_KEY)
        .server_ca(SERVER_CA)
        .build()?;

    // Create a client using the configuration
    let client = HessraClient::builder().from_config(&config).build()?;

    // Request a token for a resource
    // This is requesting a token for allowing a read operation on resource1
    // The subject is the identity of the requester, in this case "argo-cli0"
    // which is embedded as "URI:urn:test:argo-cli0" in the x509 certificate,
    // mtls_cert.
    let resource = "resource1".to_string();
    println!("Requesting token for resource: {}", resource);

    let token_response = match client
        .request_token(resource.clone(), "read".to_string())
        .await
    {
        Ok(response) => {
            println!("Token received successfully");
            if let Some(pending) = &response.pending_signoffs {
                println!("Token has {} pending signoffs", pending.len());
            }
            response
        }
        Err(e) => {
            eprintln!("Error requesting token: {}", e);
            return Err(e.into());
        }
    };

    let token = token_response.token.ok_or("No token in response")?;

    // Verify the token, this will verify using the remote authorization
    // service API since the service's public key is not known yet to the client
    let subject = "uri:urn:test:argo-cli0".to_string();
    println!(
        "Verifying token for subject: {} and resource: {}",
        subject, resource
    );

    match client
        .verify_token(token, subject, resource, "read".to_string())
        .await
    {
        Ok(response) => {
            println!("Token verification successful: {}", response);
        }
        Err(e) => {
            eprintln!("Error verifying token: {}", e);
            return Err(e.into());
        }
    }

    // Retrieve the server's public key so tokens can be verified locally,
    // without having to call the remote authorization service API.
    println!("Retrieving public key from server");
    match client.get_public_key().await {
        Ok(public_key) => {
            println!("Public key retrieved successfully");
            println!("Key: {}", public_key);
        }
        Err(e) => {
            eprintln!("Error retrieving public key: {}", e);
            return Err(e.into());
        }
    }

    // Example of using the static method to fetch the public key without a client
    println!("Fetching public key without a client");
    match HessraClient::fetch_public_key(
        config.base_url.clone(),
        config.port,
        config.server_ca.clone(),
    )
    .await
    {
        Ok(public_key) => {
            println!("Public key fetched successfully");
            println!("Key: {}", public_key);
        }
        Err(e) => {
            eprintln!("Error fetching public key: {}", e);
            return Err(e.into());
        }
    }

    println!("Example completed successfully");
    Ok(())
}
