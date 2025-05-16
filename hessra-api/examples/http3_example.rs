//! Example of using the Hessra API client with HTTP/3
//!
//! This example demonstrates how to create and use the Hessra API client with HTTP/3
//! to request and verify tokens.
//!
//! Note: This example requires the "http3" feature to be enabled.

use hessra_api::HessraClient;
use hessra_config::{HessraConfig, Protocol};

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
        .protocol(Protocol::Http3)
        .build()?;

    // Create a client using the configuration
    println!("Creating HTTP/3 client");
    let client = HessraClient::builder().from_config(&config).build()?;

    // Request a token for a resource
    let resource = "resource1".to_string();
    println!("Requesting token for resource: {}", resource);

    let token = match client
        .request_token(resource.clone(), "read".to_string())
        .await
    {
        Ok(token) => {
            println!("Token received successfully");
            token
        }
        Err(e) => {
            eprintln!("Error requesting token: {}", e);
            return Err(e.into());
        }
    };

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

    // Example of using the static method to fetch the public key with HTTP/3
    println!("Fetching public key using HTTP/3");
    match HessraClient::fetch_public_key_http3(
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

    println!("HTTP/3 example completed successfully");
    Ok(())
}
