//! Example of using the Hessra API client
//!
//! This example demonstrates how to create and use the Hessra API client
//! to request and verify tokens.

use hessra_api::{ApiError, HessraClient};
use hessra_config::{HessraConfig, Protocol};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment variables
    let config = HessraConfig::from_env("HESSRA")?;

    // Create a client using the configuration
    let client = HessraClient::builder().from_config(&config).build()?;

    // Request a token for a resource
    let resource = "example-resource".to_string();
    println!("Requesting token for resource: {}", resource);

    let token = match client.request_token(resource.clone()).await {
        Ok(token) => {
            println!("Token received successfully");
            token
        }
        Err(e) => {
            eprintln!("Error requesting token: {}", e);
            return Err(Box::new(e));
        }
    };

    // Verify the token
    let subject = "example-user".to_string();
    println!(
        "Verifying token for subject: {} and resource: {}",
        subject, resource
    );

    match client.verify_token(token, subject, resource).await {
        Ok(response) => {
            println!("Token verification successful: {}", response);
        }
        Err(e) => {
            eprintln!("Error verifying token: {}", e);
            return Err(Box::new(e));
        }
    }

    // Retrieve the server's public key
    println!("Retrieving public key from server");
    match client.get_public_key().await {
        Ok(public_key) => {
            println!("Public key retrieved successfully");
            println!("Key: {}", public_key);
        }
        Err(e) => {
            eprintln!("Error retrieving public key: {}", e);
            return Err(Box::new(e));
        }
    }

    // Example of using the static method to fetch the public key without a client
    println!("Fetching public key without a client");
    match HessraClient::fetch_public_key(config.base_url(), config.port(), config.server_ca()).await
    {
        Ok(public_key) => {
            println!("Public key fetched successfully");
            println!("Key: {}", public_key);
        }
        Err(e) => {
            eprintln!("Error fetching public key: {}", e);
            return Err(Box::new(e));
        }
    }

    println!("Example completed successfully");
    Ok(())
}
