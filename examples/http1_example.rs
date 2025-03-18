use hessra_sdk::{HessraClient, Protocol};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the client with HTTP/1.1
    let client = HessraClient::builder()
        .base_url("test.hessra.net")
        .port(443)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../certs/client.crt"))
        .mtls_key(include_str!("../certs/client.key"))
        .server_ca(include_str!("../certs/ca-2030.pem"))
        .build()?;

    // Request a token for a specific resource
    let resource = "resource1".to_string();
    let token = client.request_token(resource.clone()).await?;
    println!("Received token: {}", token);

    // Verify the token
    let verification_result = client
        .verify_token(token, "uri:urn:test:argo-cli0".to_string(), resource)
        .await?;
    println!("Token verification result: {}", verification_result);

    Ok(())
}
