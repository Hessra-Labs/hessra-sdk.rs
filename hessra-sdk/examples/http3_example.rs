use hessra_sdk::{Hessra, Protocol};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the client with HTTP/3
    let mut client = Hessra::builder()
        .base_url("test.hessra.net")
        .port(443)
        .protocol(Protocol::Http3)
        .mtls_cert(include_str!("../../certs/client.crt"))
        .mtls_key(include_str!("../../certs/client.key"))
        .server_ca(include_str!("../../certs/ca-2030.pem"))
        .build()?;

    // Setup the client with the public key
    client.setup().await?;

    // Request a token for a specific resource
    let resource = "resource1".to_string();
    let subject = "uri:urn:test:argo-cli0".to_string();
    let token = client
        .request_token(resource.clone(), "read".to_string())
        .await?;
    println!("Received token: {}", token);

    // Verify the token
    match client
        .verify_token(token, subject, resource, "read".to_string())
        .await
    {
        Ok(_) => println!("Token verified successfully"),
        Err(e) => println!("Token verification failed: {}", e),
    }

    Ok(())
}
