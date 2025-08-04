use hessra_sdk::{Hessra, Protocol};
use std::error::Error;

static BASE_URL: &str = "test.hessra.net";
static PORT: u16 = 443;
static MTLS_CERT: &str = include_str!("../../certs/client.crt");
static MTLS_KEY: &str = include_str!("../../certs/client.key");
static SERVER_CA: &str = include_str!("../../certs/ca-2030.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the client with HTTP/1.1
    let mut client = Hessra::builder()
        .base_url(BASE_URL)
        .port(PORT)
        .protocol(Protocol::Http1) // This is the default protocol, so leaving it out is also valid
        .mtls_cert(MTLS_CERT)
        .mtls_key(MTLS_KEY)
        .server_ca(SERVER_CA)
        .build()?;

    // Setup the client with the public key
    // This will fetch the public key from the server and set it in the client
    client.setup().await?;

    // Request a token for a specific resource
    let resource = "resource1".to_string();
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

    // Verify the token, this will verify the token locally since
    // the authorization service public key is set in the client
    match client
        .verify_token(
            token,
            "uri:urn:test:argo-cli0".to_string(),
            resource,
            "read".to_string(),
        )
        .await
    {
        Ok(_) => println!("Token verified successfully"),
        Err(e) => println!("Token verification failed: {}", e),
    }

    Ok(())
}
