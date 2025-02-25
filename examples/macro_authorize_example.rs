use hessra_macros::{authorize, request_authorization};
use hessra_sdk::{set_default_config, HessraConfig, Protocol};
use std::error::Error;

// Example function that requests a token using the request_authorization macro
#[allow(E0515)]
#[request_authorization("protected-resource")]
async fn get_token() -> String {
    // Token is obtained by the macro and can be returned
    "sample_token".to_string() // In a real scenario, you would return the token obtained by the macro
}

// Example function using the authorize macro with explicit config
#[authorize("protected-resource", config)]
async fn authorized_with_config(token: String, config: HessraConfig) {
    println!("Authorized function executed with explicit config! Resource: protected-resource");
    println!("Token: {}", token);
    // This function is only called if the token is valid
}

// Example function using the authorize macro with global config
#[allow(E0515)]
#[authorize("protected-resource")]
async fn authorized_with_global_config(token: String) {
    println!("Authorized function executed with global config! Resource: protected-resource");
    println!("Token: {}", token);
    // This function is only called if the token is valid
}

// Example function using the authorize macro with individual parameters
#[authorize("protected-resource")]
async fn authorized_with_params(
    token: String,
    base_url: String,
    mtls_cert: String,
    mtls_key: String,
    server_ca: String,
) {
    println!(
        "Authorized function executed with individual parameters! Resource: protected-resource"
    );
    println!("Token: {}", token);
    // This function is only called if the token is valid
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create a configuration
    let config = HessraConfig::new(
        "https://test.hessra.net",            // base URL
        Some(443),                            // port (optional)
        Protocol::Http1,                      // protocol
        include_str!("../certs/client.crt"),  // mTLS certificate
        include_str!("../certs/client.key"),  // mTLS key
        include_str!("../certs/ca-2030.pem"), // Server CA certificate
    );

    // Set as the default configuration for functions that use global config
    set_default_config(config.clone())?;

    // Get a token to use with the authorized functions
    let token = get_token().await;

    // Call the authorized function with explicit config
    authorized_with_config(token.clone(), config.clone()).await;

    // Call the authorized function with global config
    authorized_with_global_config(token.clone()).await;

    // Call the authorized function with individual parameters
    authorized_with_params(
        token.clone(),
        "https://test.hessra.net".to_string(),
        include_str!("../certs/client.crt").to_string(),
        include_str!("../certs/client.key").to_string(),
        include_str!("../certs/ca-2030.pem").to_string(),
    )
    .await;

    Ok(())
}
