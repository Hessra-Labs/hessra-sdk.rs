use hessra_macros::request_authorization;
use hessra_sdk::{set_default_config, HessraConfig, Protocol};
use std::error::Error;

// Example function using the request_authorization macro with explicit config
#[request_authorization("resource-one", config)]
async fn protected_with_config(config: HessraConfig) {
    println!("Protected function executed with explicit config! Resource: resource-one");
    // The token has already been obtained by the macro
}

// Example function using the request_authorization macro with global config
#[allow(E0515)]
#[request_authorization("resource-two")]
async fn protected_with_global_config() {
    println!("Protected function executed with global config! Resource: resource-two");
    // The token has already been obtained by the macro using the global configuration
}

// Example function using the request_authorization macro with individual parameters
#[request_authorization("resource-three")]
async fn protected_with_params(
    base_url: String,
    mtls_cert: String,
    mtls_key: String,
    server_ca: String,
) {
    println!("Protected function executed with individual parameters! Resource: resource-three");
    // The token has already been obtained by the macro using the provided parameters
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

    // Call the protected function with explicit config
    protected_with_config(config.clone()).await;

    // Call the protected function with global config
    protected_with_global_config().await;

    // Call the protected function with individual parameters
    protected_with_params(
        "https://test.hessra.net".to_string(),
        include_str!("../certs/client.crt").to_string(),
        include_str!("../certs/client.key").to_string(),
        include_str!("../certs/ca-2030.pem").to_string(),
    )
    .await;

    Ok(())
}
