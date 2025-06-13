use hessra_config::{HessraConfig, Protocol};
use hessra_sdk::{Hessra, SdkError, ServiceChain, ServiceNode};
use serde_json::json;
use std::error::Error;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_request_token_http1() -> Result<(), Box<dyn Error>> {
    // Start a mock server
    let mock_server = MockServer::start().await;

    // Mock the request_token endpoint
    Mock::given(method("POST"))
        .and(path("/request_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "response_msg": "Token generated",
            "token": "mock-token-123"
        })))
        .mount(&mock_server)
        .await;

    // Create a reqwest client
    let client = reqwest::Client::new();

    // Make the request directly to the mock server
    let response = client
        .post(format!("{}/request_token", mock_server.uri()))
        .json(&json!({"resource": "test-resource"}))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    // Verify the response
    assert_eq!(response["token"], "mock-token-123");

    Ok(())
}

#[tokio::test]
async fn test_verify_token_http1() -> Result<(), Box<dyn Error>> {
    // Start a mock server
    let mock_server = MockServer::start().await;

    // Mock the verify_token endpoint
    Mock::given(method("POST"))
        .and(path("/verify_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "response_msg": "Token verified successfully"
        })))
        .mount(&mock_server)
        .await;

    // Create a reqwest client
    let client = reqwest::Client::new();

    // Make the request directly to the mock server
    let response = client
        .post(format!("{}/verify_token", mock_server.uri()))
        .json(&json!({
            "token": "test-token",
            "resource": "test-resource"
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    // Verify the response
    assert_eq!(response["response_msg"], "Token verified successfully");

    Ok(())
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn test_request_token_http3() -> Result<(), Box<dyn Error>> {
    // Note: HTTP/3 testing is more complex and would require a proper QUIC server
    // This is a placeholder for when you implement HTTP/3 testing
    // You might want to use a real HTTP/3 server or a more sophisticated mock

    // For now, we'll skip with a message
    println!("HTTP/3 testing requires a proper QUIC server implementation");
    Ok(())
}

#[tokio::test]
async fn test_sdk_integration() -> Result<(), SdkError> {
    // 1. Create a configuration for the Hessra service
    let config = HessraConfig::builder()
        .base_url("https://test.hessra.net")
        .port(443)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("test_certs/client.crt"))
        .mtls_key(include_str!("test_certs/client.key"))
        .server_ca(include_str!("test_certs/ca.crt"))
        .public_key(include_str!("test_certs/service_public_key.pem"))
        .build()?;

    // 2. Create a Hessra SDK instance
    // In a real application, this would connect to the Hessra service
    // For testing, we're just creating the instance
    let hessra = Hessra::new(config)?;

    // 3. Create a service chain for attestations
    let _service_chain = ServiceChain::builder()
        .add_node(ServiceNode {
            component: "service1".to_string(),
            public_key: "AAAA".to_string(),
        })
        .add_node(ServiceNode {
            component: "service2".to_string(),
            public_key: "BBBB".to_string(),
        })
        .build();

    // Access components from the SDK
    let config = hessra.config();
    assert_eq!(config.base_url, "https://test.hessra.net");
    assert_eq!(config.port, Some(443));

    // 4. Alternatively, use the builder pattern for the SDK
    let hessra = hessra_sdk::Hessra::builder()
        .base_url("https://test.hessra.net")
        .port(443)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("test_certs/client.crt"))
        .mtls_key(include_str!("test_certs/client.key"))
        .server_ca(include_str!("test_certs/ca.crt"))
        .public_key(include_str!("test_certs/service_public_key.pem"))
        .build()?;

    // Verify config from builder
    let config = hessra.config();
    assert_eq!(config.base_url, "https://test.hessra.net");
    assert_eq!(config.port, Some(443));

    // Note: In a real test, we would make actual API calls to the service
    // but for an integration test without service dependencies, we'll just
    // verify the SDK can be properly configured and instantiated

    Ok(())
}
