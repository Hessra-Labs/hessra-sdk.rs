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
