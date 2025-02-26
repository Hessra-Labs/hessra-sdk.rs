use hessra_sdk::{HessraClient, HessraConfig, Protocol};
use std::error::Error;
use std::fs;
use std::path::Path;

/// This example demonstrates different ways to fetch, store, and use the public key
/// from the Hessra authentication service.
///
/// The public key is used for local token verification, allowing applications to verify
/// tokens without making network requests to the authorization service.
///
/// The example shows:
/// 1. Fetching the public key directly without creating a client
/// 2. Getting the public key using an existing client
/// 3. Storing the public key in a configuration
/// 4. Loading a configuration with an embedded public key
///
/// Note: This example requires a running Hessra service at auth.hessra.net:443.
/// The example will fail if the service is not available.

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Example 1: Fetch the public key directly without a client
    println!("Example 1: Fetching public key directly");
    let public_key =
        HessraClient::fetch_public_key("127.0.0.1", Some(4433), include_str!("../certs/ca.crt"))
            .await?;
    println!("Received public key: {}", public_key);

    // Save the public key to a file for later use
    let key_path = "./public_key.pem";
    fs::write(key_path, &public_key)?;
    println!("Saved public key to {}", key_path);

    // Example 2: Fetch the public key using an existing client
    println!("\nExample 2: Fetching public key using a client");
    let client = HessraClient::builder()
        .base_url("test.hessra.net")
        .port(443)
        .protocol(Protocol::Http1)
        .mtls_cert(include_str!("../certs/client.crt"))
        .mtls_key(include_str!("../certs/client.key"))
        .server_ca(include_str!("../certs/ca-2030.pem"))
        .build()?;

    let public_key_from_client = client.get_public_key().await?;
    println!(
        "Received public key from client: {}",
        public_key_from_client
    );

    // Example 3: Store the public key in the configuration
    println!("\nExample 3: Managing public key with configuration");
    let mut config = HessraConfig::new(
        "https://test.hessra.net",
        Some(443),
        Protocol::Http1,
        include_str!("../certs/client.crt"),
        include_str!("../certs/client.key"),
        include_str!("../certs/ca-2030.pem"),
    );

    // Fetch and store the public key in the configuration
    let public_key_from_config = config.fetch_and_store_public_key().await?;
    println!("Fetched and stored public key: {}", public_key_from_config);

    // Later, get the public key from configuration without another fetch
    let stored_key = config.get_or_fetch_public_key().await?;
    println!("Retrieved stored key: {}", stored_key);

    // Example 4: Load a configuration with an embedded public key
    println!("\nExample 4: Creating a configuration with an embedded public key");

    // Create a config JSON file with an embedded public key
    let config_json = format!(
        r#"{{
            "base_url": "https://test.hessra.net",
            "port": 443,
            "protocol": "Http1",
            "mtls_cert": "-----BEGIN CERTIFICATE-----\nMIIDpzCCAo+gAwIBAgIJAKop1rAO2QNaMA0GCSqGSIb3DQEBCwUAMGoxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp\nc2NvMRIwEAYDVQQKDAlIZXNzcmEgQ0ExGjAYBgNVBAMMEXRlc3QuaGVzc3JhLm5l\ndCBDQTAeFw0yMjA1MDUxOTA1MTlaFw0yNDAyMDMxOTA1MTlaMGgxCzAJBgNVBAYT\nAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv\nMQ8wDQYDVQQKDAZIZXNzcmExGzAZBgNVBAMMEnRlc3QuaGVzc3JhLm5ldCBTVkMw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD04a+fj2EwwgL5B5bKo9mZ\ntL3M8wOXO5ClUHFJeNAcm+XFYQIRPYJWWq2qJLq08IWxECKAUxgdUaRPElSQK7zX\nWpSZvZfGcCG2MlNKJnYDw+uL95a5FfnZ9Pp//C0Xmh+fIpLdEVDLw59+bueKUGIS\nCyKjDYxyZRMKSB8NqWFiX3P2XfTh4Ke2CA+k9hfn06YC1sBwlCjMp/UedNFK3FRc\nT21Zr4dcsXAThQiKEaE6v8Xo9OsGJapGKMk5T1MYuzYSFZpGI5nVGJDZ8pQ0J9CM\nvr7JcynWf+0liJ5o/iDtUhLwmXB1kRQFTuD5/AMVciO/9+DXn2XKJm9UiNGkgS3L\nAgMBAAGjUDBOMB0GA1UdDgQWBBSQplzWfQe2M/4zgRAMQQnpwfnbbjAfBgNVHSME\nGDAWgBQIHAZQPAwp0Y3xU0MYpH7AngrlGDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3\nDQEBCwUAA4IBAQASzMi7nk/B/Mb7sCIxBIrHe6vBgPAGWbhYdpUNH9lO0IJj3/Z+\noDdrbL4nfJjyWCefE4+nDgJPC8Nm//nG8jxZQhPSJtYVzPH7UmHs6F9lS+cBbFQ0\nAJGzC2DJTHGMqQ9UTh2sMgEUKnSdXCPWgfbdcN0CyP9xV5ZRxPCmvRIxrdpZfFsw\ndQ6PZGcGt4xzUYx46raa/z/0LlZ/MCnI0/6vlDPGEV9Gi1jvcnHxQjkXaA+0YENE\nE8pQCnP8nL5iqQngXHYi25sDj7nZKL6SSbgFBdP5W6N43n/dZQ9T55iup6us/TBJ\nTFHSU+7XDy1oANcArSYGZZsPG5MM7Yzc6KhP\n-----END CERTIFICATE-----\n",
            "mtls_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD04a+fj2EwwgL5\nB5bKo9mZtL3M8wOXO5ClUHFJeNAcm+XFYQIRPYJWWq2qJLq08IWxECKAUxgdUaRP\nElSQK7zXWpSZvZfGcCG2MlNKJnYDw+uL95a5FfnZ9Pp//C0Xmh+fIpLdEVDLw59+\nbueKUGISCyKjDYxyZRMKSB8NqWFiX3P2XfTh4Ke2CA+k9hfn06YC1sBwlCjMp/Ue\ndNFK3FRcT21Zr4dcsXAThQiKEaE6v8Xo9OsGJapGKMk5T1MYuzYSFZpGI5nVGJDZ\n8pQ0J9CMvr7JcynWf+0liJ5o/iDtUhLwmXB1kRQFTuD5/AMVciO/9+DXn2XKJm9U\niNGkgS3LAgMBAAECggEAJm0vQ37+HD+4aPx7l4oHlXLMzPbI50PQD91Z8oWjThm/\n5KIp8Sx5wEUGjcbzVw0jvGKdvbmDKJGXbmRvUBmzFbv9+HfkUxjDEX9XCMvskW3M\nqIHQVfNJ/xo90mHj4zsfpNkDb/ZTJw3NZEXIqDlIueWKh7/qf2FDfzKLLz5xt0wj\nCyN5sQK2HO4yVGZROMVyK1qvU5CzZ6FNrcJqAH2GvWYmAiGSJNeRQSIJzqzP1sJ/\nMYEzP6K1Sr8DYCDYvfM/4CQQkYsZCYGS8GFoT9ZUQuVfn0RVClaTT/m+pu7S21gT\npHHOGR7qp3sSdPK1+nf2qlDEXDL4wYcjTOYQDN9XQQKBgQD/2Q30cmeOruFftDPe\ntwz2P5ZcDGRgOvxzw1X9qvQRWzEjLXZmGDezvvAO0A9g+fXMeuUGP2kc8gAM+rpL\naqGZlF5+ObkgVRxvEIuK1U04JA0Qy+WRo8Kk7dj8JzOUPcYbXfyUwzNZvYt4cKMz\nbDsf9JMrP/MwbfMKer99p7oZiwKBgQD0+Bh6RAdwm7PtHj5fFXH1gfFEbvD2g+MB\nzauLM1UAOZzforZMfPa2Z9Voybw3Jm8A5l4JawQvC5/9AHsKhQGwCXKz1Q2vu8XY\nCpZXr3V8Q+GciD4xTxXRVtg+pHxI1ogDxnF1/i7qhkgvREtxWj16serf6VPKXoHm\n2IdgJRdLwQKBgQC/OtBhzMrpqMB9nz2uZwdyAZDnwX5whKg7/UmRLjYZqwMZ0ynC\nJsAGnFx9jvXbvEzOjJ+kQh2uxZFJo0QZSU42NiiFoBWGuVKOCrJVxEmrOlsJ0WSn\nWXVrDLQ7NKHFvDlMZ804u0QXAz+ZGvZJk9t+gxZ+TZkhSYGOdw51oVfjqQKBgQDX\n96IoR3gt9RBXQHo290Z5EFE4dVfI8HNK/30a0uFbcJoFiJ1K3wpEZ0u9nfNXXbJn\nYkto4ic5yLGDUNKgOC+YPsKmLkfO5jz6YITfHC/EYQUw5bqYKC9+9fV9/e/Sn0S3\na1APXbx+iHZcriXiU3nUzjzK96Owm3YEEe1EynC6gQKBgHoFj5AwEjw5/o9KI17x\nhqVvLGE7Y1+f7+6FV6P0cGAK6Qb9jI4Nh2M1flAVikFGpZ6xQUTBQHYo3PgYQ634\nffmAmGplcsw5vy0gwKcz9C13FTwMD3KPK6erjk4Fx4Tk1Vnl42NfC3mPgCa4yHDv\nfUlWzUkXU1XAy3oGkwMl+n9C\n-----END PRIVATE KEY-----\n",
            "server_ca": "-----BEGIN CERTIFICATE-----\nMIIEADCCAuigAwIBAgIUYvOuGAEFCGKN86lVW4cMx1e5/VAwDQYJKoZIhvcNAQEL\nBQAwgZAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQH\nDA1TYW4gRnJhbmNpc2NvMRIwEAYDVQQKDAlIZXNzcmEgQ0ExCzAJBgNVBAsMAkNB\nMRowGAYDVQQDDBF0ZXN0Lmhlc3NyYS5uZXQgQ0ExFzAVBgkqhkiG9w0BCQEWCGNh\nQG5vLm5vMCAXDTIzMDMyNjE5MDYwNloYDzIwNzAwMzEyMTkwNjA2WjCBkDELMAkG\nA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFu\nY2lzY28xEjAQBgNVBAoMCUhlc3NyYSBDQTELMAkGA1UECwwCQ0ExGjAYBgNVBAMM\nEXRlc3QuaGVzc3JhLm5ldCBDQTEXMBUGCSqGSIb3DQEJARYIYmFAbm8ubm8wggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtq5Xoa6R4Otpv8ssWG8VK5bvC\nP4Lc+HgOXyBwCJXwbXuBEJpR2bx1bh13a33tJNBOQRfr4F/OvmYGSXDdIV+PeT7C\nQ1DYL6C2oEf1Ly24LxfitXp7hO4RQBpzWpvLQIoIXnECxnNtlZ0dI2e5StuEXVxr\nXbLgwEfkndVsv2YwEbZgTN7g+/a3RkStXE5jkyOz6+5L9jZ4OOFNa4ZUNhcLHUJL\nGW2+yQK4lNr9/Ld875FPIuRcvZ42HfLEakUVoNTnO6lrT0wN2R2NWNCoRbaPYg1G\nY98L7C3VYsqGfZ8ZGTqZhbXKt0Vv/fZGTcO/RQHbAXsZiw4JJUzj9BoCr0lNAgMB\nAAGjUzBRMB0GA1UdDgQWBBQIHAZQPAwp0Y3xU0MYpH7AngrlGDAfBgNVHSMEGDAW\ngBQIHAZQPAwp0Y3xU0MYpH7AngrlGDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\nDQEBCwUAA4IBAQB0RX7xSGDKoVnNmCGkbCBd3HU3LPVOVJKVw18aHb6UEOtjrY7o\nfxQjH4Y16a3YqOCE3pOvj5ixOHvOdWiYbRlWL8jKYWCeG3BMnEjUJVWQ7/jQe3m4\nmEhDGmHVzWHwZi0FXBfIKcAHXe6ZYV5tXCwHbjhJPFXfUFWzQVaAiM8NJ9Vqapqc\n8Eb2is/LuxpxQ+cXQUHEwPuTMgSu/GjPNX6GTGCzc/pBx5sHM/5Fu8nRM5QYBoCO\nVXb52bO2ORs2yRTmBlKjF6B3ory1qGa9OBUYTa0cHGwUNjQnUSjz1vIIvBPdzgAj\nC3DLlP7NvMJQX6PXsxJiAcwk2p2gB+Lo\n-----END CERTIFICATE-----\n",
            "public_key": "{}"
        }}"#,
        public_key // Use the public key we retrieved earlier
    );

    let config_path = "./config_with_key.json";
    fs::write(config_path, &config_json)?;
    println!("Created configuration file at {}", config_path);

    // Load the configuration from the file
    let loaded_config = HessraConfig::from_file(Path::new(config_path))?;
    println!(
        "Loaded public key from config: {}",
        loaded_config.public_key.unwrap_or_default()
    );

    // Clean up
    fs::remove_file(key_path)?;
    fs::remove_file(config_path)?;
    println!("\nCleaned up temporary files");

    Ok(())
}
