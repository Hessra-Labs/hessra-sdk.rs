use hessra_sdk::{HessraClient, Protocol};
use std::error::Error;
use std::fs;
use std::path::Path;

mod test_utils;
use test_utils::generate_test_certs;

// Helper function to ensure we have test certificates
async fn setup_test_certs() -> Result<(String, String, String), Box<dyn Error>> {
    // First check if we can use the existing certs from the certs directory
    let cert_path = Path::new("test_certs");
    if cert_path.exists() {
        let ca_cert = fs::read_to_string("test_certs/ca-2030.pem")?;
        let client_cert = fs::read_to_string("test_certs/client.crt")?;
        let client_key = fs::read_to_string("test_certs/client.key")?;
        return Ok((ca_cert, client_cert, client_key));
    }

    // If not, generate test certificates
    generate_test_certs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_builder_http1() -> Result<(), Box<dyn Error>> {
        // Get test certificates
        let (ca_cert, client_cert, client_key) = setup_test_certs().await?;

        let client = HessraClient::builder()
            .base_url("test.hessra.net")
            .port(443)
            .protocol(Protocol::Http1)
            .mtls_cert(client_cert)
            .mtls_key(client_key)
            .server_ca(ca_cert)
            .build()?;

        // Just testing that the client builds successfully
        match client {
            HessraClient::Http1(_) => Ok(()),
            #[cfg(feature = "http3")]
            _ => panic!("Expected HTTP/1 client"),
        }
    }

    #[cfg(feature = "http3")]
    #[tokio::test]
    async fn test_client_builder_http3() -> Result<(), Box<dyn Error>> {
        // Get test certificates
        let (ca_cert, client_cert, client_key) = setup_test_certs().await?;

        let client = HessraClient::builder()
            .base_url("test.hessra.net")
            .port(443)
            .protocol(Protocol::Http3)
            .mtls_cert(client_cert)
            .mtls_key(client_key)
            .server_ca(ca_cert)
            .build()?;

        // Just testing that the client builds successfully
        match client {
            HessraClient::Http3(_) => Ok(()),
            _ => panic!("Expected HTTP/3 client"),
        }
    }
}
