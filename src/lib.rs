use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize)]
pub struct TokenRequest {
    pub resource: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
    pub resource: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    pub response_msg: String,
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyTokenResponse {
    pub response_msg: String,
}

#[cfg(feature = "http3")]
use {
    bytes::{Buf, Bytes},
    h3_quinn::quinn::{self, Endpoint},
    quinn_proto::crypto::rustls::QuicClientConfig,
    rustls::pki_types::CertificateDer,
    rustls::RootCertStore,
    rustls_pemfile::certs,
    std::io::BufReader,
    std::net::SocketAddr,
    std::sync::Arc,
};

#[derive(Clone)]
pub struct BaseConfig {
    base_url: String,
    port: Option<u16>,
    mtls_key: String,
    mtls_cert: String,
    server_ca: String,
}

impl BaseConfig {
    fn get_base_url(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.base_url, port),
            None => self.base_url.clone(),
        }
    }
}

pub struct Http1Client {
    config: BaseConfig,
    client: Client,
}

#[cfg(feature = "http3")]
pub struct Http3Client {
    config: BaseConfig,
    endpoint: Endpoint,
}

pub enum HessraClient {
    Http1(Http1Client),
    #[cfg(feature = "http3")]
    Http3(Http3Client),
}

pub struct HessraClientBuilder {
    config: BaseConfig,
    protocol: Protocol,
}

#[derive(Clone)]
pub enum Protocol {
    Http1,
    #[cfg(feature = "http3")]
    Http3,
}

// Add HTTP/3 ALPN constant
#[cfg(feature = "http3")]
static ALPN_QUIC_HTTP3: &[u8] = b"h3";

impl HessraClientBuilder {
    pub fn new() -> Self {
        HessraClientBuilder {
            config: BaseConfig {
                base_url: "".to_string(),
                port: None,
                mtls_key: "".to_string(),
                mtls_cert: "".to_string(),
                server_ca: "".to_string(),
            },
            protocol: Protocol::Http1,
        }
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config.base_url = base_url.into();
        self
    }

    pub fn mtls_key(mut self, mtls_key: impl Into<String>) -> Self {
        self.config.mtls_key = mtls_key.into();
        self
    }

    pub fn mtls_cert(mut self, mtls_cert: impl Into<String>) -> Self {
        self.config.mtls_cert = mtls_cert.into();
        self
    }

    pub fn server_ca(mut self, server_ca: impl Into<String>) -> Self {
        self.config.server_ca = server_ca.into();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.config.port = Some(port);
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    fn build_http1(&self) -> Result<Http1Client, Box<dyn Error>> {
        let mut identity_pem = Vec::new();
        identity_pem.extend(self.config.mtls_cert.as_bytes());
        identity_pem.extend(self.config.mtls_key.as_bytes());

        let client = Client::builder()
            .identity(reqwest::Identity::from_pem(&identity_pem)?)
            .add_root_certificate(reqwest::Certificate::from_pem(
                self.config.server_ca.as_bytes(),
            )?)
            .use_rustls_tls()
            .build()?;

        Ok(Http1Client {
            config: self.config.clone(),
            client,
        })
    }

    #[cfg(feature = "http3")]
    fn build_http3(&self) -> Result<Http3Client, Box<dyn Error>> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        // Parse root certificate
        let mut root_store = RootCertStore::empty();
        let mut reader = BufReader::new(self.config.server_ca.as_bytes());
        let certs = certs(&mut reader);
        for cert in certs {
            root_store.add(cert?)?;
        }

        // Parse client certificate chain
        let cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut self.config.mtls_cert.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| format!("invalid PEM-encoded certificate: {}", e))?;

        if cert_chain.is_empty() {
            return Err("No client certificates found".into());
        }

        // Parse private key
        let key = rustls_pemfile::private_key(&mut self.config.mtls_key.as_bytes())
            .map_err(|e| format!("malformed private key: {}", e))?
            .ok_or_else(|| Box::<dyn Error>::from("no private keys found"))?;

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)
            .map_err(|e| format!("Failed to build client crypto: {}", e))?;

        // Set ALPN protocol
        client_crypto.alpn_protocols = vec![ALPN_QUIC_HTTP3.into()];
        client_crypto.enable_early_data = true;

        let client_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto)
                .map_err(|e| format!("Failed to create QUIC config: {}", e))?,
        ));

        let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        Ok(Http3Client {
            config: self.config.clone(),
            endpoint,
        })
    }

    pub fn build(self) -> Result<HessraClient, Box<dyn Error>> {
        match self.protocol {
            Protocol::Http1 => Ok(HessraClient::Http1(self.build_http1()?)),
            #[cfg(feature = "http3")]
            Protocol::Http3 => Ok(HessraClient::Http3(self.build_http3()?)),
        }
    }
}

impl Default for HessraClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http3")]
impl Http3Client {
    async fn send_request<T, R>(
        &self,
        endpoint: &str,
        request_body: &T,
    ) -> Result<R, Box<dyn Error>>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let addr = tokio::net::lookup_host((
            self.config.base_url.as_str(),
            self.config.port.unwrap_or(443),
        ))
        .await?
        .next()
        .ok_or("dns found no addresses")?;

        let connection = self
            .endpoint
            .connect(addr, &self.config.base_url)?
            .await
            .map_err(|e| format!("Failed to connect: {}", e))?;

        let quinn_conn = h3_quinn::Connection::new(connection);
        let (_driver, mut send_request) = h3::client::new(quinn_conn).await?;

        let request = http::Request::builder()
            .uri(format!(
                "https://{}/{}",
                self.config.get_base_url(),
                endpoint
            ))
            .header("content-type", "application/json")
            .body(())?;

        let mut stream = send_request.send_request(request).await?;
        let body = serde_json::to_string(request_body)?;
        stream.send_data(Bytes::from(body)).await?;
        stream.finish().await?;

        let _response = stream.recv_response().await?;
        let mut response_data = Vec::new();

        while let Some(chunk) = stream.recv_data().await? {
            response_data.extend_from_slice(chunk.chunk());
        }

        let response: R = serde_json::from_slice(&response_data)?;
        Ok(response)
    }
}

impl Http1Client {
    async fn send_request<T, R>(
        &self,
        endpoint: &str,
        request_body: &T,
    ) -> Result<R, Box<dyn Error>>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .post(format!(
                "https://{}/{}",
                self.config.get_base_url(),
                endpoint
            ))
            .json(request_body)
            .send()
            .await?
            .json::<R>()
            .await?;

        Ok(response)
    }
}

impl HessraClient {
    pub fn builder() -> HessraClientBuilder {
        HessraClientBuilder::new()
    }

    pub async fn request_token(&self, resource: String) -> Result<String, Box<dyn Error>> {
        let token_request = TokenRequest { resource };

        let response: TokenResponse = match self {
            HessraClient::Http1(client) => {
                client.send_request("request_token", &token_request).await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client.send_request("request_token", &token_request).await?
            }
        };

        response.token.ok_or_else(|| "No token in response".into())
    }

    pub async fn verify_token(
        &self,
        token: String,
        resource: String,
    ) -> Result<String, Box<dyn Error>> {
        let verify_token_request = VerifyTokenRequest { token, resource };

        let response: VerifyTokenResponse = match self {
            HessraClient::Http1(client) => {
                client
                    .send_request("verify_token", &verify_token_request)
                    .await?
            }
            #[cfg(feature = "http3")]
            HessraClient::Http3(client) => {
                client
                    .send_request("verify_token", &verify_token_request)
                    .await?
            }
        };

        Ok(response.response_msg)
    }
}
