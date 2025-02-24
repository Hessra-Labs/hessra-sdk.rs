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

#[derive(Clone)]
struct Config {
    base_url: String,
    port: Option<u16>,
    mtls_key: String,
    mtls_cert: String,
    server_ca: String,
}

pub struct HessraClient {
    config: Config,
    client: Client,
}

pub struct HessraClientBuilder {
    config: Config,
}

impl HessraClientBuilder {
    pub fn new() -> Self {
        HessraClientBuilder {
            config: Config {
                base_url: "".to_string(),
                port: None,
                mtls_key: "".to_string(),
                mtls_cert: "".to_string(),
                server_ca: "".to_string(),
            },
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

    pub fn build(self) -> Result<HessraClient, Box<dyn Error>> {
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

        Ok(HessraClient {
            config: self.config,
            client,
        })
    }
}

impl Default for HessraClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HessraClient {
    pub fn builder() -> HessraClientBuilder {
        HessraClientBuilder::new()
    }

    fn get_base_url(&self) -> String {
        match self.config.port {
            Some(port) => format!("{}:{}", self.config.base_url, port),
            None => self.config.base_url.clone(),
        }
    }

    pub async fn request_token(&self, resource: String) -> Result<String, Box<dyn Error>> {
        let token_request = TokenRequest { resource };

        let response = self
            .client
            .post(format!("{}/request_token", self.get_base_url()))
            .json(&token_request)
            .send()
            .await?
            .json::<TokenResponse>()
            .await?;

        response.token.ok_or_else(|| "No token in response".into())
    }

    pub async fn verify_token(
        &self,
        token: String,
        resource: String,
    ) -> Result<String, Box<dyn Error>> {
        let verify_token_request = VerifyTokenRequest { token, resource };

        let response = self
            .client
            .post(format!("{}/verify_token", self.get_base_url()))
            .json(&verify_token_request)
            .send()
            .await?
            .json::<VerifyTokenResponse>()
            .await?;

        Ok(response.response_msg)
    }
}
