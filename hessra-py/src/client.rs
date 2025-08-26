use std::sync::Arc;

use hessra_sdk::{Hessra, ServiceChain};
use pyo3::prelude::*;
use pyo3::types::PyType;
use tokio::runtime::Runtime;

use crate::config::PyHessraConfig;
use crate::error::HessraPyResult;
use crate::identity::PyIdentityTokenResponse;

#[pyclass(name = "HessraClient")]
pub struct PyHessraClient {
    inner: Arc<Hessra>,
    runtime: Arc<Runtime>,
}

#[pymethods]
impl PyHessraClient {
    #[new]
    pub fn new(config: &PyHessraConfig) -> HessraPyResult<Self> {
        let runtime = Arc::new(Runtime::new().map_err(|e| crate::error::HessraPyError {
            inner: format!("Failed to create async runtime: {e}"),
        })?);

        let hessra = Hessra::new(config.inner().clone())?;

        Ok(Self {
            inner: Arc::new(hessra),
            runtime,
        })
    }

    pub fn request_token_simple(
        &self,
        resource: String,
        operation: String,
    ) -> HessraPyResult<String> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        runtime
            .block_on(async move { inner.request_token_simple(resource, operation).await })
            .map_err(Into::into)
    }

    #[classmethod]
    pub fn builder(_cls: &Bound<PyType>) -> PyHessraClientBuilder {
        PyHessraClientBuilder {
            inner: Hessra::builder(),
        }
    }

    pub fn setup(&mut self) -> HessraPyResult<()> {
        Err(crate::error::HessraPyError {
            inner: "Use setup_new() method instead for immutable setup".to_string(),
        })
    }

    pub fn setup_new(&self) -> HessraPyResult<PyHessraClient> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        let new_hessra = runtime.block_on(async move { inner.with_setup().await })?;

        Ok(PyHessraClient {
            inner: Arc::new(new_hessra),
            runtime,
        })
    }

    pub fn verify_token(
        &self,
        token: String,
        subject: String,
        resource: String,
        operation: String,
    ) -> HessraPyResult<()> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        runtime
            .block_on(async move {
                inner
                    .verify_token(token, subject, resource, operation)
                    .await
            })
            .map_err(Into::into)
    }

    pub fn verify_token_local(
        &self,
        token: String,
        subject: String,
        resource: String,
        operation: String,
    ) -> HessraPyResult<()> {
        self.inner
            .verify_token_local(token, subject, resource, operation)
            .map_err(Into::into)
    }

    pub fn verify_token_remote(
        &self,
        token: String,
        subject: String,
        resource: String,
        operation: String,
    ) -> HessraPyResult<String> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        runtime
            .block_on(async move {
                inner
                    .verify_token_remote(token, subject, resource, operation)
                    .await
            })
            .map_err(Into::into)
    }

    pub fn get_public_key(&self) -> HessraPyResult<String> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        runtime
            .block_on(async move { inner.get_public_key().await })
            .map_err(Into::into)
    }

    pub fn attest_service_chain_token(
        &self,
        token: String,
        service: String,
    ) -> HessraPyResult<String> {
        self.inner
            .attest_service_chain_token(token, service)
            .map_err(Into::into)
    }

    pub fn verify_service_chain_token_local(
        &self,
        token: String,
        subject: String,
        resource: String,
        operation: String,
        service_chain_json: String,
        component: Option<String>,
    ) -> HessraPyResult<()> {
        let service_chain = ServiceChain::from_json(&service_chain_json)?;

        self.inner
            .verify_service_chain_token_local(
                token,
                subject,
                resource,
                operation,
                &service_chain,
                component,
            )
            .map_err(Into::into)
    }

    pub fn verify_service_chain_token_remote(
        &self,
        token: String,
        subject: String,
        resource: String,
        component: Option<String>,
    ) -> HessraPyResult<String> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        runtime
            .block_on(async move {
                inner
                    .verify_service_chain_token_remote(token, subject, resource, component)
                    .await
            })
            .map_err(Into::into)
    }

    pub fn request_identity_token(
        &self,
        identifier: Option<String>,
    ) -> HessraPyResult<PyIdentityTokenResponse> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        let response =
            runtime.block_on(async move { inner.request_identity_token(identifier).await })?;
        Ok(response.into())
    }

    pub fn refresh_identity_token(
        &self,
        current_token: String,
        identifier: Option<String>,
    ) -> HessraPyResult<PyIdentityTokenResponse> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        let response = runtime.block_on(async move {
            inner
                .refresh_identity_token(current_token, identifier)
                .await
        })?;
        Ok(response.into())
    }

    pub fn request_token_with_identity(
        &self,
        resource: String,
        operation: String,
        identity_token: String,
    ) -> HessraPyResult<String> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        runtime
            .block_on(async move {
                let response = inner
                    .request_token_with_identity(resource, operation, identity_token)
                    .await?;
                response
                    .token
                    .ok_or_else(|| hessra_sdk::SdkError::Generic("No token returned".to_string()))
            })
            .map_err(Into::into)
    }

    pub fn verify_identity_token_local(
        &self,
        token: String,
        identity: String,
    ) -> HessraPyResult<()> {
        self.inner
            .verify_identity_token_local(token, identity)
            .map_err(Into::into)
    }

    pub fn attenuate_identity_token(
        &self,
        token: String,
        delegated_identity: String,
        duration: Option<i64>,
    ) -> HessraPyResult<String> {
        // Default to 1 hour if not specified
        let duration = duration.unwrap_or(3600);
        self.inner
            .attenuate_identity_token(token, delegated_identity, duration)
            .map_err(Into::into)
    }

    pub fn create_identity_token_local(
        &self,
        subject: String,
        duration: Option<i64>,
    ) -> HessraPyResult<String> {
        // Default to 1 hour if not specified
        let duration = duration.unwrap_or(3600);
        self.inner
            .create_identity_token_local(subject, duration)
            .map_err(Into::into)
    }
}

#[pyclass(name = "HessraClientBuilder")]
pub struct PyHessraClientBuilder {
    inner: hessra_sdk::HessraBuilder,
}

#[pymethods]
impl PyHessraClientBuilder {
    pub fn base_url(&mut self, base_url: String) -> PyHessraClientBuilder {
        let inner =
            std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder()).base_url(base_url);
        PyHessraClientBuilder { inner }
    }

    pub fn port(&mut self, port: u16) -> PyHessraClientBuilder {
        let inner = std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder()).port(port);
        PyHessraClientBuilder { inner }
    }

    pub fn mtls_key(&mut self, mtls_key: String) -> PyHessraClientBuilder {
        let inner =
            std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder()).mtls_key(mtls_key);
        PyHessraClientBuilder { inner }
    }

    pub fn mtls_cert(&mut self, mtls_cert: String) -> PyHessraClientBuilder {
        let inner =
            std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder()).mtls_cert(mtls_cert);
        PyHessraClientBuilder { inner }
    }

    pub fn server_ca(&mut self, server_ca: String) -> PyHessraClientBuilder {
        let inner =
            std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder()).server_ca(server_ca);
        PyHessraClientBuilder { inner }
    }

    pub fn protocol(&mut self, protocol: String) -> HessraPyResult<PyHessraClientBuilder> {
        use hessra_config::Protocol;

        let proto = match protocol.as_str() {
            "http1" => Protocol::Http1,
            _ => {
                return Err(crate::error::HessraPyError {
                    inner: format!("Invalid protocol: {protocol}. Must be 'http1'"),
                })
            }
        };
        let inner =
            std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder()).protocol(proto);
        Ok(PyHessraClientBuilder { inner })
    }

    pub fn public_key(&mut self, public_key: String) -> PyHessraClientBuilder {
        let inner = std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder())
            .public_key(public_key);
        PyHessraClientBuilder { inner }
    }

    pub fn personal_keypair(&mut self, keypair: String) -> PyHessraClientBuilder {
        let inner = std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder())
            .personal_keypair(keypair);
        PyHessraClientBuilder { inner }
    }

    pub fn build(&mut self) -> HessraPyResult<PyHessraClient> {
        let runtime = Arc::new(Runtime::new().map_err(|e| crate::error::HessraPyError {
            inner: format!("Failed to create async runtime: {e}"),
        })?);

        let inner = std::mem::replace(&mut self.inner, hessra_sdk::Hessra::builder());
        let hessra = inner.build()?;

        Ok(PyHessraClient {
            inner: Arc::new(hessra),
            runtime,
        })
    }
}
