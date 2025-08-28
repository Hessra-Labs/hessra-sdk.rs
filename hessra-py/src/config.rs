use hessra_config::{HessraConfig, Protocol};
use pyo3::prelude::*;
use pyo3::types::PyType;

use crate::error::HessraPyResult;

#[pyclass(name = "HessraConfig")]
pub struct PyHessraConfig {
    inner: HessraConfig,
}

// Default removed since we don't want to create configs with dummy certificates

#[pymethods]
impl PyHessraConfig {
    // Removed the #[new] method that was creating dummy certificates
    // Users should use the builder pattern or from_env instead

    #[classmethod]
    pub fn builder(_cls: &Bound<PyType>) -> PyHessraConfigBuilder {
        PyHessraConfigBuilder {
            base_url: None,
            port: None,
            mtls_cert: None,
            mtls_key: None,
            server_ca: None,
            protocol: None,
            public_key: None,
            personal_keypair: None,
        }
    }

    #[classmethod]
    pub fn from_env(_cls: &Bound<PyType>) -> HessraPyResult<Self> {
        Ok(Self {
            inner: HessraConfig::from_env("HESSRA")?,
        })
    }

    #[getter]
    pub fn base_url(&self) -> String {
        self.inner.base_url.clone()
    }

    #[getter]
    pub fn port(&self) -> Option<u16> {
        self.inner.port
    }

    #[getter]
    pub fn protocol(&self) -> String {
        match self.inner.protocol {
            Protocol::Http1 => "http1".to_string(),
        }
    }

    #[getter]
    pub fn public_key(&self) -> Option<String> {
        self.inner.public_key.clone()
    }

    pub fn to_builder(&self) -> PyHessraConfigBuilder {
        PyHessraConfigBuilder {
            base_url: Some(self.inner.base_url.clone()),
            port: self.inner.port,
            mtls_cert: self.inner.mtls_cert.clone(),
            mtls_key: self.inner.mtls_key.clone(),
            server_ca: Some(self.inner.server_ca.clone()),
            protocol: Some(match self.inner.protocol {
                Protocol::Http1 => "http1".to_string(),
            }),
            public_key: self.inner.public_key.clone(),
            personal_keypair: self.inner.personal_keypair.clone(),
        }
    }
}

impl PyHessraConfig {
    pub fn inner(&self) -> &HessraConfig {
        &self.inner
    }
}

#[pyclass(name = "HessraConfigBuilder")]
#[derive(Clone)]
pub struct PyHessraConfigBuilder {
    base_url: Option<String>,
    port: Option<u16>,
    mtls_cert: Option<String>,
    mtls_key: Option<String>,
    server_ca: Option<String>,
    protocol: Option<String>,
    public_key: Option<String>,
    personal_keypair: Option<String>,
}

#[pymethods]
impl PyHessraConfigBuilder {
    pub fn base_url(&mut self, base_url: String) -> PyHessraConfigBuilder {
        self.base_url = Some(base_url);
        self.clone()
    }

    pub fn port(&mut self, port: u16) -> PyHessraConfigBuilder {
        self.port = Some(port);
        self.clone()
    }

    pub fn mtls_key(&mut self, mtls_key: String) -> PyHessraConfigBuilder {
        self.mtls_key = Some(mtls_key);
        self.clone()
    }

    pub fn mtls_cert(&mut self, mtls_cert: String) -> PyHessraConfigBuilder {
        self.mtls_cert = Some(mtls_cert);
        self.clone()
    }

    pub fn server_ca(&mut self, server_ca: String) -> PyHessraConfigBuilder {
        self.server_ca = Some(server_ca);
        self.clone()
    }

    pub fn protocol(&mut self, protocol: String) -> HessraPyResult<PyHessraConfigBuilder> {
        match protocol.as_str() {
            "http1" => {
                self.protocol = Some(protocol);
                Ok(self.clone())
            }
            _ => {
                Err(crate::error::HessraPyError {
                    inner: format!("Invalid protocol: {protocol}. Must be 'http1'"),
                })
            }
        }
    }

    pub fn public_key(&mut self, public_key: String) -> PyHessraConfigBuilder {
        self.public_key = Some(public_key);
        self.clone()
    }

    pub fn personal_keypair(&mut self, keypair: String) -> PyHessraConfigBuilder {
        self.personal_keypair = Some(keypair);
        self.clone()
    }

    pub fn build(&mut self) -> HessraPyResult<PyHessraConfig> {
        let mut builder = HessraConfig::builder();
        
        if let Some(ref base_url) = self.base_url {
            builder = builder.base_url(base_url.clone());
        }
        
        if let Some(port) = self.port {
            builder = builder.port(port);
        }
        
        // Only set mTLS if provided - don't use dummy values
        if let Some(ref cert) = self.mtls_cert {
            builder = builder.mtls_cert(cert.clone());
        }
        
        if let Some(ref key) = self.mtls_key {
            builder = builder.mtls_key(key.clone());
        }
        
        if let Some(ref ca) = self.server_ca {
            builder = builder.server_ca(ca.clone());
        }
        
        if let Some(ref proto) = self.protocol {
            let protocol = match proto.as_str() {
                "http1" => Protocol::Http1,
                _ => return Err(crate::error::HessraPyError {
                    inner: format!("Invalid protocol: {proto}"),
                }),
            };
            builder = builder.protocol(protocol);
        }
        
        if let Some(ref public_key) = self.public_key {
            builder = builder.public_key(public_key.clone());
        }
        
        if let Some(ref keypair) = self.personal_keypair {
            builder = builder.personal_keypair(keypair.clone());
        }
        
        Ok(PyHessraConfig {
            inner: builder.build()?,
        })
    }
}
