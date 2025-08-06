use hessra_config::{HessraConfig, Protocol};
use pyo3::prelude::*;
use pyo3::types::PyType;

use crate::error::HessraPyResult;

#[pyclass(name = "HessraConfig")]
pub struct PyHessraConfig {
    inner: HessraConfig,
}

impl Default for PyHessraConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl PyHessraConfig {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: HessraConfig::new(
                "localhost".to_string(),
                Some(443),
                Protocol::Http1,
                "dummy-cert".to_string(),
                "dummy-key".to_string(),
                "dummy-ca".to_string(),
            ),
        }
    }

    #[classmethod]
    pub fn builder(_cls: &Bound<PyType>) -> PyHessraConfigBuilder {
        PyHessraConfigBuilder {
            inner: HessraConfig::builder(),
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
            inner: self.inner.to_builder(),
        }
    }
}

impl PyHessraConfig {
    pub fn inner(&self) -> &HessraConfig {
        &self.inner
    }
}

#[pyclass(name = "HessraConfigBuilder")]
pub struct PyHessraConfigBuilder {
    inner: hessra_config::HessraConfigBuilder,
}

#[pymethods]
impl PyHessraConfigBuilder {
    pub fn base_url(&mut self, base_url: String) -> PyHessraConfigBuilder {
        let inner = std::mem::replace(&mut self.inner, HessraConfig::builder()).base_url(base_url);
        PyHessraConfigBuilder { inner }
    }

    pub fn port(&mut self, port: u16) -> PyHessraConfigBuilder {
        let inner = std::mem::replace(&mut self.inner, HessraConfig::builder()).port(port);
        PyHessraConfigBuilder { inner }
    }

    pub fn mtls_key(&mut self, mtls_key: String) -> PyHessraConfigBuilder {
        let inner = std::mem::replace(&mut self.inner, HessraConfig::builder()).mtls_key(mtls_key);
        PyHessraConfigBuilder { inner }
    }

    pub fn mtls_cert(&mut self, mtls_cert: String) -> PyHessraConfigBuilder {
        let inner =
            std::mem::replace(&mut self.inner, HessraConfig::builder()).mtls_cert(mtls_cert);
        PyHessraConfigBuilder { inner }
    }

    pub fn server_ca(&mut self, server_ca: String) -> PyHessraConfigBuilder {
        let inner =
            std::mem::replace(&mut self.inner, HessraConfig::builder()).server_ca(server_ca);
        PyHessraConfigBuilder { inner }
    }

    pub fn protocol(&mut self, protocol: String) -> HessraPyResult<PyHessraConfigBuilder> {
        let proto = match protocol.as_str() {
            "http1" => Protocol::Http1,
            _ => {
                return Err(crate::error::HessraPyError {
                    inner: format!("Invalid protocol: {protocol}. Must be 'http1'"),
                })
            }
        };
        let inner = std::mem::replace(&mut self.inner, HessraConfig::builder()).protocol(proto);
        Ok(PyHessraConfigBuilder { inner })
    }

    pub fn public_key(&mut self, public_key: String) -> PyHessraConfigBuilder {
        let inner =
            std::mem::replace(&mut self.inner, HessraConfig::builder()).public_key(public_key);
        PyHessraConfigBuilder { inner }
    }

    pub fn personal_keypair(&mut self, keypair: String) -> PyHessraConfigBuilder {
        let inner =
            std::mem::replace(&mut self.inner, HessraConfig::builder()).personal_keypair(keypair);
        PyHessraConfigBuilder { inner }
    }

    pub fn build(&mut self) -> HessraPyResult<PyHessraConfig> {
        let inner = std::mem::replace(&mut self.inner, HessraConfig::builder());
        Ok(PyHessraConfig {
            inner: inner.build()?,
        })
    }
}
