use pyo3::exceptions::PyException;
use pyo3::prelude::*;

#[derive(Debug)]
pub struct HessraPyError {
    pub inner: String,
}

impl std::fmt::Display for HessraPyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for HessraPyError {}

impl From<hessra_sdk::SdkError> for HessraPyError {
    fn from(err: hessra_sdk::SdkError) -> Self {
        HessraPyError {
            inner: err.to_string(),
        }
    }
}

impl From<hessra_config::ConfigError> for HessraPyError {
    fn from(err: hessra_config::ConfigError) -> Self {
        HessraPyError {
            inner: err.to_string(),
        }
    }
}

impl From<hessra_token::TokenError> for HessraPyError {
    fn from(err: hessra_token::TokenError) -> Self {
        HessraPyError {
            inner: err.to_string(),
        }
    }
}

pyo3::create_exception!(
    hessra_py,
    HessraPyException,
    PyException,
    "An error occurred in Hessra"
);

impl From<HessraPyError> for PyErr {
    fn from(err: HessraPyError) -> PyErr {
        HessraPyException::new_err(err.inner)
    }
}

pub type HessraPyResult<T> = Result<T, HessraPyError>;
