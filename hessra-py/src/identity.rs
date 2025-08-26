use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// Python binding for IdentityTokenResponse
#[pyclass(name = "IdentityTokenResponse")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyIdentityTokenResponse {
    #[pyo3(get)]
    pub response_msg: String,
    #[pyo3(get)]
    pub token: Option<String>,
    #[pyo3(get)]
    pub expires_in: Option<u64>,
    #[pyo3(get)]
    pub identity: Option<String>,
}

#[pymethods]
impl PyIdentityTokenResponse {
    #[new]
    pub fn new(
        response_msg: String,
        token: Option<String>,
        expires_in: Option<u64>,
        identity: Option<String>,
    ) -> Self {
        Self {
            response_msg,
            token,
            expires_in,
            identity,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "IdentityTokenResponse(response_msg='{}', token={}, expires_in={:?}, identity={:?})",
            self.response_msg,
            if self.token.is_some() {
                "Some(...)"
            } else {
                "None"
            },
            self.expires_in,
            self.identity
        )
    }

    fn __str__(&self) -> String {
        self.__repr__()
    }
}

impl From<hessra_api::IdentityTokenResponse> for PyIdentityTokenResponse {
    fn from(resp: hessra_api::IdentityTokenResponse) -> Self {
        Self {
            response_msg: resp.response_msg,
            token: resp.token,
            expires_in: resp.expires_in,
            identity: resp.identity,
        }
    }
}
