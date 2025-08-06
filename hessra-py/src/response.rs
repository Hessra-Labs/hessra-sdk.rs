use hessra_api::{SignTokenResponse, SignoffInfo, TokenResponse};
use pyo3::prelude::*;

#[pyclass(name = "SignoffInfo")]
#[derive(Clone)]
pub struct PySignoffInfo {
    #[pyo3(get)]
    pub component: String,
    #[pyo3(get)]
    pub authorization_service: String,
    #[pyo3(get)]
    pub public_key: String,
}

#[pymethods]
impl PySignoffInfo {
    #[new]
    pub fn new(component: String, authorization_service: String, public_key: String) -> Self {
        Self {
            component,
            authorization_service,
            public_key,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SignoffInfo(component='{}', authorization_service='{}', public_key='{}...')",
            self.component,
            self.authorization_service,
            &self.public_key[..std::cmp::min(20, self.public_key.len())]
        )
    }
}

impl From<&SignoffInfo> for PySignoffInfo {
    fn from(info: &SignoffInfo) -> Self {
        Self {
            component: info.component.clone(),
            authorization_service: info.authorization_service.clone(),
            public_key: info.public_key.clone(),
        }
    }
}

#[pyclass(name = "TokenResponse")]
pub struct PyTokenResponse {
    #[pyo3(get)]
    pub response_msg: String,
    #[pyo3(get)]
    pub token: Option<String>,
    #[pyo3(get)]
    pub pending_signoffs: Option<Vec<PySignoffInfo>>,
}

#[pymethods]
impl PyTokenResponse {
    #[new]
    pub fn new(
        response_msg: String,
        token: Option<String>,
        pending_signoffs: Option<Vec<PySignoffInfo>>,
    ) -> Self {
        Self {
            response_msg,
            token,
            pending_signoffs,
        }
    }

    fn __repr__(&self) -> String {
        let token_preview = match &self.token {
            Some(t) => format!("Some('{}...')", &t[..std::cmp::min(20, t.len())]),
            None => "None".to_string(),
        };

        let pending_count = match &self.pending_signoffs {
            Some(signoffs) => format!("Some({} signoffs)", signoffs.len()),
            None => "None".to_string(),
        };

        format!(
            "TokenResponse(response_msg='{}', token={}, pending_signoffs={})",
            self.response_msg, token_preview, pending_count
        )
    }
}

impl From<TokenResponse> for PyTokenResponse {
    fn from(response: TokenResponse) -> Self {
        let pending_signoffs = response
            .pending_signoffs
            .map(|signoffs| signoffs.iter().map(PySignoffInfo::from).collect());

        Self {
            response_msg: response.response_msg,
            token: response.token,
            pending_signoffs,
        }
    }
}

#[pyclass(name = "SignTokenResponse")]
pub struct PySignTokenResponse {
    #[pyo3(get)]
    pub response_msg: String,
    #[pyo3(get)]
    pub signed_token: Option<String>,
}

#[pymethods]
impl PySignTokenResponse {
    #[new]
    pub fn new(response_msg: String, signed_token: Option<String>) -> Self {
        Self {
            response_msg,
            signed_token,
        }
    }

    fn __repr__(&self) -> String {
        let token_preview = match &self.signed_token {
            Some(t) => format!("Some('{}...')", &t[..std::cmp::min(20, t.len())]),
            None => "None".to_string(),
        };

        format!(
            "SignTokenResponse(response_msg='{}', signed_token={})",
            self.response_msg, token_preview
        )
    }
}

impl From<SignTokenResponse> for PySignTokenResponse {
    fn from(response: SignTokenResponse) -> Self {
        Self {
            response_msg: response.response_msg,
            signed_token: response.signed_token,
        }
    }
}
