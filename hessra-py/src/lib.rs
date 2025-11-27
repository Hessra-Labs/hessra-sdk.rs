use pyo3::prelude::*;

mod client;
mod config;
mod error;
mod identity;
mod response;

pub use client::PyHessraClient;
pub use config::PyHessraConfig;
pub use error::{HessraPyError, HessraPyResult};
pub use identity::PyIdentityTokenResponse;
pub use response::PyMintIdentityTokenResponse;

#[pymodule]
fn hessra_py(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyHessraConfig>()?;
    m.add_class::<PyHessraClient>()?;
    m.add_class::<PyIdentityTokenResponse>()?;
    m.add_class::<PyMintIdentityTokenResponse>()?;
    m.add(
        "HessraPyException",
        m.py().get_type::<error::HessraPyException>(),
    )?;
    Ok(())
}
