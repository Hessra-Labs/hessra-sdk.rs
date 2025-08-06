use pyo3::prelude::*;

mod client;
mod config;
mod error;
mod response;

pub use client::PyHessraClient;
pub use config::PyHessraConfig;
pub use error::{HessraPyError, HessraPyResult};

#[pymodule]
fn hessra_py(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyHessraConfig>()?;
    m.add_class::<PyHessraClient>()?;
    m.add(
        "HessraPyException",
        m.py().get_type::<error::HessraPyException>(),
    )?;
    Ok(())
}
