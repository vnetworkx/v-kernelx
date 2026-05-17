pub mod certification;
pub mod consensus;
pub mod developer;
pub mod drain;
pub mod engine;
pub mod error;
pub mod interpreter;
pub mod origin;
pub mod projection;
pub mod python_api;
pub mod query;
pub mod record;
pub mod reconstruction;
pub mod sdk;
pub mod state;
pub mod storage;
pub mod transfer;
pub mod validation;
pub mod wallet;

pub use certification::*;
pub use consensus::*;
pub use developer::*;
pub use drain::*;
pub use engine::*;
pub use error::*;
pub use interpreter::*;
pub use origin::*;
pub use projection::*;
pub use python_api::*;
pub use query::*;
pub use record::*;
pub use reconstruction::*;
pub use sdk::*;
pub use state::*;
pub use storage::*;
pub use transfer::*;
pub use validation::*;
pub use wallet::*;

use pyo3::prelude::*;
use pyo3::types::PyModule;

#[pyfunction]
fn kernel_name() -> &'static str {
    "v-kernelx"
}

#[pyfunction]
fn kernel_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pyfunction]
fn exposed_modules() -> Vec<&'static str> {
    vec![
        "certification",
        "consensus",
        "developer",
        "drain",
        "engine",
        "error",
        "interpreter",
        "origin",
        "projection",
        "python_api",
        "query",
        "record",
        "reconstruction",
        "sdk",
        "state",
        "storage",
        "transfer",
        "validation",
        "wallet",
    ]
}

#[pymodule]
fn v_kernelx(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(kernel_name, m)?)?;
    m.add_function(wrap_pyfunction!(kernel_version, m)?)?;
    m.add_function(wrap_pyfunction!(exposed_modules, m)?)?;
    m.add_class::<PyKernelEngine>()?;

    Ok(())
}