pub mod certification;
pub mod consensus;
pub mod dag;
pub mod developer;
pub mod drain;
pub mod engine;
pub mod error;
pub mod event;
pub mod ffi;
pub mod hash;
pub mod interpreter;
pub mod origin;
pub mod projection;
pub mod python_api;
pub mod query;
pub mod reconstruction;
pub mod record;
pub mod region;
pub mod replay;
pub mod sdk;
pub mod serialization;
pub mod signature;
pub mod snapshot;
pub mod state;
pub mod storage;
pub mod transfer;
pub mod validation;
pub mod wallet;

pub use certification::*;
pub use consensus::*;
pub use dag::*;
pub use developer::*;
pub use drain::*;
pub use engine::*;
pub use error::*;
pub use event::{OperationType, VectorEvent, VectorState};
pub use ffi::*;
pub use hash::*;
pub use interpreter::*;
pub use origin::*;
pub use projection::*;
pub use python_api::*;
pub use query::*;
pub use reconstruction::*;
pub use record::*;
pub use region::*;
pub use sdk::*;
pub use serialization::*;
pub use signature::*;
pub use snapshot::*;
pub use state::*;
pub use storage::*;
pub use transfer::*;
pub use validation::*;

pub use replay::compute_state_root as replay_compute_state_root;
pub use wallet::verifying_key_from_hex as wallet_verifying_key_from_hex;

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
        "dag",
        "developer",
        "drain",
        "engine",
        "error",
        "event",
        "ffi",
        "hash",
        "interpreter",
        "origin",
        "projection",
        "python_api",
        "query",
        "region",
        "reconstruction",
        "record",
        "replay",
        "sdk",
        "serialization",
        "signature",
        "snapshot",
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
