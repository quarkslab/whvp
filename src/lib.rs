
#![feature(vec_remove_item)]

use pyo3::prelude::*;

#[macro_use]
extern crate bitflags;

pub mod bindings;
pub mod mem;
pub mod whvp;
pub mod fuzz;

#[pymodule]
fn whvp(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<bindings::Emulator>()?;
    m.add_class::<bindings::Fuzzer>()?;
    Ok(())
}


