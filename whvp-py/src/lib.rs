#![feature(vec_remove_item)]
#![allow(non_upper_case_globals)]

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use ctrlc;
use simple_logger;

#[macro_use]
extern crate ctor;

#[macro_use]
extern crate log;

// #[macro_use]
// extern crate custom_debug_derive;

#[macro_use]
extern crate anyhow;

pub mod core;

#[ctor]
fn install_handler() {
    ctrlc::set_handler(move || {
        warn!("killed by ctrl-c");
        std::process::exit(128);
    })
    .expect("Error setting Ctrl-C handler");
}

#[pyfunction]
pub fn init_log() -> PyResult<()> {
    match simple_logger::init() {
        Ok(_) => {}
        Err(_) => return Err(PyErr::new::<exceptions::Exception, _>("can't setup logger")),
    }
    Ok(())
}

#[pyfunction]
pub fn log(message: &str) -> PyResult<()> {
    info!("{}", message);
    Ok(())
}

#[pyfunction]
pub fn warn(message: &str) -> PyResult<()> {
    warn!("{}", message);
    Ok(())
}

#[pyfunction]
pub fn error(message: &str) -> PyResult<()> {
    error!("{}", message);
    Ok(())
}

#[pymodule]
fn whvp(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    // m.add_class::<core::Emulator>()?;
    m.add_class::<core::Fuzzer>()?;
    // m.add_class::<core::Fuzzer2>()?;
    m.add_class::<core::Tracer>()?;
    m.add_wrapped(wrap_pyfunction!(init_log))?;
    m.add_wrapped(wrap_pyfunction!(log))?;
    m.add_wrapped(wrap_pyfunction!(warn))?;
    Ok(())
}
