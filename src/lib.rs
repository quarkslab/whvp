
#![feature(vec_remove_item)]

#![allow(non_upper_case_globals)]

use pyo3::prelude::*;

use ctrlc;

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate smallvec;

#[macro_use]
extern crate ctor;

pub mod bindings;
pub mod mem;
pub mod whvp;
pub mod fuzz;
pub mod watch;

#[ctor]
fn install_handler() {
    ctrlc::set_handler(move || {
        println!("killed by ctrl-c");
        std::process::exit(128);
    }).expect("Error setting Ctrl-C handler");
}

#[pymodule]
fn whvp(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<bindings::Emulator>()?;
    m.add_class::<bindings::Fuzzer>()?;
    Ok(())
}


