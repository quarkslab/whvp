
use structopt::StructOpt;

use pyo3::{prelude::*, types::*};
use pyo3::exceptions;

pub mod whvp;
pub mod bindings;

#[derive(StructOpt, Debug)]
#[structopt()]
struct Cli {

    /// Activate debug mode
    #[structopt(short, long)]
    debug: bool,

    /// The path to the file to read
    #[structopt(parse(from_os_str))]
    path: std::path::PathBuf,

    #[structopt(short="-u")]
    update: bool,
}

fn run(plugin: String) -> PyResult<()> {
    let gil = Python::acquire_gil();
    let py = gil.python();

    let module = PyModule::from_code(
        py,
        &plugin,
        "plugin.py",
        "plugin",
    )?;

    let cls = py.get_type::<bindings::Emulator>();
    let py_emulator = cls.call((), None)?;
    let emulator: &mut bindings::Emulator = py_emulator.downcast_mut::<bindings::Emulator>()?;

    let init_func = module.get("init")?.to_object(py);

    let memory_access_callback = module.get("callback")?.to_object(py);
    let fini_func = module.get("fini")?.to_object(py);

    let context = init_func.call1(py, (py_emulator,))?;
    
    let py_context = match <PyDict as PyTryFrom>::try_from(context.as_ref(py)) {
        Ok(dict) => dict,
        Err(_error) => return Err(PyErr::new::<exceptions::Exception, _>("init func should return a dict"))
    };

    let return_address = py_context.get_item("return_address")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get return address"))?
                            .extract::<u64>()?;

    let mut result = bindings::EmulationResult::new();
    let mut addresses: Vec<u64> = Vec::new();
    addresses.push(return_address);
    let limit = 0;
    let mut cancel = 0;
    while limit == 0 || result.exits < limit {
        match emulator.run() {
            Ok(exit) => {
                result.exits += 1;
                match exit.reason {
                    whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonMemoryAccess => { 
                        cancel = 0;
                        result.pages += 1;
                        let args = (py_emulator, &context, exit.gpa, exit.gva);
                        memory_access_callback.call(py, args, None)?;
                    },
                    whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonException => { 
                        cancel = 0;
                        if exit.exception_type == 1 {
                            result.coverage.push(exit.rip);
                            if addresses.contains(&exit.rip) {
                                result.status = 0;
                                break;
                            }
                        }
                    },
                    whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonCanceled => { 
                        cancel += 1;
                        if cancel > 5 {
                            result.status = 1;
                            break;
                        }
                    }
                        _ => {
                        panic!("Unhandled VM exit reason {}", exit.reason);
                    }
                }
            },
            _ => {
                return Err(PyErr::new::<exceptions::Exception, _>("can't run emulator"))
            }
        }
    }
    if limit != 0 && result.exits > limit {
        result.status = 3;
    }

    fini_func.call1(py, (py_emulator, result))?;
    Ok(())
}

fn main() {
    let args = Cli::from_args();
    let result = std::fs::read_to_string(&args.path);
    
    match result {
        Ok(content) => { 
            match run(content) {
                Ok(()) => {
                    println!("done");
                },
                Err(error) => {
                    println!("can't run plugin");
                    let gil = Python::acquire_gil();
                    let py = gil.python();
                    error.print(py);
                }
            }
        }
        Err(error) => {
            println!("Oh noes: {}", error);
        }
    }
}
