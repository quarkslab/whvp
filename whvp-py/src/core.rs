
use std::time::Duration;
use std::str::FromStr;

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::*;

use whvp_core::mem::{self, X64VirtualAddressSpace};
use whvp_core::trace::{self, Tracer as TracerTrait};
use whvp_core::fuzz;

use whvp_core::snapshot::Snapshot;


pub struct PythonSnapshot {

    callback: PyObject

}

impl PythonSnapshot  {

    pub fn new(callback: PyObject) -> PyResult<Self> {
        let snapshot = PythonSnapshot {
            callback: callback
        };
        Ok(snapshot)

    }
}

impl Snapshot for PythonSnapshot {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> anyhow::Result<()> {
        let base = gpa & !0xfff;
        let args = (base, 0);
        let gil = Python::acquire_gil();
        let py = gil.python();

        let callback_result = match self.callback.call(py, args, None) {
            Ok(result) => result,
            Err(e) => {
                return Err(anyhow!("can't call callback: {:?}", e))
            }
        };

        let bytes = match <PyBytes as PyTryFrom>::try_from(callback_result.as_ref(py)) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(anyhow!("callback should return bytes"))
            }
        };
        let slice = &bytes.as_bytes()[..buffer.len()];
        buffer.copy_from_slice(slice);
        Ok(())
    }

}

impl X64VirtualAddressSpace for PythonSnapshot {

    fn read_gpa(&self, gpa: mem::Gpa, buf: &mut [u8]) -> anyhow::Result<()> {
        Snapshot::read_gpa(self, gpa, buf)
    }

    fn write_gpa(&mut self, _gpa: mem::Gpa, _data: &[u8]) -> anyhow::Result<()> {
        warn!("read-only snapshot");
        Ok(())
    }

}

#[pyclass]
pub struct Tracer {
    tracer: trace::WhvpTracer<PythonSnapshot>,
}


#[pymethods]
impl Tracer {
    #[new]
    pub fn new(obj: &PyRawObject, callback: PyObject) -> PyResult<()> {
        let snapshot = PythonSnapshot::new(callback)?;
        let tracer = trace::WhvpTracer::new(snapshot)
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't create tracer {}", e)))?;

        obj.init({
            Tracer {
                tracer: tracer,
            }
        });
        Ok(())
    }

    pub fn set_initial_context(&mut self, context: &PyDict, _py: Python) -> PyResult<()> {
        let context: ProcessorState = context.extract()?;
        self.tracer.set_initial_context(&context.0)
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't set context {}", e)))?;

        Ok(())
    }

    pub fn run(&mut self, params: &PyDict, _py: Python) -> PyResult<TraceResult> {
        let params: TraceParams = params.extract()?;
        let trace = self.tracer.run(&params.0)
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't run tracer {}", e)))?;
        Ok(TraceResult{ trace })
    }

    pub fn restore_snapshot(&mut self, _py: Python) -> PyResult<usize> {
        let pages = self.tracer.restore_snapshot()
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't restore snapshot: {}", e)))?;
        Ok(pages)
    }
    
    fn read_virtual_memory(&mut self, addr: usize, size: usize) -> PyResult<PyObject> {
        let cr3 = self.tracer.cr3()
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't get cr3: {}", e)))?;

        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);

        match self.tracer.read_gva(cr3, addr as u64, &mut buffer) {
            Ok(()) => {
                let gil = Python::acquire_gil();
                let py = gil.python();
                return Ok(PyBytes::new(py, &buffer).into());
            }
            _ => {
                return Err(PyErr::new::<exceptions::ValueError, _>(
                    "can't read virtual memory",
                ))
            }
        }
    }

    fn write_virtual_memory(&mut self, addr: usize, bytes: &PyBytes) -> PyResult<()> {
        let cr3 = self.tracer.cr3()
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't get cr3: {}", e)))?;

        match self.tracer.write_gva(cr3, addr as u64, bytes.as_bytes()) {
            Ok(()) => return Ok(()),
            _ => {
                return Err(PyErr::new::<exceptions::ValueError, _>(
                    "can't write virtual memory",
                ))
            }
        }
    }


}

struct SegmentRegister(trace::Segment);

impl<'source> pyo3::FromPyObject<'source> for SegmentRegister {
    fn extract(obj: &'source PyAny) -> PyResult<Self> {
        let dict: &mut PyDict = obj.extract()?;
        let mut segment = trace::Segment::default();
        segment.selector = dict
            .get_item("selector")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get selector"))?
            .extract::<u16>()?;

        Ok(SegmentRegister(segment))
    }
}


struct ProcessorState(trace::ProcessorState);

impl<'source> pyo3::FromPyObject<'source> for ProcessorState {
    fn extract(obj: &'source PyAny) -> PyResult<Self> {
        let context: &mut PyDict = obj.extract()?;

        let mut state = trace::ProcessorState::default();

        state.rax = context
            .get_item("rax")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rax"))?
            .extract::<u64>()?;

        state.rbx = context
            .get_item("rbx")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rbx"))?
            .extract::<u64>()?;

        state.rcx = context
            .get_item("rcx")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rcx"))?
            .extract::<u64>()?;

        state.rdx = context
            .get_item("rdx")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rdx"))?
            .extract::<u64>()?;

        state.rsi = context
            .get_item("rsi")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rsi"))?
            .extract::<u64>()?;

        state.rdi = context
            .get_item("rdi")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rdi"))?
            .extract::<u64>()?;

        state.rsp = context
            .get_item("rsp")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rsp"))?
            .extract::<u64>()?;

        state.rbp = context
            .get_item("rbp")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rbp"))?
            .extract::<u64>()?;

        state.r8 = context
            .get_item("r8")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r8"))?
            .extract::<u64>()?;

        state.r9 = context
            .get_item("r9")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r9"))?
            .extract::<u64>()?;

        state.r10 = context
            .get_item("r10")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r10"))?
            .extract::<u64>()?;

        state.r11 = context
            .get_item("r11")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r11"))?
            .extract::<u64>()?;

        state.r12 = context
            .get_item("r12")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r12"))?
            .extract::<u64>()?;

        state.r13 = context
            .get_item("r13")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r13"))?
            .extract::<u64>()?;

        state.r14 = context
            .get_item("r14")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r14"))?
            .extract::<u64>()?;

        state.r15 = context
            .get_item("r15")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r15"))?
            .extract::<u64>()?;

        state.rflags = context
            .get_item("rflags")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rflags"))?
            .extract::<u64>()?;

        state.rip = context
            .get_item("rip")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rip"))?
            .extract::<u64>()?;

        state.cr0 = context
            .get_item("cr0")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr0"))?
            .extract::<u64>()?;

        state.cr3 = context
            .get_item("cr3")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr3"))?
            .extract::<u64>()?;

        state.cr4 = context
            .get_item("cr4")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr4"))?
            .extract::<u64>()?;

        state.cr8 = context
            .get_item("cr8")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr8"))?
            .extract::<u64>()?;

        state.efer = context
            .get_item("efer")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get efer"))?
            .extract::<u64>()?;

        state.gdtr = context
            .get_item("gdtr")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gdtr"))?
            .extract::<u64>()?;

        state.gdtl = context
            .get_item("gdtl")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gdtl"))?
            .extract::<u16>()?;

        state.idtr = context
            .get_item("idtr")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get idtr"))?
            .extract::<u64>()?;

        state.idtl = context
            .get_item("idtl")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get idtl"))?
            .extract::<u16>()?;

        state.cs = context
            .get_item("cs")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cs"))?
            .extract::<SegmentRegister>()?.0;

        state.ss = context
            .get_item("ss")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get ss"))?
            .extract::<SegmentRegister>()?.0;

        state.ds = context
            .get_item("ds")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get ds"))?
            .extract::<SegmentRegister>()?.0;

        state.es = context
            .get_item("es")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get es"))?
            .extract::<SegmentRegister>()?.0;

        state.fs = context
            .get_item("fs")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get fs"))?
            .extract::<SegmentRegister>()?.0;

        state.gs = context
            .get_item("gs")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gs"))?
            .extract::<SegmentRegister>()?.0;

        state.gs_base = context
            .get_item("gs_base")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gs base"))?
            .extract::<u64>()?;

        state.fs_base = context
            .get_item("fs_base")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get fs base"))?
            .extract::<u64>()?;

        state.kernel_gs_base = context
            .get_item("kernel_gs_base")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get kernel gs base"))?
            .extract::<u64>()?;

        Ok(ProcessorState(state))
    }
}

struct TraceParams(trace::Params);

impl<'source> pyo3::FromPyObject<'source> for TraceParams {
    fn extract(obj: &'source PyAny) -> PyResult<Self> {
        let dict: &mut PyDict = obj.extract()?;
        let mut params = trace::Params::default();

        params.return_address = dict
            .get_item("return_address")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get return address",
            ))?
            .extract::<u64>()?;

        // FIXME: optional parameter
        params.limit = dict
            .get_item("limit")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get limit",
            ))?
            .extract::<u64>()?;

        // FIXME: optional parameter
        params.save_context = dict
            .get_item("save_context")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get save context",
            ))?
            .extract::<bool>()?;

        let coverage_mode: &str = dict
            .get_item("coverage")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get coverage_mode",
            ))?
            .extract()?;

        params.coverage_mode = trace::CoverageMode::from_str(coverage_mode)
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("invalid coverage mode {}", e)))?;

        // FIXME: optional parameter
        params.save_instructions = dict
            .get_item("save_instructions")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "missing parameter: save_instructions",
            ))?
            .extract()?;

        params.excluded_addresses = dict
            .get_item("excluded_addresses")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get excluded addresses",
            ))?
            .extract()?;

        let max_duration = dict .get_item("max_duration");
        if let Some(duration) = max_duration {
            params.max_duration = Duration::new(duration.extract()?, 0);

        }

        Ok(TraceParams(params))
    }
}

#[pyclass]
pub struct TraceResult {
    trace: trace::Trace,
}


#[pymethods]
impl TraceResult {
    fn get_coverage(&mut self) -> PyResult<PyObject> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let lst = PyList::empty(py);

        for (address, context) in self.trace.coverage.iter() {
            let item = PyDict::new(py);
            if let Some(context) = context {
                item.set_item("rax", context.rax)?;
                item.set_item("rbx", context.rbx)?;
                item.set_item("rcx", context.rcx)?;
                item.set_item("rdx", context.rdx)?;
                item.set_item("rsi", context.rsi)?;
                item.set_item("rdi", context.rdi)?;
                item.set_item("rsp", context.rsp)?;
                item.set_item("rbp", context.rbp)?;
                item.set_item("r8", context.r8)?;
                item.set_item("r9", context.r9)?;
                item.set_item("r10", context.r10)?;
                item.set_item("r11", context.r11)?;
                item.set_item("r12", context.r12)?;
                item.set_item("r13", context.r13)?;
                item.set_item("r14", context.r14)?;
                item.set_item("r15", context.r15)?;
                item.set_item("rflags", context.rflags)?;
                item.set_item("rip", context.rip)?;
            } else {
                item.set_item("rip", address)?;
            }
            lst.append(item)?;
        }
        Ok(lst.into())
    }

    fn get_instructions(&mut self) -> PyObject {
        let gil = Python::acquire_gil();
        let py = gil.python();
        PyList::new(py, &self.trace.instrs).into()
    }

    fn get_unique_addresses(&mut self) -> PyObject {
        let gil = Python::acquire_gil();
        let py = gil.python();
        PyList::new(py, &self.trace.seen).into()
    }

    fn get_status(&mut self) -> PyObject {
        let gil = Python::acquire_gil();
        let py = gil.python();
        PyString::new(py, &self.trace.status.to_string()).into()
    }

    fn get_elapsed_time(&mut self) -> PyObject {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let output = if let (Some(start), Some(end)) = (self.trace.start, self.trace.end) {
            format!("{:?}", end.duration_since(start))
        } else {
            format!("unknown")
        };

        PyString::new(py, &output).into()
    }

    fn save(&mut self, path: String) -> PyResult<()> {
        self.trace.save(&path)
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't save trace {}", e)))?;
        Ok(())
    }

}

#[pyproto]
impl pyo3::PyObjectProtocol for TraceResult {
    fn __str__(&self) -> PyResult<String> {
        Ok(format!(
            "coverage {}, status {:?}",
            self.trace.coverage.len(),
            self.trace.status
        ))
    }
}


struct FuzzParams(fuzz::Params);

impl<'source> pyo3::FromPyObject<'source> for FuzzParams {
    fn extract(obj: &'source PyAny) -> PyResult<Self> {
        let params: &mut PyDict = obj.extract()?;

        let max_iterations = params
            .get_item("max_iterations")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get max iterations",
            ))?
            .extract::<u64>()?;
        let max_time = params
            .get_item("max_time")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get max time"))?
            .extract::<u64>()?;
        let input = params
            .get_item("input")
            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get input"))?
            .extract::<u64>()?;
        let input_size = params
            .get_item("input_size")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get input size",
            ))?
            .extract::<u64>()?;
        let stop_on_crash: bool = params
            .get_item("stop_on_crash")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get stop on crash",
            ))?
            .extract()?;
        let display_delay = params
            .get_item("display_delay")
            .ok_or(PyErr::new::<exceptions::Exception, _>(
                "can't get display delay",
            ))?
            .extract::<u64>()?;

        let params = fuzz::Params {
            max_iterations: max_iterations,
            max_duration: Duration::new(max_time, 0),
            input: input,
            input_size: input_size,
            stop_on_crash: stop_on_crash,
            display_delay: Duration::new(display_delay, 0),
        };
        Ok(FuzzParams(params))
    }
}

#[pyclass]
pub struct Fuzzer {
    path: String,
}

#[pymethods]
impl Fuzzer {
    #[new]
    pub fn new(obj: &PyRawObject, path: PyObject, py: Python) -> PyResult<()> {
        let path: String = path.extract(py)?;

        obj.init({
            Fuzzer {
                path: path,
            }
        });

        Ok(())
    }

    pub fn run(&mut self, tracer: PyObject, context: &PyDict, trace_params: &PyDict, fuzz_params: &PyDict, py: Python) -> PyResult<()> {
        let tracer: &mut Tracer = tracer.extract(py)?;
        let context: ProcessorState = context.extract()?;

        let trace_params: TraceParams = trace_params.extract()?;
        let fuzz_params: FuzzParams = fuzz_params.extract()?;

        let mut fuzzer = fuzz::Fuzzer::new(&self.path)
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't create fuzzer: {}", e)))?;

        let mut strategy = fuzz::RandomStrategy::new();
        fuzzer.run(&mut strategy, &fuzz_params.0, &mut tracer.tracer, &context.0, &trace_params.0)
            .map_err(|e| PyErr::new::<exceptions::Exception, _>(format!("can't run fuzzer: {}", e)))?;

        Ok(())
    }
}


