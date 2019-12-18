
use std::convert::TryInto;
use std::collections::HashSet;
use std::time::Duration;
use std::thread;
use std::sync::mpsc;

use pyo3::prelude::*;
use pyo3::exceptions;
use pyo3::types::*;

use zydis;

use lain::hexdump;

use crate::whvp;
use crate::mem;
use crate::fuzz;
use crate::watch;

use crate::mem::X64VirtualAddressSpace;

#[pyclass]
#[derive(Copy, Clone, Default)]
pub struct EmulatorExit {
    pub reason: i32,
    pub rip: u64,
    pub rflags: u64,
    pub exception_type: u8,
    pub exception_parameter: u64,
    pub error_code: u32,
    pub gva: u64,
    pub gpa: u64,
    pub access_type: u32,
    pub gpa_unmapped: u32,
    pub gva_valid: u32,
    pub instruction_bytes: [u8; 0x10]
}

impl From<whvp::ExitContext> for EmulatorExit {

    fn from(_i: whvp::ExitContext) -> EmulatorExit {
        let exit = EmulatorExit::default();
        exit
    } 
}

#[pymethods]
impl EmulatorExit {

    #[getter]
    fn reason(&self) -> i32 {
        self.reason
    }

    #[getter]
    fn rip(&self) -> u64 {
        self.rip
    }

    #[getter]
    fn rflags(&self) -> u64 {
        self.rflags
    }

    #[getter]
    fn exception_type(&self) -> u8 {
        self.exception_type
    }

    #[getter]
    fn exception_parameter(&self) -> u64 {
        self.exception_parameter
    }

    #[getter]
    fn error_code(&self) -> u32 {
        self.error_code
    }

    #[getter]
    fn gpa(&self) -> u64 {
        self.gpa
    }

    #[getter]
    fn gva(&self) -> u64 {
        self.gva
    }

    #[getter]
    fn access_type(&self) -> u32 {
        self.access_type
    }

    #[getter]
    fn gpa_unmapped(&self) -> u32 {
        self.gpa_unmapped
    }

    #[getter]
    fn gva_valid(&self) -> u32 {
        self.gva_valid
    }

}

#[pyproto]
impl pyo3::PyObjectProtocol for EmulatorExit {

    fn __str__(&self) -> PyResult<String> {
        // let reason = match self.reason {
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonNone =>
        //         "None",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonMemoryAccess =>
        //         "MemoryAccess",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64IoPortAccess =>
        //         "IoPortAccess",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnrecoverableException =>
        //         "UnrecoverableException",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonInvalidVpRegisterValue =>
        //         "InvalidVpRegisterValue",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnsupportedFeature =>
        //         "UnsupportedFeature",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64InterruptWindow =>
        //         "InterruptWindow",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Halt =>
        //         "Halt",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64ApicEoi =>
        //         "ApicEoi",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess =>
        //         "MsrAccess",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Cpuid =>
        //         "Cpuid",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonException =>
        //         "Exception",
        //     whvp::WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonCanceled =>
        //         "Canceled",
        //     _ => "Invalid"
        // };
        Ok(format!("vm exit: rip {:x}, gva {:x}, gpa {:x}", self.rip, self.gva, self.gpa))
    }

}

// FIXME : try to use enum
// FIXME: move this to whvp mod
// rename to from_whvp_exit_context

// impl EmulatorExit {
//     fn from_whvp(exit_context: whvp::WHV_RUN_VP_EXIT_CONTEXT) -> Self {
//         let exit = EmulatorExit {
//             reason: exit_context.ExitReason,
//             rip: exit_context.VpContext.Rip,
//             rflags: exit_context.VpContext.Rflags,
//             exception_type: unsafe { exit_context.__bindgen_anon_1.VpException.ExceptionType },
//             exception_parameter: unsafe { exit_context.__bindgen_anon_1.VpException.ExceptionParameter },
//             error_code: unsafe { exit_context.__bindgen_anon_1.VpException.ErrorCode },
//             gva: unsafe { exit_context.__bindgen_anon_1.MemoryAccess.Gva },
//             gpa: unsafe { exit_context.__bindgen_anon_1.MemoryAccess.Gpa },
//             access_type: unsafe { exit_context.__bindgen_anon_1.MemoryAccess.AccessInfo.__bindgen_anon_1.AccessType() },
//             gpa_unmapped: unsafe { exit_context.__bindgen_anon_1.MemoryAccess.AccessInfo.__bindgen_anon_1.GpaUnmapped() },
//             gva_valid: unsafe { exit_context.__bindgen_anon_1.MemoryAccess.AccessInfo.__bindgen_anon_1.GvaValid() },
//             instruction_bytes: unsafe { exit_context.__bindgen_anon_1.VpException.InstructionBytes }
//         };
//         exit
//     }
// }

#[derive(Debug,PartialEq,PartialOrd)]
pub enum EmulationStatus {
    Success,
    UnHandledVmExit,
    ForbiddenAddress,
    UnHandledException,
    Stucked,
    LimitExceeded,
}

#[pyclass]
#[derive(Debug,Default)]
pub struct Context {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    pub rip: u64
}

impl From<whvp::PartitionContext> for Context {

    fn from(context: whvp::PartitionContext) -> Self {
        Context {
            rax: unsafe {context.rax.Reg64},
            rbx: unsafe {context.rbx.Reg64},
            rcx: unsafe {context.rcx.Reg64},
            rdx: unsafe {context.rdx.Reg64},
            rsi: unsafe {context.rsi.Reg64},
            rdi: unsafe {context.rdi.Reg64},
            rsp: unsafe {context.rsp.Reg64},
            rbp: unsafe {context.rbp.Reg64},
            r8: unsafe {context.r8.Reg64},
            r9: unsafe {context.r9.Reg64},
            r10: unsafe {context.r10.Reg64},
            r11: unsafe {context.r11.Reg64},
            r12: unsafe {context.r12.Reg64},
            r13: unsafe {context.r13.Reg64},
            r14: unsafe {context.r14.Reg64},
            r15: unsafe {context.r15.Reg64},
            rflags: unsafe {context.rflags.Reg64},
            rip: unsafe {context.rip.Reg64},
        }
    }

}

#[pyclass]
pub struct EmulationResult {
    pub coverage: Vec<u64>,
    pub context: Vec<Context>,
    pub exits: u64,
    pub status: EmulationStatus,
}

impl EmulationResult {

    pub fn new() -> Self {
        EmulationResult {
            coverage: Vec::new(),
            context: Vec::new(),
            exits: 0,
            status: EmulationStatus::Success,
        }
    }

}

impl std::fmt::Display for EmulationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "vm exit: {}, coverage {}, status {:?}", self.exits, self.coverage.len(), self.status)
    }
}

#[pymethods]
impl EmulationResult {

    fn get_coverage(&mut self) -> PyObject {
        let gil = Python::acquire_gil();
        let py = gil.python();
        PyList::new(py, &self.coverage).into()
    }

    fn get_context(&mut self) -> PyResult<PyObject> {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let lst = PyList::empty(py);

        for context in &self.context {
            let item = PyDict::new(py);
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
            lst.append(item)?;
        }

        Ok(lst.into())
    }
}

#[pyproto]
impl pyo3::PyObjectProtocol for EmulationResult {

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("vm exit: {}, coverage {}, status {:?}", self.exits, self.coverage.len(), self.status))
    }

}

#[pyclass]
pub struct Emulator {
    partition: whvp::Partition,
    allocator: mem::Allocator,
    snapshot: mem::GpaManager,
    pub code: u64,
    pub data: u64
}

impl Emulator {

    fn fetch_gpa(&mut self, memory_access_callback: &PyObject, gpa: usize, gva: usize, data: &mut [u8], py: Python) -> PyResult<()> {
        let args = (gpa, gva);
        let callback_result = memory_access_callback.call(py, args, None)?;
        let bytes = match <PyBytes as PyTryFrom>::try_from(callback_result.as_ref(py)) {
            Ok(bytes) => bytes,
            Err(_) => return Err(PyErr::new::<exceptions::Exception, _>("callback should return bytes"))
        };
        data.copy_from_slice(bytes.as_bytes());
        Ok(())
    }

}

#[pymethods]
impl Emulator {

    #[new]
    pub fn new(obj: &PyRawObject) -> PyResult<()> {
        let partition = whvp::Partition::new()?;
        let allocator = mem::Allocator::new();
        let snapshot = mem::GpaManager::new();
        obj.init({
            Emulator {
                partition: partition,
                allocator: allocator,
                snapshot: snapshot,
                code: 0,
                data: 0,
            }
        });
        Ok(())
    }

    // FIXME: get_regs variant?
    fn get_reg(&mut self, name: &str) -> PyResult<u64> {
        let context = self.partition.get_regs()?;
        let value = match name {
            "rax" => Ok(unsafe { context.rax.Reg64 }),
            "rbx" => Ok(unsafe { context.rbx.Reg64 }),
            "rcx" => Ok(unsafe { context.rcx.Reg64 }),
            "rdx" => Ok(unsafe { context.rdx.Reg64 }),
            "rsi" => Ok(unsafe { context.rsi.Reg64 }),
            "rdi" => Ok(unsafe { context.rdi.Reg64 }),
            "rsp" => Ok(unsafe { context.rsp.Reg64 }),
            "rbp" => Ok(unsafe { context.rbp.Reg64 }),
            "r8" => Ok(unsafe { context.r8.Reg64 }),
            "r9" => Ok(unsafe { context.r9.Reg64 }),
            "r10" => Ok(unsafe { context.r10.Reg64 }),
            "r11" => Ok(unsafe { context.r11.Reg64 }),
            "r12" => Ok(unsafe { context.r12.Reg64 }),
            "r13" => Ok(unsafe { context.r13.Reg64 }),
            "r14" => Ok(unsafe { context.r14.Reg64 }),
            "r15" => Ok(unsafe { context.r15.Reg64 }),
            "rflags" => Ok(unsafe { context.rflags.Reg64 }),
            "rip" => Ok(unsafe { context.rip.Reg64 }),
            "cr0" => Ok(unsafe { context.cr0.Reg64 }),
            "cr3" => Ok(unsafe { context.cr3.Reg64 }),
            "cr4" => Ok(unsafe { context.cr4.Reg64 }),
            "cr8" => Ok(unsafe { context.cr8.Reg64 }),
            _ => Err(PyErr::new::<exceptions::ValueError, _>("invalid register"))
        };
        value
    }

    fn set_reg(&mut self, name: &str, value: u64) -> PyResult<()> {
        let mut context = self.partition.get_regs()?;
        let result = match name {
            "rax" => {
                context.rax.Reg64 = value;
                Ok(())
            }, 
            "rbx" => {
                context.rbx.Reg64 = value;
                Ok(())
            },
            "rcx" => {
                context.rcx.Reg64 = value;
                Ok(())
            },
            "rdx" => {
                context.rdx.Reg64 = value;
                Ok(())
            },
            "rsi" => {
                context.rsi.Reg64 = value;
                Ok(())
            },
            "rdi" => {
                context.rdi.Reg64 = value;
                Ok(())
            },
            "rsp" => {
                context.rsp.Reg64 = value;
                Ok(())
            },
            "rbp" => {
                context.rbp.Reg64 = value;
                Ok(())
            },
            "r8" => {
                context.r8.Reg64 = value;
                Ok(())
            },
            "r9" => {
                context.r9.Reg64 = value;
                Ok(())
            },
            "r10" => {
                context.r10.Reg64 = value;
                Ok(())
            },
            "r11" => {
                context.r11.Reg64 = value;
                Ok(())
            },
            "r12" => {
                context.r12.Reg64 = value;
                Ok(())
            },
            "r13" => {
                context.r13.Reg64 = value;
                Ok(())
            },
            "r14" => {
                context.r14.Reg64 = value;
                Ok(())
            },
            "r15" => {
                context.r15.Reg64 = value;
                Ok(())
            },
            "rflags" => {
                context.rflags.Reg64 = value;
                Ok(())
            },
            "rip" => {
                context.rip.Reg64 = value;
                Ok(())
            },
            "cr0" => {
                context.cr0.Reg64 = value;
                Ok(())
            },
            "cr3" => {
                context.cr3.Reg64 = value;
                Ok(())
            },
            "cr4" => {
                context.cr4.Reg64 = value;
                Ok(())
            },
            "cr8" => {
                context.cr8.Reg64 = value;
                Ok(())
            },
            "efer" => {
                context.efer.Reg64 = value;
                Ok(())
            },
            "kernel_gs_base" => {
                context.kernel_gs_base.Reg64 = value;
                Ok(())
            },
            _ => Err(PyErr::new::<exceptions::ValueError, _>("invalid register"))
        };
        self.partition.set_regs(&context)?;
        result
    }

    fn set_table_reg(&mut self, name: &str, base: u64, limit: u16) -> PyResult<()> {
        let mut context = self.partition.get_regs()?;
        let result = match name {
            "gdt" => {
                context.gdtr.Table.Base = base;
                context.gdtr.Table.Limit = limit;
                Ok(())
            }, 
            "idt" => {
                context.idtr.Table.Base = base;
                context.idtr.Table.Limit = limit;
                Ok(())
            },
            _ => Err(PyErr::new::<exceptions::ValueError, _>("invalid register"))
        };
        self.partition.set_regs(&context)?;
        result
    }

    fn set_segment_reg(&mut self, name: &str, base: u64, limit: u32, long: u16, privilege: u16, selector: u16) -> PyResult<()> {
        let mut context = self.partition.get_regs()?;
        let result = match name {
            "cs" => {
                context.cs.Segment.Base = base;
                context.cs.Segment.Limit = limit;
                unsafe {
                    context.cs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(long);
                    context.cs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(privilege);
                }
                context.cs.Segment.Selector = selector;
                Ok(())
            }, 
            "ds" => {
                context.ds.Segment.Base = base;
                context.ds.Segment.Limit = limit;
                unsafe {
                    context.ds.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(long);
                    context.ds.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(privilege);
                }
                context.ds.Segment.Selector = selector;
                Ok(())
            }, 
            "es" => {
                context.es.Segment.Base = base;
                context.es.Segment.Limit = limit;
                unsafe {
                    context.es.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(long);
                    context.es.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(privilege);
                }
                context.es.Segment.Selector = selector;
                Ok(())
            }, 
            "fs" => {
                context.fs.Segment.Base = base;
                context.fs.Segment.Limit = limit;
                unsafe {
                    context.fs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(long);
                    context.fs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(privilege);
                }
                context.fs.Segment.Selector = selector;
                Ok(())
            }, 
            "gs" => {
                context.gs.Segment.Base = base;
                context.gs.Segment.Limit = limit;
                unsafe {
                    context.gs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(long);
                    context.gs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(privilege);
                }
                context.gs.Segment.Selector = selector;
                Ok(())
            }, 
            "ss" => {
                context.ss.Segment.Base = base;
                context.ss.Segment.Limit = limit;
                unsafe {
                    context.ss.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(long);
                    context.ss.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(privilege);
                }
                context.ss.Segment.Selector = selector;
                Ok(())
            }, 
            _ => Err(PyErr::new::<exceptions::ValueError, _>("invalid register"))
        };
        self.partition.set_regs(&context)?;
        result
    }

    fn allocate_physical_memory(&mut self, addr: usize, size: usize) -> PyResult<usize> {
        let pages: usize = self.allocator.allocate_physical_memory(size);
        let permissions = whvp::MapGpaRangeFlags::Read |
            whvp::MapGpaRangeFlags::Write |
            whvp::MapGpaRangeFlags::Execute;

        match self.partition.map_physical_memory(addr, pages, size, permissions.bits()) {
            Ok(()) => {
                return Ok(pages)
            },
            _ => {
                return Err(PyErr::new::<exceptions::ValueError, _>("can't allocate physical memory"))
            }
        }
    }

    fn read_physical_memory(&mut self, addr: usize, size: usize) -> PyResult<PyObject> {
        let data = self.partition.read_physical_memory(addr, size);
        match data {
            Ok(slice) => {
                let gil = Python::acquire_gil();
                let py = gil.python();
                return Ok(PyBytes::new(py, slice).into())
            },
            _ => {
                return Err(PyErr::new::<exceptions::ValueError, _>("invalid region"))
            }
        }
    }

    fn write_physical_memory(&mut self, addr: usize, bytes: &PyBytes) -> PyResult<usize> {
        match self.partition.write_physical_memory(addr, bytes.as_bytes()) {
            Ok(len) => {
                return Ok(len)
            },
            _ => {
                return Err(PyErr::new::<exceptions::ValueError, _>("invalid region"))
            }
        }
    }

    fn is_physical_memory_valid(&mut self, addr: usize, size: usize) -> bool {
        self.partition.is_physical_memory_valid(addr, size)
    }

    pub fn run(&mut self) -> PyResult<EmulatorExit> {
        match self.partition.run() {
            Ok(exit) => {
                let exit_context: whvp::ExitContext = exit.into();
                // FIXME: to complete
                let exit: EmulatorExit = exit_context.into();
                return Ok(exit)
            },
            _ => {
                return Err(PyErr::new::<exceptions::Exception, _>("can't run emulator"))
            }
        }
    }

    #[args(limit=0)]
    pub fn run_until(&mut self, params: &PyDict, memory_access_callback: PyObject, limit: u64, py: Python) -> PyResult<EmulationResult> {
        let mut result = EmulationResult::new();
        let params: &mut PyDict = params.extract()?;

        let return_address = params.get_item("return_address")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get return_address"))?
                            .extract::<u64>()?;

        let coverage_mode: &str = params.get_item("coverage_mode")
                        .ok_or(PyErr::new::<exceptions::Exception, _>("can't get coverage_mode"))?
                        .extract()?;

        let mut context = self.partition.get_regs()?;

        // FIXME: have a struct for tracing mode
        match coverage_mode {
            "no" => {},
            "instrs" => {
                let rflags = unsafe { context.rflags.Reg64 };
                context.rflags.Reg64 = rflags | 0x100;
                self.partition.set_regs(&context)?;
            },
            "hit" => {},
            "bbl" => {},
            _ => {
                return Err(PyErr::new::<exceptions::Exception, _>("invalid coverage mode"))
            }
        }

        let save_context: bool = params.get_item("save_context")
                        .ok_or(PyErr::new::<exceptions::Exception, _>("can't get save_context"))?
                        .extract()?;

        let stopping_addresses = params.get_item("stopping_addresses")
                        .ok_or(PyErr::new::<exceptions::Exception, _>("can't get stopping addresses"))?
                        .extract::<Vec<u64>>()?;

        let bp = [0xcc; 1];
        let cr3 = unsafe { context.cr3.Reg64 };
        let _ = self.partition.write_gva(cr3, return_address, &bp);
        for addr in stopping_addresses.iter() {
            let _ = self.partition.write_gva(cr3, *addr, &bp);
        }

        let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64).unwrap();
        // FIXME: use args to set this
        let display_instructions = true;
        let mut cancel = 0;
        while limit == 0 || result.exits < limit {
            match self.partition.run() {
                Ok(exit) => {
                    let exit_context: whvp::ExitContext = exit.into();
                    result.exits += 1;
                    match exit_context {
                        whvp::ExitContext::MemoryAccess(_vp_context, memory_access_context) => {
                            cancel = 0;
                            let gpa = memory_access_context.Gpa;
                            let gva = memory_access_context.Gva;
                            
                            let access_type = memory_access_context.AccessInfo.AccessType;
                            let mut data: [u8; 4096] = [0; 4096];
                            self.fetch_gpa(&memory_access_callback, gpa as usize, gva as usize, &mut data, py)?;

                            let base: usize = (gpa & !0xfff).try_into()?;
                            self.allocate_physical_memory(base, 0x1000)?;
                            
                            if coverage_mode == "hit" && access_type == whvp::MemoryAccessType::Execute {
                                let page: &PyBytes = PyBytes::new(py, &[0xcc; 4096]);
                                self.write_physical_memory(base, page)?;

                            } else {
                                let gva_base = return_address & !0xfff;
                                let offset: usize = (return_address & 0xfff).try_into()?;
                                if gva_base <= gva && gva < gva_base + 0x1000 {
                                    data[offset] = 0xcc;
                                }
                                for addr in stopping_addresses.iter() {
                                    let gva_base = addr & !0xfff;
                                    let offset: usize = (addr & 0xfff).try_into()?;
                                    if gva_base <= gva && gva < gva_base + 0x1000 {
                                        data[offset] = 0xcc;
                                    }
                                }
                                let page: &PyBytes = PyBytes::new(py, &data);
                                self.write_physical_memory(base, page)?;
                            }

                            self.snapshot.add_page(base as u64, data);

                            if access_type == whvp::MemoryAccessType::Execute {
                                self.code += 1;
                            } else {
                                self.data += 1;
                            }
                        },
                        whvp::ExitContext::Exception(vp_context, exception_context) => {
                            cancel = 0;
                            let rip = vp_context.Rip;
                            let exception_type: whvp::ExceptionType = exception_context.ExceptionType.into();
                            if vp_context.ExecutionState.InterruptShadow {
                                println!("interrupt shadow");
                                let mut interrupt_context = self.partition.get_regs()?;
                                unsafe { interrupt_context.interrupt_state.InterruptState.__bindgen_anon_1.set_InterruptShadow(0) };
                                self.partition.set_regs(&interrupt_context)?;
                            }
                            if display_instructions {
                                let _ = display_buffer(rip, &exception_context.InstructionBytes);
                            }
                            match exception_type {
                                whvp::ExceptionType::DebugTrapOrFault |
                                whvp::ExceptionType::BreakpointTrap => {
                                    if coverage_mode == "hit" && exception_type == whvp::ExceptionType::BreakpointTrap {
                                        let paddr = self.partition.translate_virtual_address(rip as usize)
                                            .map_err(|_| PyErr::new::<exceptions::Exception, _>("can't translate virtual address"))?;
                                        
                                        let mut buffer = [0u8; 16];

                                        let cr3 = unsafe { context.cr3.Reg64 };

                                        match self.snapshot.read_gva(cr3, rip as u64, &mut buffer) {
                                            Ok(()) => {},
                                            Err(mem::VirtMemError::MissingPage(gpa)) => {
                                                let mut data: [u8; 4096] = [0; 4096];
                                                self.fetch_gpa(&memory_access_callback, gpa as usize, 0, &mut data, py)?;

                                                let base: usize = (gpa & !0xfff).try_into()?;
                                                let page: &PyBytes = PyBytes::new(py, &[0xcc; 4096]);
                                                self.allocate_physical_memory(base, 0x1000)?;
                                                self.write_physical_memory(base, page)?;

                                                self.snapshot.add_page(base as u64, data);
                                                self.snapshot.read_gva(cr3, rip as u64, &mut buffer)?;
                                            }
                                            Err(err) => {
                                                return Err(err.into())
                                            }
                                        }
                                        if display_instructions {
                                            let _ = display_buffer(rip, &buffer);
                                        }

                                        let instruction = decoder.decode(&buffer)
                                            .map_err(|_| PyErr::new::<exceptions::Exception, _>("can't decode instruction"))?
                                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't decode instruction"))?;
                                        
                                        // FIXME: replace this by self.partition.write_gva(gva, &buffer)
                                        let length = instruction.length as usize;
                                        let offset = (rip & 0xfff) as usize;
                                        let remain = (0x1000 - offset) as usize;
                                        let addr = paddr as usize;
                                        if length <= remain {
                                            let data: &PyBytes = PyBytes::new(py, &buffer[..length]);
                                            self.write_physical_memory(addr, data)?;
                                        } else {
                                            let data: &PyBytes = PyBytes::new(py, &buffer[..remain]);
                                            self.write_physical_memory(addr, data)?;
                                            let addr = (rip + remain as u64) as usize;
                                            let gpa = self.snapshot.translate_gva(cr3, addr as u64)? as usize;
                                            let data: &PyBytes = PyBytes::new(py, &buffer[remain..length]);
                                            self.write_physical_memory(gpa, data)?;
                                        }
                                    }

                                    result.coverage.push(rip as u64);

                                    if save_context {
                                        let context: Context = self.partition.get_regs()?.into();
                                        result.context.push(context);
                                    } 

                                    if rip as u64 == return_address {
                                        result.status = EmulationStatus::Success;
                                        break;
                                    }

                                    if stopping_addresses.contains(&(rip as u64)) {
                                        result.status = EmulationStatus::ForbiddenAddress;
                                        break;
                                    }
                                },
                                _ => {
                                    result.status = EmulationStatus::UnHandledException;
                                    break;
                                }
                            }
                        },
                        whvp::ExitContext::Canceled(_, _) => {
                            cancel += 1;
                            if cancel > 10 {
                                println!("stopping, seems stucked");
                                result.status = EmulationStatus::Stucked;
                                break;
                            }

                        }
                        _ => {
                            println!("unhandled vm exit");
                            result.status = EmulationStatus::UnHandledVmExit;
                            break;
                        }
                    }
                },
                _ => {
                    return Err(PyErr::new::<exceptions::Exception, _>("can't run emulator"))
                }
            }
        }
        if limit != 0 && result.exits > limit {
            result.status = EmulationStatus::LimitExceeded;
        }
        Ok(result)
    }

}

fn display_buffer(rip: u64, buffer: &[u8]) -> PyResult<()> {
    let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64).unwrap();
    let instruction = decoder.decode(&buffer)
        .map_err(|_| PyErr::new::<exceptions::Exception, _>("can't decode instruction"))?
        .ok_or(PyErr::new::<exceptions::Exception, _>("can't decode instruction"))?;

    let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL).unwrap();
    let mut buffer = [0u8; 200];
    let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
    formatter.format_instruction(&instruction, &mut buffer, Some(rip as u64), None).unwrap();
    println!("0x{:016X} {}", rip, buffer);
    Ok(())

}

#[pyclass]
pub struct Fuzzer {
    channel: mpsc::Receiver<Vec<u8>>
}

#[pymethods]
impl Fuzzer {

    #[new]
    pub fn new(obj: &PyRawObject) {
        let (tx, rx) = mpsc::channel();
        let path = ".";
        let _thread = thread::spawn(move || watch::watch(tx, &path));

        obj.init({
            Fuzzer {
                channel: rx,
            }
        });
    }

    pub fn run(&mut self, py_emulator: PyObject, initial_context: &PyDict, params: &PyDict, memory_access_callback: PyObject, report_callback: PyObject, py: Python) -> PyResult<()> {
        let mut emulator: &mut Emulator = py_emulator.extract(py)?;

        let context: &mut PyDict = initial_context.extract()?;
        self.restore_context(&mut emulator.partition, context)?;

        let params: &PyDict = params.extract()?;

        let context = emulator.partition.get_regs()?;

        // FIXME: extract from python dict
        let display_duration = Duration::new(1, 0);

        let fuzz_params = self.get_params(params)?;

        let mut stats = fuzz::Stats::new(display_duration);

        let mut corpus = fuzz::Corpus::new();

        let mut coverage = HashSet::new();

        let cr3 = unsafe { context.cr3.Reg64 };

        let input_size: usize = fuzz_params.input_size.try_into()?;

        println!("executing a first time to map memory");
        let result = emulator.run_until(&params, memory_access_callback.clone_ref(py), 0, py)?;
        match result.status {
            EmulationStatus::Success => {
            },
            _ => {
                return Err(PyErr::new::<exceptions::Exception, _>("first execution failed!"))
            }
        }
        self.restore_mem(&mut emulator)?;

        let mut data = Vec::with_capacity(input_size);
        data.resize(input_size, 0);

        emulator.partition.read_gva(cr3, fuzz_params.input, &mut data)?;

        let mut new = 0;
        for addr in result.coverage.iter() {
            if coverage.insert(*addr) {
                new += 1;
            }
        }

        corpus.add(new, &data);
        
        loop {
            match self.channel.try_recv() {
                Ok(data) => {
                    corpus.worklist.push(data);
                },
                _ => {}
            }
            
            let data: Vec<u8> = match corpus.get_next_input() {
                None => {
                    println!("no more input, quitting");
                    break;
                },
                Some(data) => {
                    data
                }
            };

            let mut input = corpus.mutate_input(&data);
            input.truncate(input_size);

            match emulator.partition.write_gva(cr3, fuzz_params.input, &input) {
                Ok(()) => {
                },
                Err(e) => {
                    println!("can't write fuzzer input {:?}", e);
                    break;
                }
            }
 
            emulator.partition.set_regs(&context)?;

            let result = emulator.run_until(&params, memory_access_callback.clone_ref(py), 0, py)?;
            match result.status {
                EmulationStatus::ForbiddenAddress => {
                    let bytes: &PyBytes = PyBytes::new(py, &input);
                    let args = (py_emulator.clone_ref(py), bytes);
                    let callback_result = report_callback.call(py, args, None)?;
                },
                EmulationStatus::Stucked => {
                    println!("hanged");
                    let crash_context = emulator.partition.get_regs()?;
                    println!("{}", crash_context);
                    break;
                },
                _ => {}
            }

            stats.iterations += 1;
            stats.total_iterations += 1;

            let mut new = 0;
            for addr in result.coverage.iter() {
                if coverage.insert(*addr) {
                    new += 1;
                }
            }

            if new > 0 {
                corpus.add(new, &input);
            }
            stats.coverage += new as u64;
            stats.total_coverage = coverage.len() as u64;

            stats.code = emulator.code;
            stats.data = emulator.data;

            stats.check_display();

            if fuzz_params.max_duration.as_secs() != 0 && stats.total_start.elapsed() > fuzz_params.max_duration {
                break;
            }

            if fuzz_params.max_iterations != 0 && stats.total_iterations > fuzz_params.max_iterations {
                break;
            }

            self.restore_mem(&mut emulator)?;

        }

        corpus.display();
        Ok(())

    }

}

impl Fuzzer {
    fn get_params(&mut self, params: &PyDict) -> PyResult<fuzz::Params> {
        let max_iterations = params.get_item("max_iterations")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get max iterations"))?
                            .extract::<u64>()?;
        let max_time = params.get_item("max_time")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get max time"))?
                            .extract::<u64>()?;
        let input = params.get_item("input")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get input"))?
                            .extract::<u64>()?;
        let input_size = params.get_item("input_size")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get input size"))?
                            .extract::<u64>()?;
        let input_type: &str = params.get_item("input_type")
                        .ok_or(PyErr::new::<exceptions::Exception, _>("can't get input type"))?
                        .extract()?;

        let params = fuzz::Params {
            max_iterations: max_iterations,
            max_duration: Duration::new(max_time, 0),
            input: input,
            input_size: input_size,
            input_type: match input_type {
                "reg" => fuzz::InputType::Reg,
                "mem" => fuzz::InputType::Mem,
                _ => return Err(PyErr::new::<exceptions::Exception, _>("bad input type"))
            }
        };
        Ok(params)

    }

    fn restore_context(&mut self, partition: &mut whvp::Partition, context: &PyDict) -> PyResult<bool> {
        let mut regs = partition.get_regs()?;

        let value = context.get_item("rax")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rax"))?
                            .extract::<u64>()?;
        regs.rax.Reg64 = value;

        let value = context.get_item("rbx")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rbx"))?
                            .extract::<u64>()?;
        regs.rbx.Reg64 = value;

        let value = context.get_item("rcx")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rcx"))?
                            .extract::<u64>()?;
        regs.rcx.Reg64 = value;

        let value = context.get_item("rdx")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rdx"))?
                            .extract::<u64>()?;
        regs.rdx.Reg64 = value;

        let value = context.get_item("rsi")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rsi"))?
                            .extract::<u64>()?;
        regs.rsi.Reg64 = value;

        let value = context.get_item("rdi")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rdi"))?
                            .extract::<u64>()?;
        regs.rdi.Reg64 = value;

        let value = context.get_item("rsp")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rsp"))?
                            .extract::<u64>()?;
        regs.rsp.Reg64 = value;

        let value = context.get_item("rbp")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rbp"))?
                            .extract::<u64>()?;
        regs.rbp.Reg64 = value;

        let value = context.get_item("r8")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r8"))?
                            .extract::<u64>()?;
        regs.r8.Reg64 = value;

        let value = context.get_item("r9")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r9"))?
                            .extract::<u64>()?;
        regs.r9.Reg64 = value;

        let value = context.get_item("r10")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r10"))?
                            .extract::<u64>()?;
        regs.r10.Reg64 = value;

        let value = context.get_item("r11")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r11"))?
                            .extract::<u64>()?;
        regs.r11.Reg64 = value;

        let value = context.get_item("r12")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r12"))?
                            .extract::<u64>()?;
        regs.r12.Reg64 = value;

        let value = context.get_item("r13")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r13"))?
                            .extract::<u64>()?;
        regs.r13.Reg64 = value;

        let value = context.get_item("r14")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r14"))?
                            .extract::<u64>()?;
        regs.r14.Reg64 = value;

        let value = context.get_item("r15")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get r15"))?
                            .extract::<u64>()?;
        regs.r15.Reg64 = value;

        let value = context.get_item("rflags")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rflags"))?
                            .extract::<u64>()?;
        regs.rflags.Reg64 = value;

        let value = context.get_item("rip")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get rip"))?
                            .extract::<u64>()?;
        regs.rip.Reg64 = value;

        let value = context.get_item("cr0")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr0"))?
                            .extract::<u64>()?;
        regs.cr0.Reg64 = value;

        let value = context.get_item("cr3")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr3"))?
                            .extract::<u64>()?;
        regs.cr3.Reg64 = value;

        let value = context.get_item("cr4")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr4"))?
                            .extract::<u64>()?;
        regs.cr4.Reg64 = value;

        let value = context.get_item("cr8")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cr8"))?
                            .extract::<u64>()?;
        regs.cr8.Reg64 = value;

        let value = context.get_item("efer")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get efer"))?
                            .extract::<u64>()?;
        regs.efer.Reg64 = value;

        let base = context.get_item("gdtr")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gdtr"))?
                            .extract::<u64>()?;
        let limit = context.get_item("gdtl")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gdtl"))?
                            .extract::<u16>()?;
        regs.gdtr.Table.Base = base;
        regs.gdtr.Table.Limit = limit;

        let base = context.get_item("idtr")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get idtr"))?
                            .extract::<u64>()?;
        let limit = context.get_item("idtl")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get idtl"))?
                            .extract::<u16>()?;
        regs.idtr.Table.Base = base;
        regs.idtr.Table.Limit = limit;

        let selector = context.get_item("cs")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get cs"))?
                            .extract::<u16>()?;
        regs.cs.Segment.Base = 0;
        regs.cs.Segment.Limit = 0;
        unsafe {
            regs.cs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(1);
            regs.cs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(0);
        }
        regs.cs.Segment.Selector = selector;

        let selector = context.get_item("ss")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get ss"))?
                            .extract::<u16>()?;
        regs.ss.Segment.Base = 0;
        regs.ss.Segment.Limit = 0;
        unsafe {
            regs.ss.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(0);
            regs.ss.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(0);
        }
        regs.ss.Segment.Selector = selector;

        let selector = context.get_item("ds")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get ds"))?
                            .extract::<u16>()?;
        regs.ds.Segment.Base = 0;
        regs.ds.Segment.Limit = 0;
        unsafe {
            regs.ds.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(0);
            regs.ds.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(0);
        }
        regs.ds.Segment.Selector = selector;

        let selector = context.get_item("es")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get es"))?
                            .extract::<u16>()?;
        regs.es.Segment.Base = 0;
        regs.es.Segment.Limit = 0;
        unsafe {
            regs.es.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(0);
            regs.es.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(0);
        }
        regs.es.Segment.Selector = selector;

        let selector = context.get_item("fs")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get fs"))?
                            .extract::<u16>()?;
        let base = context.get_item("fs_base")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get fs base"))?
                            .extract::<u64>()?;
        regs.fs.Segment.Base = base;
        regs.fs.Segment.Limit = 0;
        unsafe {
            regs.fs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(0);
            regs.fs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(0);
        }
        regs.fs.Segment.Selector = selector;

        let selector = context.get_item("gs")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gs"))?
                            .extract::<u16>()?;
        let base = context.get_item("gs_base")
                            .ok_or(PyErr::new::<exceptions::Exception, _>("can't get gs base"))?
                            .extract::<u64>()?;
        regs.gs.Segment.Base = base;
        regs.gs.Segment.Limit = 0;
        unsafe {
            regs.gs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_Long(0);
            regs.gs.Segment.__bindgen_anon_1.__bindgen_anon_1.set_DescriptorPrivilegeLevel(0);
        }
        regs.gs.Segment.Selector = selector;

        partition.set_regs(&regs)?;
        Ok(true)
    }

    fn restore_mem(&mut self, emulator: &mut Emulator) -> PyResult<bool> {
        let partition = &mut emulator.partition;
        let regions = &mut partition.mapped_regions;
        let mut addresses = regions.iter().map(|region| region.base).collect::<Vec<_>>();
        addresses.sort();
        for addr in addresses.iter() {
            let bitmap = partition.query_gpa_range(*addr, 0x1000)?;
            if bitmap == 1 {
                if let Some(arr) = emulator.snapshot.pages.get(&(*addr as u64)) {
                    match partition.write_physical_memory(*addr, arr) {
                        Ok(_) => {
                            partition.flush_gpa_range(*addr, 0x1000)?;
                        },
                        _ => {
                            return Err(PyErr::new::<exceptions::ValueError, _>("can't restore data"))
                        }
                    }
                }
            }
        }
        Ok(true)
    }
}

impl From<mem::VirtMemError> for PyErr {

    fn from(err: mem::VirtMemError) -> Self {
        let msg = format!("{:?}", err);
        return PyErr::new::<exceptions::Exception, _>(msg);
    }

}

impl From<whvp::PartitionError> for PyErr {

    fn from(err: whvp::PartitionError) -> Self {
        let msg = format!("{:?}", err);
        return PyErr::new::<exceptions::Exception, _>(msg);
    }

}