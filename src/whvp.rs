

use std::mem::size_of;
use std::mem::zeroed;
use std::ptr::null_mut;
use std::ffi::c_void;
use std::error::Error;
use std::fmt;
use std::slice::from_raw_parts_mut;
use std::cmp::min;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time;

use whvp_sys::*;

bitflags! {
    pub struct MapGpaRangeFlags : i32 {
        const NONE = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagNone;
        const READ = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagRead;
        const WRITE = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagWrite;
        const EXECUTE = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagExecute;
        const TRACK_DIRTY_PAGES = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagTrackDirtyPages;
    }
}

bitflags! {
    pub struct TranslateGvaFlags : i32 {
        const NONE = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagNone;
        const VALIDATE_READ = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateRead;
        const VALIDATE_WRITE = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateWrite;
        const VALIDATE_EXECUTE = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateExecute;
        const PRIVILEGE_EXEMPT = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagPrivilegeExempt;
        const SET_PAGE_TABLE_BITS = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagSetPageTableBits;
    }
}

bitflags! {
    pub struct MemoryAccessType : i32 {
        const EXECUTE = WHV_MEMORY_ACCESS_TYPE_WHvMemoryAccessExecute;
    }
}

bitflags! {
    pub struct ExceptionType : u64 {
        const DIVIDE_ERROR_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeDivideErrorFault;
        const DEBUG_TRAP_OR_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeDebugTrapOrFault;
        const BREAKPOINT_TRAP = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeBreakpointTrap;
        const OVERFLOW_TRAP = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeOverflowTrap;
        const BOUND_RANGE_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeBoundRangeFault;
        const INVALID_OPCODE_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeInvalidOpcodeFault;
        const DEVICE_NOT_AVAILABLE_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeDeviceNotAvailableFault;
        const DOUBLE_FAULT_ABORT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeDoubleFaultAbort;
        const INVALID_TASK_STATE_SEGMENT_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeInvalidTaskStateSegmentFault;
        const SEGMENT_NOT_PRESENT_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeSegmentNotPresentFault;
        const STACK_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeStackFault;
        const GENERAL_PROTECTION_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeGeneralProtectionFault;
        const PAGE_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypePageFault;
        const FLOATING_POINT_ERROR_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeFloatingPointErrorFault;
        const ALIGNMENT_CHECK_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeAlignmentCheckFault;
        const MACHINE_CHECK_ABORT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeMachineCheckAbort;
        const SIMD_FLOATING_POINT_FAULT = 1 << WHV_EXCEPTION_TYPE_WHvX64ExceptionTypeSimdFloatingPointFault;
    }
}

bitflags! {
    pub struct ExitReason : i32 {
        const NONE = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonNone;
        const MEMORY_ACCESS = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonMemoryAccess;
        const PORT_ACCESS = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64IoPortAccess;
        const UNCOVERABLE_EXCEPTION = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnrecoverableException;
        const INVALID_REGISTER = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonInvalidVpRegisterValue;
        const UNSUPPORTED_FEATURE = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonUnsupportedFeature;
        const INTERRUPT_WINDOW = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64InterruptWindow;
        const MSR_ACCESS = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64MsrAccess;
        const CPUID = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonX64Cpuid;
        const EXCEPTION = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonException;
        const CANCELED = WHV_RUN_VP_EXIT_REASON_WHvRunVpExitReasonCanceled;
    }
}

#[derive(Debug)]
pub struct EmulatorError {
    details: String
}

impl EmulatorError {
    fn new(msg: String) -> EmulatorError {
        EmulatorError{details: msg}
    }
}

impl fmt::Display for EmulatorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for EmulatorError {
    fn description(&self) -> &str {
        &self.details
    }
}

const WHV_REGISTER_NAMES: &[i32] = &[
    WHV_REGISTER_NAME_WHvX64RegisterRax,
    WHV_REGISTER_NAME_WHvX64RegisterRcx,
    WHV_REGISTER_NAME_WHvX64RegisterRdx,
    WHV_REGISTER_NAME_WHvX64RegisterRbx,
    WHV_REGISTER_NAME_WHvX64RegisterRsp,
    WHV_REGISTER_NAME_WHvX64RegisterRbp,
    WHV_REGISTER_NAME_WHvX64RegisterRsi,
    WHV_REGISTER_NAME_WHvX64RegisterRdi,
    WHV_REGISTER_NAME_WHvX64RegisterR8,
    WHV_REGISTER_NAME_WHvX64RegisterR9,
    WHV_REGISTER_NAME_WHvX64RegisterR10,
    WHV_REGISTER_NAME_WHvX64RegisterR11,
    WHV_REGISTER_NAME_WHvX64RegisterR12,
    WHV_REGISTER_NAME_WHvX64RegisterR13,
    WHV_REGISTER_NAME_WHvX64RegisterR14,
    WHV_REGISTER_NAME_WHvX64RegisterR15,
    WHV_REGISTER_NAME_WHvX64RegisterRip,
    WHV_REGISTER_NAME_WHvX64RegisterRflags,
    WHV_REGISTER_NAME_WHvX64RegisterEs,
    WHV_REGISTER_NAME_WHvX64RegisterCs,
    WHV_REGISTER_NAME_WHvX64RegisterSs,
    WHV_REGISTER_NAME_WHvX64RegisterDs,
    WHV_REGISTER_NAME_WHvX64RegisterFs,
    WHV_REGISTER_NAME_WHvX64RegisterGs,
    WHV_REGISTER_NAME_WHvX64RegisterLdtr,
    WHV_REGISTER_NAME_WHvX64RegisterTr,
    WHV_REGISTER_NAME_WHvX64RegisterIdtr,
    WHV_REGISTER_NAME_WHvX64RegisterGdtr,
    WHV_REGISTER_NAME_WHvX64RegisterCr0,
    WHV_REGISTER_NAME_WHvX64RegisterCr2,
    WHV_REGISTER_NAME_WHvX64RegisterCr3,
    WHV_REGISTER_NAME_WHvX64RegisterCr4,
    WHV_REGISTER_NAME_WHvX64RegisterCr8,
    WHV_REGISTER_NAME_WHvX64RegisterDr0,
    WHV_REGISTER_NAME_WHvX64RegisterDr1,
    WHV_REGISTER_NAME_WHvX64RegisterDr2,
    WHV_REGISTER_NAME_WHvX64RegisterDr3,
    WHV_REGISTER_NAME_WHvX64RegisterDr6,
    WHV_REGISTER_NAME_WHvX64RegisterDr7,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm0,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm1,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm2,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm3,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm4,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm5,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm6,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm7,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm8,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm9,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm10,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm11,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm12,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm13,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm14,
    // WHV_REGISTER_NAME_WHvX64RegisterXmm15,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx0,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx1,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx2,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx3,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx4,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx5,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx6,
    // WHV_REGISTER_NAME_WHvX64RegisterFpMmx7,
    // WHV_REGISTER_NAME_WHvX64RegisterFpControlStatus,
    // WHV_REGISTER_NAME_WHvX64RegisterXmmControlStatus,
    // WHV_REGISTER_NAME_WHvX64RegisterTsc,
    WHV_REGISTER_NAME_WHvX64RegisterEfer,
    WHV_REGISTER_NAME_WHvX64RegisterKernelGsBase,
    // WHV_REGISTER_NAME_WHvX64RegisterApicBase,
    // WHV_REGISTER_NAME_WHvX64RegisterPat,
    WHV_REGISTER_NAME_WHvX64RegisterSysenterCs,
    WHV_REGISTER_NAME_WHvX64RegisterSysenterEip,
    WHV_REGISTER_NAME_WHvX64RegisterSysenterEsp,
    WHV_REGISTER_NAME_WHvX64RegisterStar,
    WHV_REGISTER_NAME_WHvX64RegisterLstar,
    WHV_REGISTER_NAME_WHvX64RegisterCstar,
    WHV_REGISTER_NAME_WHvX64RegisterSfmask,
    // WHV_REGISTER_NAME_WHvX64RegisterTscAux,
    // WHV_REGISTER_NAME_WHvX64RegisterSpecCtrl,
    // WHV_REGISTER_NAME_WHvX64RegisterPredCmd,
    // WHV_REGISTER_NAME_WHvX64RegisterApicId,
    // WHV_REGISTER_NAME_WHvX64RegisterApicVersion,
    // WHV_REGISTER_NAME_WHvRegisterPendingInterruption,
    // WHV_REGISTER_NAME_WHvRegisterInterruptState,
    // WHV_REGISTER_NAME_WHvRegisterPendingEvent,
    // WHV_REGISTER_NAME_WHvX64RegisterDeliverabilityNotifications,
    // WHV_REGISTER_NAME_WHvRegisterInternalActivityState,
    // WHV_REGISTER_NAME_WHvX64RegisterXCr0,
];

#[repr(C, align(64))]
pub struct EmulatorContext {
    pub rax: WHV_REGISTER_VALUE,
    pub rcx: WHV_REGISTER_VALUE,
    pub rdx: WHV_REGISTER_VALUE,
    pub rbx: WHV_REGISTER_VALUE,
    pub rsp: WHV_REGISTER_VALUE,
    pub rbp: WHV_REGISTER_VALUE,
    pub rsi: WHV_REGISTER_VALUE,
    pub rdi: WHV_REGISTER_VALUE,
    pub r8:  WHV_REGISTER_VALUE,
    pub r9:  WHV_REGISTER_VALUE,
    pub r10: WHV_REGISTER_VALUE,
    pub r11: WHV_REGISTER_VALUE,
    pub r12: WHV_REGISTER_VALUE,
    pub r13: WHV_REGISTER_VALUE,
    pub r14: WHV_REGISTER_VALUE,
    pub r15: WHV_REGISTER_VALUE,
    pub rip: WHV_REGISTER_VALUE,

    pub rflags: WHV_REGISTER_VALUE,

    pub es: WHV_REGISTER_VALUE,
    pub cs: WHV_REGISTER_VALUE,
    pub ss: WHV_REGISTER_VALUE,
    pub ds: WHV_REGISTER_VALUE,
    pub fs: WHV_REGISTER_VALUE,
    pub gs: WHV_REGISTER_VALUE,

    pub ldtr: WHV_REGISTER_VALUE,
    pub tr:   WHV_REGISTER_VALUE,
    pub idtr: WHV_REGISTER_VALUE,
    pub gdtr: WHV_REGISTER_VALUE,

    pub cr0: WHV_REGISTER_VALUE,
    pub cr2: WHV_REGISTER_VALUE,
    pub cr3: WHV_REGISTER_VALUE,
    pub cr4: WHV_REGISTER_VALUE,
    pub cr8: WHV_REGISTER_VALUE,

    pub dr0: WHV_REGISTER_VALUE,
    pub dr1: WHV_REGISTER_VALUE,
    pub dr2: WHV_REGISTER_VALUE,
    pub dr3: WHV_REGISTER_VALUE,
    pub dr6: WHV_REGISTER_VALUE,
    pub dr7: WHV_REGISTER_VALUE,

    // pub xmm0: WHV_REGISTER_VALUE,
    // pub xmm1: WHV_REGISTER_VALUE,
    // pub xmm2: WHV_REGISTER_VALUE,
    // pub xmm3: WHV_REGISTER_VALUE,
    // pub xmm4: WHV_REGISTER_VALUE,
    // pub xmm5: WHV_REGISTER_VALUE,
    // pub xmm6: WHV_REGISTER_VALUE,
    // pub xmm7: WHV_REGISTER_VALUE,
    // pub xmm8: WHV_REGISTER_VALUE,
    // pub xmm9: WHV_REGISTER_VALUE,
    // pub xmm10: WHV_REGISTER_VALUE,
    // pub xmm11: WHV_REGISTER_VALUE,
    // pub xmm12: WHV_REGISTER_VALUE,
    // pub xmm13: WHV_REGISTER_VALUE,
    // pub xmm14: WHV_REGISTER_VALUE,
    // pub xmm15: WHV_REGISTER_VALUE,

    // pub st0: WHV_REGISTER_VALUE,
    // pub st1: WHV_REGISTER_VALUE,
    // pub st2: WHV_REGISTER_VALUE,
    // pub st3: WHV_REGISTER_VALUE,
    // pub st4: WHV_REGISTER_VALUE,
    // pub st5: WHV_REGISTER_VALUE,
    // pub st6: WHV_REGISTER_VALUE,
    // pub st7: WHV_REGISTER_VALUE,

    // pub fp_control:  WHV_REGISTER_VALUE,
    // pub xmm_control: WHV_REGISTER_VALUE,

    // pub tsc: WHV_REGISTER_VALUE,
    pub efer: WHV_REGISTER_VALUE,
    pub kernel_gs_base: WHV_REGISTER_VALUE,
    // pub apic_base: WHV_REGISTER_VALUE,
    // pub pat: WHV_REGISTER_VALUE,
    pub sysenter_cs: WHV_REGISTER_VALUE,
    pub sysenter_eip: WHV_REGISTER_VALUE,
    pub sysenter_esp: WHV_REGISTER_VALUE,
    pub star: WHV_REGISTER_VALUE,
    pub lstar: WHV_REGISTER_VALUE,
    pub cstar: WHV_REGISTER_VALUE,
    pub sfmask: WHV_REGISTER_VALUE,

    // pub tsc_aux: WHV_REGISTER_VALUE,
    // pub spec_ctrl: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub pred_cmd: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub apic_id: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub apic_version: WHV_REGISTER_VALUE, not yet supported by Windows 17763
    // pub pending_interruption: WHV_REGISTER_VALUE,
    // pub interrupt_state: WHV_REGISTER_VALUE,
    // pub pending_event: WHV_REGISTER_VALUE,
    // pub deliverability_notifications: WHV_REGISTER_VALUE,
    // pub internal_activity_state: WHV_REGISTER_VALUE, unknown type

    // pub xcr0: WHV_REGISTER_VALUE,
}

impl std::fmt::Display for EmulatorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        unsafe {
            write!(f,
                "rax {:016x} rcx {:016x} rdx {:016x} rbx {:016x}\n\
                 rsp {:016x} rbp {:016x} rsi {:016x} rdi {:016x}\n\
                 r8  {:016x} r9  {:016x} r10 {:016x} r11 {:016x}\n\
                 r12 {:016x} r13 {:016x} r14 {:016x} r15 {:016x}\n\
                 rip {:016x}\n\
                 rflags {:016x}\n\
                 ",
                 self.rax.Reg64, self.rcx.Reg64, self.rdx.Reg64, self.rbx.Reg64,
                 self.rsp.Reg64, self.rbp.Reg64, self.rsi.Reg64, self.rdi.Reg64,
                 self.r8.Reg64, self.r9.Reg64, self.r10.Reg64, self.r11.Reg64,
                 self.r12.Reg64, self.r13.Reg64, self.r14.Reg64, self.r15.Reg64,
                 self.rip.Reg64,
                 self.rflags.Reg64,
            )
        }
    }
}

// #[repr(i32)]
// #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
// enum PagePermission {
//     NONE = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagNone,
//     READ = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagRead,
//     WRITE = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagWrite,
//     EXECUTE = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagExecute,
//     TRACK_DIRTY = WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagTrackDirtyPages,
// }


// #[repr(C, align(4096))]
// #[derive(Clone, Copy)]
// struct Page([u8; 4096]);


pub struct Allocator {
    pages: Vec<(usize, usize)>,
}

impl Allocator {
    pub fn new() -> Self {
        let allocator = Allocator {
            pages: Vec::new()
        };
        allocator
    }

    pub fn allocate_physical_memory(&mut self, size: usize) -> usize {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        let addr = ptr as usize;
        self.pages.push((addr, size));
        addr
    }
}

impl Drop for Allocator {
    fn drop(&mut self) {
        println!("destructing allocator");
        for &(addr, size) in &self.pages {
            let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
            let ptr = addr as *mut u8;
            unsafe { std::alloc::dealloc(ptr, layout) };
        }
    }
}

#[derive(Debug,PartialEq)]
pub struct MemoryRegion {
    pub base: usize,
    pub size: usize,
    pub addr: usize
}

#[derive(Debug)]
pub struct Emulator {
    partition: WHV_PARTITION_HANDLE,
    virtual_processors: Vec<u32>,
    pub mapped_regions: Vec<MemoryRegion>,
}

impl Emulator {
    pub fn new() -> Result<Self, EmulatorError> {
        let partition = create_partition()?;

        let mut emulator = Emulator {
            partition,
            virtual_processors: Vec::new(),
            mapped_regions: Vec::new(),
        };

        // FIXME in args
        let proc_count = 1u32;
        emulator.set_processor_count(proc_count)?;

        emulator.set_extended_vm_exits()?;

        // FIXME in args
        // let vmexit_bitmap: u64 = (1 << 1) | (1 << 14);
        let vmexit_bitmap: u64 = (1 << 1) | (1 << 3);
        emulator.set_exception_bitmap(vmexit_bitmap)?;

        emulator.setup_partition()?;

        emulator.create_processor()?;

        let handle = partition as usize;

        std::thread::spawn(move || kicker(handle));

        Ok(emulator)
    }

    fn set_processor_count(&mut self, proc_count: u32) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvSetPartitionProperty(self.partition,
            WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeProcessorCount,
            &proc_count as *const u32 as *const c_void,
            std::mem::size_of_val(&proc_count) as u32)
        };
        match hr {
            0 => return Ok(()),
            _ => {
                let msg = format!("WHvSetPartitionProperty failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    fn set_extended_vm_exits(&mut self) -> Result<(), EmulatorError> {
        let mut exits: WHV_EXTENDED_VM_EXITS = unsafe { std::mem::zeroed() };
        unsafe {
            exits.__bindgen_anon_1.set_ExceptionExit(1);
            // exits.__bindgen_anon_1.set_X64MsrExit(1);
            // exits.__bindgen_anon_1.set_X64CpuidExit(1);
        }
        let hr = unsafe { WHvSetPartitionProperty(self.partition,
            WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExtendedVmExits,
            &exits as *const WHV_EXTENDED_VM_EXITS as *const c_void,
            std::mem::size_of_val(&exits) as u32)
        };
        match hr {
            0 => return Ok(()),
            _ => {
                let msg = format!("WHvSetPartitionProperty failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    fn set_exception_bitmap(&mut self, bitmap: u64) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvSetPartitionProperty(self.partition,
            WHV_PARTITION_PROPERTY_CODE_WHvPartitionPropertyCodeExceptionExitBitmap,
            &bitmap as *const u64 as *const c_void,
            std::mem::size_of_val(&bitmap) as u32)
        };
        match hr {
            0 => return Ok(()),
            _ => {
                let msg = format!("WHvSetPartitionProperty failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    fn setup_partition(&mut self) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvSetupPartition(self.partition) };
        match hr {
            0 => return Ok(()),
            _ => {
                let msg = format!("WHvSetupPartition failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    fn create_processor(&mut self) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvCreateVirtualProcessor(self.partition, 0, 0) };
        match hr {
            0 => {
                self.virtual_processors.push(0);
                return Ok(())
            },
            _ => {
                let msg = format!("WHvCreateVirtualProcessor failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    // FIXME: overkill to get full context, need another way
    pub fn get_regs(&mut self) -> Result<(EmulatorContext), EmulatorError> {
        let mut context: EmulatorContext = unsafe { std::mem::zeroed() };

        let hr = unsafe { WHvGetVirtualProcessorRegisters(self.partition, 0,
            WHV_REGISTER_NAMES.as_ptr(), WHV_REGISTER_NAMES.len() as u32,
            &mut context as *mut EmulatorContext as *mut WHV_REGISTER_VALUE) };

        match hr {
            0 => {
                return Ok(context)
            },
            _ => {
                let msg = format!("WHvGetVirtualProcessorRegisters failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    pub fn set_regs(&mut self, context: &EmulatorContext) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvSetVirtualProcessorRegisters(self.partition, 0,
            WHV_REGISTER_NAMES.as_ptr(), WHV_REGISTER_NAMES.len() as u32,
            context as *const EmulatorContext as *const WHV_REGISTER_VALUE) };
 
        match hr {
            0 => {
                return Ok(())
            },
            _ => {
                let msg = format!("WHvSetVirtualProcessorRegisters failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    pub fn map_physical_memory(&mut self, addr: usize, buffer: usize, length: usize, perm: i32) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvMapGpaRange(self.partition,
            buffer as *mut c_void, addr as u64,
            length as u64, perm | WHV_MAP_GPA_RANGE_FLAGS_WHvMapGpaRangeFlagTrackDirtyPages)
        };
        match hr {
            0 => {
                let region = MemoryRegion {base: addr, size: length, addr: buffer};
                self.mapped_regions.push(region);
                return Ok(())
            },
            _ => {
                let msg = format!("WHvMapGpaRange failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    pub fn unmap_physical_memory(&mut self, addr: usize, size: usize) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvUnmapGpaRange(self.partition,
            addr as u64,
            size as u64)
        };
        match hr {
            0 => {
                self.mapped_regions.retain(|region| !(region.base <= addr && addr < region.base + region.size 
                        && region.base <= addr + size && addr + size <= region.base + region.size));
                return Ok(())
            },
            _ => {
                let msg = format!("WHvUnmapGpaRange failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    pub fn query_gpa_range(&mut self, addr: usize, size: usize) -> Result<u64, EmulatorError> {
        let mut bitmap: u64 = 0;
        let hr = unsafe { WHvQueryGpaRangeDirtyBitmap(self.partition,
            addr as u64,
            size as u64,
            &mut bitmap as *mut u64,
            std::mem::size_of_val(&bitmap) as u32)
        };
        match hr {
            0 => {
                return Ok(bitmap)
            },
            _ => {
                let msg = format!("WHvQueryGpaRangeDirtyBitmap failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    pub fn flush_gpa_range(&mut self, addr: usize, size: usize) -> Result<(), EmulatorError> {
        let hr = unsafe { WHvQueryGpaRangeDirtyBitmap(self.partition,
            addr as u64,
            size as u64,
            0 as *mut u64,
            0)
        };
        match hr {
            0 => {
                return Ok(())
            },
            _ => {
                let msg = format!("WHvQueryGpaRangeDirtyBitmap failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    pub fn read_physical_memory(&mut self, addr: usize, size: usize) -> Result<&[u8], EmulatorError> {
        // FIXME: handle crossing regions reads
        let region = self.get_region(addr, size);
        match region {
            Some(region) => {
                let offset = addr - region.base;
                let region_addr = region.addr + offset;
                let slice: &[u8] = unsafe {
                    from_raw_parts_mut(region_addr as *mut u8, size)
                };
                return Ok(slice)
            },
            None => {
                let msg = format!("can't find region");
                return Err(EmulatorError::new(msg))
            }
        }
    }

    pub fn write_physical_memory(&mut self, addr: usize, data: &[u8]) -> Result<usize, EmulatorError> {
        // FIXME: handle crossing regions writes
        let region = self.get_region(addr, data.len());
        match region {
            Some(region) => {
                let offset = addr - region.base;

                let slice: &mut [u8] = unsafe {
                    from_raw_parts_mut(region.addr as *mut u8, region.size)
                };
                let pos = 0usize;
                let remaining_region_size = region.size.saturating_sub(offset);

                let size = min(data.len() - pos, remaining_region_size);
                slice[offset..offset + size].copy_from_slice(&data[pos..pos + size]);
                return Ok(size)
            },
            None => {
                let msg = format!("can't find region");
                return Err(EmulatorError::new(msg))
            }
        }
    }

    pub fn is_physical_memory_valid(&mut self, addr: usize, size: usize) -> bool {
        let region = self.get_region(addr, size);
        match region {
            Some(_) => {
                return true
            },
            None => {
                return false
            }
        }
    }

    fn get_region(&mut self, addr: usize, size: usize) -> Option<&MemoryRegion> {
        let region = self.mapped_regions.iter().find(
            |region| region.base <= addr && addr < region.base + region.size 
                        && region.base <= addr + size && addr + size <= region.base + region.size
        );
        region
    }

    pub fn translate_virtual_address(&mut self, addr: usize) -> Result<u64, EmulatorError> {
        let flags = WHV_TRANSLATE_GVA_FLAGS_WHvTranslateGvaFlagValidateRead;
        let mut result: WHV_TRANSLATE_GVA_RESULT = unsafe { std::mem::zeroed() };
        let mut gpa: u64 = 0;
        let hr = unsafe { WHvTranslateGva(self.partition,
            0,
            addr as u64,
            flags,
            &mut result as *mut WHV_TRANSLATE_GVA_RESULT,
            &mut gpa as *mut u64)
        };
        match hr {
            0 => {
                match result.ResultCode {
                    WHV_TRANSLATE_GVA_RESULT_CODE_WHvTranslateGvaResultSuccess => return Ok(gpa),
                    _ => {
                        let msg = format!("WHvTranslateGva failed: code {:#x}", result.ResultCode);
                        return Err(EmulatorError::new(msg))
                    }
                }
            },
            _ => {
                let msg = format!("WHvTranslateGva failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }

    // pub fn read_virtual_memory(&mut self) -> Result<(), EmulatorError> {

    // }

    // pub fn write_virtual_memory(&mut self) -> Result<(), EmulatorError> {

    // }

    pub fn run(&mut self) -> Result<WHV_RUN_VP_EXIT_CONTEXT, EmulatorError> {
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = unsafe { std::mem::zeroed() };
        KICKER_ACTIVE.store(1, Ordering::SeqCst);
        let hr = unsafe { WHvRunVirtualProcessor(self.partition, 0,
            &mut exit_context as *mut WHV_RUN_VP_EXIT_CONTEXT as *mut c_void,
            std::mem::size_of_val(&exit_context) as u32) };
        KICKER_ACTIVE.store(0, Ordering::SeqCst);
        match hr {
            0 => {
                return Ok(exit_context)
            },
            _ => {
                let msg = format!("WHvRunVirtualProcessor failed with {:#x}", hr);
                return Err(EmulatorError::new(msg))
            }
        };
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        println!("destructing emulator");
        for &pid in &self.virtual_processors {
            let res = unsafe { WHvDeleteVirtualProcessor(self.partition, pid) };
            assert!(res == 0, "WHvDeleteVirtualProcessor() error: {:#x}", res);
        }

        let res = unsafe { WHvDeletePartition(self.partition) };
        assert!(res == 0, "WHvDeletePartition() error: {:#x}", res);
        // FIXME: unmap regions
    }
}

static KICKER_ACTIVE: AtomicUsize = AtomicUsize::new(0);

fn kicker(handle: usize) {
    let handle = handle as WHV_PARTITION_HANDLE;
    let delay = time::Duration::from_millis(10);

    loop {
        thread::sleep(delay);

        if KICKER_ACTIVE.load(Ordering::SeqCst) == 0 { continue; }

        unsafe { WHvCancelRunVirtualProcessor(handle, 0, 0); }
    }
}

pub fn get_capability() -> BOOL {
    let code = WHV_CAPABILITY_CODE_WHvCapabilityCodeHypervisorPresent;
    let mut capability = unsafe { zeroed::<WHV_CAPABILITY>() };
    let mut size = 0u32;
    let _hr = unsafe { WHvGetCapability(code, &mut capability as *mut WHV_CAPABILITY as *mut c_void, size_of::<WHV_CAPABILITY>() as u32, &mut size) };
    unsafe { capability.HypervisorPresent }
}

pub fn create_partition() -> Result<WHV_PARTITION_HANDLE, EmulatorError> {
    let mut partition: WHV_PARTITION_HANDLE = null_mut();
    let hr = unsafe { WHvCreatePartition(&mut partition) };
    match hr {
        0 => return Ok(partition),
        _ => {
            let msg = format!("WHvCreatePartition failed with {:#x}", hr);
            return Err(EmulatorError::new(msg))
        }
    };
}

fn set_dr7(mut dr7: u64, slot: u8) -> u64 {
    dr7 |= 1 << (slot * 2);

    let condition = 0; // HW_EXECUTE
    // set the condition (RW0 - RW3) field for the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
    dr7 |= condition << ((slot * 4) + 16);

    let length = 0;
    // set the length (LEN0-LEN3) field for the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
    dr7 |= length << ((slot * 4) + 18);
    dr7
}

fn clear_dr7(mut dr7: u64, slot: u8) -> u64 {
    dr7 &= !(1 << (slot * 2));
    // remove the condition (RW0 - RW3) field from the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
    dr7 &= !(3 << ((slot * 4) + 16));

    // remove the length (LEN0-LEN3) field from the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
    dr7 &= !(3 << ((slot * 4) + 18));
    dr7
}

pub fn set_hw_breakpoint(context: &mut EmulatorContext, address: u64) -> () {
    let slot = 0;
    context.dr0.Reg64 = address;
    let dr7 = unsafe { context.dr7.Reg64 };
    context.dr7.Reg64 = set_dr7(dr7, slot);
}
