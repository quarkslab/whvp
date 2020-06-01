
use std::str::FromStr;
use std::collections::BTreeSet;
use std::collections::HashMap;

use std::io::{BufWriter, Write};

use std::time::{Instant, Duration};

use std::convert::TryInto;

use anyhow::{Result, Context as AnyContext};

use serde::{Serialize, Deserialize};
use serde_json;

use crate::whvp;
use crate::mem::{self, X64VirtualAddressSpace};

use crate::snapshot::Snapshot;


#[derive(Serialize, Deserialize, CustomDebug, Default)]
pub struct Segment {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub flags: u16
}

#[derive(Serialize, Deserialize, CustomDebug, Default)]
pub struct ProcessorState {
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
    pub rip: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub gdtr: u64,
    pub gdtl: u16,
    pub idtr: u64,
    pub idtl: u16,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub es: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64
}


#[derive(Debug, PartialEq, PartialOrd)]
pub enum CoverageMode {
    None,
    Instrs,
    Hit,
}

impl Default for CoverageMode {
    fn default() -> Self {
        CoverageMode::None
    }
}

impl FromStr for CoverageMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<CoverageMode> {
        let coverage_mode = match s {
            "no" => CoverageMode::None,
            "instrs" => CoverageMode::Instrs,
            "hit" => CoverageMode::Hit,
            _ => {
                return Err(anyhow!(
                    "invalid coverage mode",
                ))
            }
        };
        Ok(coverage_mode)
    }
}


#[derive(Default, Serialize, Deserialize, CustomDebug)]
pub struct Params {
    #[serde(skip)]
    pub limit: u64,
    pub max_duration: Duration,
    pub return_address: u64,
    pub excluded_addresses: HashMap<String, u64>,
    #[serde(skip)]
    pub save_context: bool,
    #[serde(skip)]
    pub coverage_mode: CoverageMode,
    #[serde(skip)]
    pub save_instructions: bool,
}

impl FromStr for ProcessorState {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<ProcessorState> {
        let context = serde_json::from_str(s)?;
        Ok(context)
    }
}

// FIXME: from string?
// pub fn parse_context(content: &str) -> Result<InitialContext> {
// }

pub fn parse_params(content: &str) -> Result<Params> {
    let context = serde_json::from_str(content)?;
    Ok(context)
}

#[derive(Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EmulationStatus {
    Success,
    Error,
    ForbiddenAddress,
    Timeout,
    LimitExceeded,
    UnHandledException,
}

impl std::fmt::Display for EmulationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EmulationStatus::Success => write!(f, "Success"),
            EmulationStatus::Error => write!(f, "Error"),
            EmulationStatus::ForbiddenAddress => write!(f, "ForbiddenAddress"),
            EmulationStatus::Timeout => write!(f, "Timeout"),
            EmulationStatus::LimitExceeded => write!(f, "LimitExceeded"),
            EmulationStatus::UnHandledException => write!(f, "UnhandledException"),
        }
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
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
    pub rip: u64,
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct Trace {
    #[serde(skip)]
    pub start: Option<Instant>,
    #[serde(skip)]
    pub end: Option<Instant>,
    pub coverage: Vec<(u64, Option<Context>)>,
    pub instrs: Vec<String>,
    pub status: EmulationStatus,
    pub seen: BTreeSet<u64>,
    pub mem_access: Vec<(u64, u64, usize, String)>
}

impl Trace {

    pub fn new() -> Self {
        Trace {
            start: None,
            end: None,
            coverage: Vec::new(),
            instrs: Vec::new(),
            seen: BTreeSet::new(),
            status: EmulationStatus::Success,
            mem_access: Vec::new()
        }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let mut fp = BufWriter::new(std::fs::File::create(path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }
}


pub trait Tracer {

    fn set_initial_context(&mut self, context: &ProcessorState) -> Result<()>;

    fn run(&mut self, params: &Params) -> Result<Trace>;

    fn restore_snapshot(&mut self) -> Result<usize>;

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<()>;

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<()>;

    fn cr3(&mut self) -> Result<u64>;

    fn get_code_pages(&mut self) -> usize;
    fn get_data_pages(&mut self) -> usize;

}

impl From<whvp::PartitionContext> for Context {

    fn from(context: whvp::PartitionContext) -> Self {
        Context {
            rax: unsafe { context.rax.Reg64 },
            rbx: unsafe { context.rbx.Reg64 },
            rcx: unsafe { context.rcx.Reg64 },
            rdx: unsafe { context.rdx.Reg64 },
            rsi: unsafe { context.rsi.Reg64 },
            rdi: unsafe { context.rdi.Reg64 },
            rsp: unsafe { context.rsp.Reg64 },
            rbp: unsafe { context.rbp.Reg64 },
            r8: unsafe { context.r8.Reg64 },
            r9: unsafe { context.r9.Reg64 },
            r10: unsafe { context.r10.Reg64 },
            r11: unsafe { context.r11.Reg64 },
            r12: unsafe { context.r12.Reg64 },
            r13: unsafe { context.r13.Reg64 },
            r14: unsafe { context.r14.Reg64 },
            r15: unsafe { context.r15.Reg64 },
            rflags: unsafe { context.rflags.Reg64 },
            rip: unsafe { context.rip.Reg64 },
        }
    }
}

pub struct WhvpTracer <S: Snapshot> {
    cache: mem::GpaManager,
    allocator: mem::Allocator,
    partition: whvp::Partition,
    snapshot: S,
    code: usize,
    data: usize,
}

impl <S: Snapshot + mem::X64VirtualAddressSpace> WhvpTracer <S>{

    pub fn new(snapshot: S) -> Result<Self> {
        let allocator = mem::Allocator::new();
        let cache = mem::GpaManager::new();
        let partition = whvp::Partition::new()?;

        let tracer = WhvpTracer {
            cache: cache,
            allocator: allocator,
            partition: partition,
            snapshot: snapshot,
            code: 0,
            data: 0,
        };

        Ok(tracer)
    }

    fn handle_memory_access(&mut self, params: &Params, memory_access_context: &whvp::MemoryAccessContext, trace: &mut Trace) -> Result<bool> {
        let partition = &mut self.partition;
        let allocator = &mut self.allocator;
        let cache = &mut self.cache;
        let snapshot = &self.snapshot;

        let gpa = memory_access_context.Gpa;
        let gva = memory_access_context.Gva;

        let base: usize = (gpa & !0xfff).try_into()?;
        let mut data: [u8; 4096] = [0; 4096];
        
        match Snapshot::read_gpa(snapshot, gpa, &mut data) {
            Ok(_) => {
                cache.add_page(base as u64, data);
            },
            Err(e) => {
                warn!("can't read gpa {:x} from snapshot ({})", gpa, e);
                trace.status = EmulationStatus::Error;
                return Ok(true);
            }
        }
        
        let access_type = memory_access_context.AccessInfo.AccessType;

        match access_type {
            whvp::MemoryAccessType::Execute => {
                self.code += 1;
            },
            _ => {
                self.data += 1;
            }
        }

        if params.coverage_mode == CoverageMode::Hit && access_type == whvp::MemoryAccessType::Execute {
            data.copy_from_slice(&[0xcc; 4096]);
        } 
        else {
            let gva_base = params.return_address & !0xfff;
            let offset: usize = (params.return_address & 0xfff).try_into()?;
            if gva_base <= gva && gva < gva_base + 0x1000 {
                info!("setting bp on return address {:x}", gva);
                data[offset] = 0xcc;
            }

            for (name, &addr) in params.excluded_addresses.iter() {
                let gva_base = addr & !0xfff;
                let offset: usize = (addr & 0xfff).try_into()?;
                if gva_base <= gva && gva < gva_base + 0x1000 {
                    info!("setting bp on excluded address {} ({:x})", name, addr);
                    data[offset] = 0xcc;
                }
            }
        }

        let pages: usize = allocator.allocate_physical_memory(0x1000);
        let permissions = whvp::MapGpaRangeFlags::Read
                    | whvp::MapGpaRangeFlags::Write
                    | whvp::MapGpaRangeFlags::Execute;

        partition.map_physical_memory(base, pages, 0x1000, permissions.bits())?;
        partition.write_physical_memory(base, &data)?;
        Ok(false)

    }

    fn handle_exception(&mut self, params: &Params, vp_context: &whvp::VpContext, exception_context: &whvp::ExceptionContext, trace: &mut Trace) -> Result<bool> {
        let partition = &mut self.partition;

        if vp_context.ExecutionState.InterruptShadow {
            let mut interrupt_context = partition.get_regs()?;
            unsafe {
                interrupt_context
                    .interrupt_state
                    .InterruptState
                    .__bindgen_anon_1
                    .set_InterruptShadow(0)
            };
            partition.set_regs(&interrupt_context)?;
        }

        let rip = vp_context.Rip;

        if rip as u64 == params.return_address {
            return Ok(true);
        }

        for (_k, &v) in params.excluded_addresses.iter() {
            if v == rip {
                trace.status = EmulationStatus::ForbiddenAddress;
                return Ok(true);
            }
        }

        let exception_type: whvp::ExceptionType = exception_context.ExceptionType.into();
        match exception_type {
            whvp::ExceptionType::DebugTrapOrFault | whvp::ExceptionType::BreakpointTrap => {
                trace.seen.insert(rip);
                if params.save_context {
                    let context = partition.get_regs()?.into();
                    trace.coverage.push((rip, Some(context)));
                } else {
                    trace.coverage.push((rip, None));
                }
            },
            _ => {
                trace.status = EmulationStatus::UnHandledException;
                return Ok(true)
            }
        }

        if exception_type == whvp::ExceptionType::BreakpointTrap {
            let offset = (rip & 0xfff) as usize;
            let remain = (0x1000 - offset) as usize;
            let size = std::cmp::min(0x10, remain);
            let mut buffer = vec![0u8; size];
            let cr3 = self.cr3()?;
            match self.cache.read_gva(cr3, rip as u64, &mut buffer) {
                Ok(()) => {},
                _ => {
                    warn!("can't read snapshot for {:x}", rip);
                    trace.status = EmulationStatus::Error;
                    return Ok(true)
                }
            }
            
            let instruction = self.decode_instruction(&buffer)?;
            let length = instruction.length as usize;
            self.write_gva(cr3, rip, &buffer[..length])?;
        }

        if params.save_instructions {
            let buffer = exception_context.InstructionBytes;
            let instruction = self.decode_instruction(&buffer)?;
            let output = self.format_instruction(rip, instruction)?;
            trace.instrs.push(output);
        }

        Ok(false)
    }

    fn decode_instruction(&mut self, buffer: &[u8]) -> Result<zydis::DecodedInstruction> {
        let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?;
        let result = decoder.decode(&buffer)?;
        if let Some(instruction) = result {
            Ok(instruction)
        } else {
            Err(anyhow!("can't decode instruction"))
        }
    }

    fn format_instruction(&mut self, rip: u64, instruction: zydis::DecodedInstruction) -> Result<String> {
        let formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL)?;
        let mut buffer = [0u8; 200];
        let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
        formatter.format_instruction(&instruction, &mut buffer, Some(rip as u64), None)?;
        let output = format!("0x{:016X}: {}", rip, buffer);
        Ok(output)
    }

}


impl <S: Snapshot + mem::X64VirtualAddressSpace> Tracer for WhvpTracer <S> {

    fn set_initial_context(&mut self, context: &ProcessorState) -> Result<()> {
        let partition = &mut self.partition;
        let mut regs = partition.get_regs()?;

        regs.rax.Reg64 = context.rax;
        regs.rbx.Reg64 = context.rbx;
        regs.rcx.Reg64 = context.rcx;
        regs.rdx.Reg64 = context.rdx;
        regs.rsi.Reg64 = context.rsi;
        regs.rdi.Reg64 = context.rdi;
        regs.rsp.Reg64 = context.rsp;
        regs.rbp.Reg64 = context.rbp;
        regs.r8.Reg64 = context.r8;
        regs.r9.Reg64 = context.r9;
        regs.r10.Reg64 = context.r10;
        regs.r11.Reg64 = context.r11;
        regs.r12.Reg64 = context.r12;
        regs.r13.Reg64 = context.r13;
        regs.r14.Reg64 = context.r14;
        regs.r15.Reg64 = context.r15;
        regs.rflags.Reg64 = context.rflags;
        regs.rip.Reg64 = context.rip;
        regs.cr0.Reg64 = context.cr0;
        regs.cr3.Reg64 = context.cr3;
        regs.cr4.Reg64 = context.cr4;
        regs.cr8.Reg64 = context.cr8;
        regs.efer.Reg64 = context.efer;

        regs.star.Reg64 = context.star;
        regs.lstar.Reg64 = context.lstar;
        regs.cstar.Reg64 = context.cstar;

        regs.kernel_gs_base.Reg64 = context.kernel_gs_base;

        regs.gdtr.Table.Base = context.gdtr;
        regs.gdtr.Table.Limit = context.gdtl;

        regs.idtr.Table.Base = context.idtr;
        regs.idtr.Table.Limit = context.idtl;

        // FIXME: forward long mode and privilege level (read from attr?)
        regs.cs.Segment.Base = 0;
        regs.cs.Segment.Limit = 0;
        unsafe {
            regs.cs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(1);
            regs.cs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.cs.Segment.Selector = context.cs.selector;

        regs.ss.Segment.Base = 0;
        regs.ss.Segment.Limit = 0;
        unsafe {
            regs.ss
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.ss
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.ss.Segment.Selector = context.ss.selector;

        regs.ds.Segment.Base = 0;
        regs.ds.Segment.Limit = 0;
        unsafe {
            regs.ds
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.ds
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.ds.Segment.Selector = context.ds.selector;

        regs.es.Segment.Base = 0;
        regs.es.Segment.Limit = 0;
        unsafe {
            regs.es
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.es
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.es.Segment.Selector = context.es.selector;

        regs.fs.Segment.Base = context.fs_base;
        regs.fs.Segment.Limit = 0;
        unsafe {
            regs.fs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.fs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.fs.Segment.Selector = context.fs.selector;

        regs.gs.Segment.Base = context.gs_base;
        regs.gs.Segment.Limit = 0;
        unsafe {
            regs.gs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_Long(0);
            regs.gs
                .Segment
                .__bindgen_anon_1
                .__bindgen_anon_1
                .set_DescriptorPrivilegeLevel(0);
        }
        regs.gs.Segment.Selector = context.gs.selector;

        partition.set_regs(&regs)?;
        Ok(())
    }

    fn run(&mut self, params: &Params) -> Result<Trace> {
        let mut exits = 0;
        let mut cancel = 0;

        let mut trace = Trace::new();

        let mut regs = self.partition.get_regs()?;
        let rip = unsafe { regs.rip.Reg64 };
        let cr3 = unsafe { regs.cr3.Reg64 };

        if params.coverage_mode == CoverageMode::Instrs {
            let rflags = unsafe { regs.rflags.Reg64 };
            regs.rflags.Reg64 = rflags | 0x100;
            self.partition.set_regs(&regs)?;
        }

        if params.coverage_mode != CoverageMode::Hit {
            trace.seen.insert(rip);
            if params.save_context {
                let context = regs.into();
                trace.coverage.push((rip, Some(context)));
            } else {
                trace.coverage.push((rip, None));
            }
        }

        if params.save_instructions {
            let mut buffer = [0u8; 16];

            match self.cache.read_gva(cr3, rip as u64, &mut buffer) {
                Ok(()) => {
                    let instruction = self.decode_instruction(&buffer)?;
                    let output = self.format_instruction(rip, instruction)?;
                    trace.instrs.push(output);
                }
                _ => {
                    match self.snapshot.read_gva(cr3, rip as u64, &mut buffer) {
                        Ok(()) => {
                            let instruction = self.decode_instruction(&buffer)?;
                            let output = self.format_instruction(rip, instruction)?;
                            trace.instrs.push(output);
                        },
                        _ => {
                            trace.instrs.push(format!("0x{:016X}: ???", rip));
                        }
                    }
                }
            }
        }

        trace.start = Some(Instant::now());

        while params.limit == 0 || exits < params.limit {
            let exit = self.partition.run()?;
            exits += 1;
            if params.max_duration != Duration::default() && trace.start.unwrap().elapsed() > params.max_duration {
                trace.status = EmulationStatus::Timeout;
                break;
            }
            let exit_context: whvp::ExitContext = exit.into();
            match exit_context {
                whvp::ExitContext::MemoryAccess(_vp_context, memory_access_context) => {
                    cancel = 0;
                    if self.handle_memory_access(&params, &memory_access_context, &mut trace)? {
                        break;
                    }
                }
                whvp::ExitContext::Exception(vp_context, exception_context) => {
                    cancel = 0;
                    if self.handle_exception(&params, &vp_context, &exception_context, &mut trace)? {
                        break;
                    }
                }
                whvp::ExitContext::Canceled(_, _) => {
                    cancel += 1;
                    if cancel > 10 {
                        error!("stopping, seems stucked");
                        trace.status = EmulationStatus::Timeout;
                        break;
                    }
                }
                _ => {
                    error!("unhandled vm exit: {:?}", exit_context);
                    trace.status = EmulationStatus::Error;
                    break;
                }
            }
        }
        trace.end = Some(Instant::now());
        Ok(trace)
    }

    fn restore_snapshot(&mut self) -> Result<usize> {
        // let start = Instant::now();
        let mut pages: usize = 0;
        let partition = &mut self.partition;
        let regions = &mut partition.mapped_regions;
        let addresses = regions.iter().map(|region| region.base).collect::<Vec<_>>();
        // FIXME: compute range ?
        // addresses.sort();
        for addr in addresses.iter() {
            let bitmap = partition.query_gpa_range(*addr, 0x1000)?;
            if bitmap == 1 {
                if let Some(arr) = self.cache.pages.get(&(*addr as u64)) {
                    match partition.write_physical_memory(*addr, arr) {
                        Ok(_) => {
                            partition.flush_gpa_range(*addr, 0x1000)?;
                            pages += 1;
                        }
                        _ => {
                            return Err(anyhow!("can't restore data"))
                        }
                    }
                }
            }
        }
        // info!("restored {} pages from snapshot in {:?}", pages, start.elapsed());
        Ok(pages)
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<()> {
        self.partition.read_gva(cr3, vaddr, data).context("can't read gva")
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<()> {
        self.partition.write_gva(cr3, vaddr, data).context("can't write gva")
    }

    fn cr3(&mut self) -> Result<u64> {
        let context = self.partition.get_regs()?;
        let cr3 = unsafe { context.cr3.Reg64 };
        Ok(cr3)
    }

    // FIXME: move this in gpa manager
    fn get_code_pages(&mut self) -> usize {
        self.code
    }

    fn get_data_pages(&mut self) -> usize {
        self.data
    }

}

 