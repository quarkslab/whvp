
use std::error::Error;
use std::fmt;
use std::mem;
use std::iter;

use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use fnv::FnvHasher;

pub type FastMap64<K, V> = HashMap<K, V, BuildHasherDefault<FnvHasher>>;

pub type Gva = u64;
pub type Gpa = u64;


const fn page_off(a: Gpa) -> (Gpa, usize) {
    (a & !0xfff, a as usize & 0xfff)
}

const fn pml4_index(gva: Gva) -> u64 {
    gva >> (12 + (9 * 3)) & 0x1ff
}

const fn pdpt_index(gva: Gva) -> u64 {
    gva >> (12 + (9 * 2)) & 0x1ff
}

const fn pd_index(gva: Gva) -> u64 {
    gva >> (12 + (9 * 1)) & 0x1ff
}

const fn pt_index(gva: Gva) -> u64 {
    gva >> (12 + (9 * 0)) & 0x1ff
}

const fn base_flags(gpa: Gpa) -> (Gpa, u64) {
    (gpa & !0xfff & 0x000f_ffff_ffff_ffff, gpa & 0x1ff)
}

const fn pte_flags(pte: Gva) -> (Gpa, u64) {
    (pte & !0xfff & 0x000f_ffff_ffff_ffff, pte & 0xfff)
}

const fn page_offset(gva: Gva) -> u64 {
    gva & 0xfff
}

pub struct GpaManager {
    pub pages: FastMap64<u64, [u8; 4096]>

}

impl GpaManager {

    pub fn new() -> Self {
        GpaManager {
            pages: FastMap64::default(),
        }
    }

    pub fn add_page(&mut self, gpa: Gpa, page: [u8; 4096]) {
        let (base, _) = page_off(gpa);
        self.pages.insert(base, page);
    }

    pub fn del_page(&mut self, gpa: Gpa) {
        let (base, _) = page_off(gpa);
        self.pages.remove(&base);
    }

    pub fn read_gpa_u64(&self, gpa: Gpa) -> Result<u64, VirtMemError> {
        let mut buf = [0; mem::size_of::<u64>()];
        self.read_gpa(gpa, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_gpa(&self, gpa: Gpa, buf: &mut [u8]) -> Result<(), VirtMemError> {
        if gpa + (buf.len() as Gpa) > (gpa & !0xfff) + 0x1000 {
            return Err(VirtMemError::SpanningPage);
        }

        let (base, off) = page_off(gpa);
        match self.pages.get(&base) {
            Some(arr) => {
                return Ok(buf.copy_from_slice(&arr[off..off + buf.len()]))
            },
            None => return Err(VirtMemError::MissingPage(base))
        }
    }

    pub fn write_gpa(&mut self, gpa: Gpa, data: &[u8]) -> Result<(), VirtMemError> {
        if gpa + (data.len() as Gpa) > (gpa & !0xfff) + 0x1000 {
            return Err(VirtMemError::SpanningPage);
        }

        let (base, off) = page_off(gpa);
        self.pages.entry(base).and_modify(|page| {
            let dst = &mut page[off..off + data.len()];
            dst.copy_from_slice(data);
        });

        Ok(())
    }

    pub fn read_gva_u64(&self, cr3: Gpa, gva: Gva) -> Result<u64, VirtMemError> {
        let mut buf = [0; mem::size_of::<u64>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_gva_u32(&self, cr3: Gpa, gva: Gva) -> Result<u32, VirtMemError> {
        let mut buf = [0; mem::size_of::<u32>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_gva_u16(&self, cr3: Gpa, gva: Gva) -> Result<u16, VirtMemError> {
        let mut buf = [0; mem::size_of::<u16>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    pub fn read_gva_u8(&self, cr3: Gpa, gva: Gva) -> Result<u8, VirtMemError> {
        let mut buf = [0; mem::size_of::<u8>()];
        self.read_gva(cr3, gva, &mut buf)?;
        Ok(u8::from_le_bytes(buf))
    }

    pub fn read_gva(&self, cr3: Gpa, gva: Gva, buf: &mut [u8]) -> Result<(), VirtMemError> {
        let mut off = 0;

        for (start, sz) in chunked(gva, buf.len()) {
            let gpa = self.translate_gva(cr3, start)?;
            self.read_gpa(gpa, &mut buf[off..off + sz])?;
            off += sz;
        }

        Ok(())
    }

    pub fn write_gva(&mut self, cr3: Gpa, gva: Gva, buf: &[u8]) -> Result<(), VirtMemError> {
        let mut off = 0;

        for (start, sz) in chunked(gva, buf.len()) {
            let gpa = self.translate_gva(cr3, start)?;
            self.write_gpa(gpa, &buf[off..off + sz])?;
            off += sz;
        }

        Ok(())
    }

    pub fn translate_gva(&self, cr3: Gpa, gva: Gva) -> Result<Gpa, VirtMemError> {
        let (pml4_base, _) = base_flags(cr3);

        let pml4e_addr = pml4_base + pml4_index(gva) * 8;
        let pml4e = self.read_gpa_u64(pml4e_addr)?;

        let (pdpt_base, pml4e_flags) = base_flags(pml4e);

        if pml4e_flags & 1 == 0 {
            return Err(VirtMemError::Pml4eNotPresent);
        }

        let pdpte_addr = pdpt_base + pdpt_index(gva) * 8;
        let pdpte = self.read_gpa_u64(pdpte_addr)?;

        let (pd_base, pdpte_flags) = base_flags(pdpte);

        if pdpte_flags & 1 == 0 {
            return Err(VirtMemError::PdpteNotPresent);
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1
        if pdpte_flags & 1 << 7 != 0 {
            return Ok((pdpte & 0xffff_ffff_c000_0000) + (gva & 0x3fff_ffff));
        }

        let pde_addr = pd_base + pd_index(gva) * 8;
        let pde = self.read_gpa_u64(pde_addr)?;

        let (pt_base, pde_flags) = base_flags(pde);

        if pde_flags & 1 == 0 {
            return Err(VirtMemError::PdeNotPresent);
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18
        if pde_flags & 1 << 7 != 0 {
            return Ok((pde & 0xffff_ffff_ffe0_0000) + (gva & 0x1f_ffff));
        }

        let pte_addr = pt_base + pt_index(gva) * 8;
        let pte = self.read_gpa_u64(pte_addr)?;

        let (pte_paddr, pte_flags) = pte_flags(pte);

        if pte_flags & 1 == 0 {
            return Err(VirtMemError::PteNotPresent);
        }

        Ok(pte_paddr + page_offset(gva))
    }



}

// pub struct SyncUnsafeCell<T>(pub UnsafeCell<T>);
// unsafe impl<T> Sync for SyncUnsafeCell<T> {}

// impl<T> SyncUnsafeCell<T> {
    // pub fn new(a: T) -> Self {
        // Self(UnsafeCell::new(a))
    // }
// }

// #[ctor]
// static FAULT: SyncUnsafeCell<Box<dyn FnMut(PhyAddress)>> =
    // { SyncUnsafeCell::new(Box::new(|_| panic!("no missing_page function set"))) };

// pub type FastMap64<K, V> = HashMap<K, V, BuildHasherDefault<FnvHasher>>;

// #[ctor]
// pub static MEM: SyncUnsafeCell<FastMap64<PhyAddress, *mut u8>> =
//     { SyncUnsafeCell::new(FastMap64::default()) };

// unsafe fn mem() -> &'static mut FastMap64<PhyAddress, *mut u8> {
//     &mut (*(MEM.0.get()))
// }

// pub unsafe fn missing_page<T: FnMut(PhyAddress) + 'static>(f: T) {
//     *(FAULT.0.get()) = Box::new(f);
// }

// pub unsafe fn fault(gpa: PhyAddress) {
//     let f = FAULT.0.get();
//     (**f)(gpa);
// }

// pub unsafe fn resolve_hva(gpa: PhyAddress) -> *mut u8 {
//     let (page, off) = page_off(gpa);
//     (*(mem().get(&page).unwrap())).add(off)
// }

// pub unsafe fn resolve_hva_checked(gpa: PhyAddress) -> Option<*mut u8> {
//     let (page, off) = page_off(gpa);

//     match mem().get(&page) {
//         Some(p) => Some(p.add(off)),
//         None => None,
//     }
// }


#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum VirtMemError {
    Pml4eNotPresent,
    PdpteNotPresent,
    PdeNotPresent,
    PteNotPresent,
    SpanningPage,
    MissingPage(u64)
}

impl fmt::Display for VirtMemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for VirtMemError {
    fn description(&self) -> &str {
        "virtual to physical translation error"
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

fn chunked(start: Gva, sz: usize) -> impl Iterator<Item = (Gva, usize)> {
    debug_assert!(start.checked_add(sz as u64).is_some());

    let mut remaining = sz;
    let mut base = start;

    iter::from_fn(move || {
        if remaining == 0 {
            None
        } else {
            let chunk_base = base;

            let chunk_sz = if base as usize + remaining > (base as usize & !0xfff) + 0x1000 {
                ((base & !0xfff) + 0x1000 - base) as usize
            } else {
                remaining
            };

            base += chunk_sz as Gva;
            remaining -= chunk_sz;

            Some((chunk_base, chunk_sz))
        }
    })
}

