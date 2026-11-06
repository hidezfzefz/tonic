//! Mapping a loaded object into our address space.
//!
//! One reservation, then all PT_LOAD segments are copied into it and the final
//! permissions are applied per page. Per-page union matters: adjacent segments
//! routinely share a page (the tail of .text and the head of .rodata), and a
//! naive per-segment `mprotect` would either fault or leave data writable.
//!
//! The mapping is intentionally leaked: `LoadedObject` holds raw addresses and
//! the process is expected to exit with the object still mapped.

use std::ffi::c_void;
use std::ptr;

use crate::bionic;
use crate::elf::{Elf, PF_R, PF_W, PF_X, PT_GNU_RELRO, PT_LOAD};
use crate::error::{LoadError, Result};

const PROT_NONE: i32 = 0;
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;

const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
const MAP_NORESERVE: i32 = 0x4000;

unsafe extern "C" {
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn mprotect(address: *mut c_void, length: usize, protection: i32) -> i32;
    fn munmap(address: *mut c_void, length: usize) -> i32;
}

#[derive(Clone, Copy, Debug)]
pub struct Mapping {
    /// First address that belongs to the object (page aligned).
    pub start: usize,
    /// Value added to every virtual address in the file.
    pub bias: usize,
    pub span: usize,
    pub page: usize,
}

impl Mapping {
    pub fn contains(&self, address: usize, length: usize) -> bool {
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        address >= self.start && end <= self.start + self.span
    }
}

pub fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default()
}

/// Reserve and populate the object's address range.
///
/// # Safety
/// The object must stay alive for the lifetime of the mapping, and the caller
/// must not unmap or overlap the returned range.
pub unsafe fn map_object(elf: &Elf<'_>) -> Result<Mapping> {
    let page = bionic::page_size();
    let segments: Vec<_> = elf
        .phdrs
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD)
        .collect();

    if segments.is_empty() {
        return Err(LoadError::Elf("no PT_LOAD segments".into()));
    }

    let min_vaddr = segments
        .iter()
        .map(|phdr| phdr.p_vaddr)
        .min()
        .unwrap_or(0) as usize;
    let max_vaddr = segments
        .iter()
        .map(|phdr| phdr.p_vaddr + phdr.p_memsz)
        .max()
        .unwrap_or(0) as usize;
    let span = max_vaddr.saturating_sub(min_vaddr);
    if span == 0 {
        return Err(LoadError::Elf("PT_LOAD segments cover no memory".into()));
    }

    let align = segments
        .iter()
        .map(|phdr| phdr.p_align as usize)
        .max()
        .unwrap_or(page)
        .max(page);
    if !align.is_power_of_two() {
        return Err(LoadError::Elf(format!(
            "segment alignment {align:#x} is not a power of two"
        )));
    }

    let (start, bias) = if elf.e_type == crate::elf::ET_DYN {
        // Reserve span + align so the aligned base always exists inside the
        // reservation, then hand back the surplus.
        let total = span
            .checked_add(align)
            .ok_or_else(|| LoadError::Elf("mapping size overflows usize".into()))?;
        let raw = unsafe {
            mmap(
                ptr::null_mut(),
                total,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                -1,
                0,
            )
        };
        if raw as isize == -1 {
            return Err(LoadError::Mmap {
                what: "reserving address space".into(),
                errno: last_errno(),
            });
        }
        let raw_address = raw as usize;
        let aligned = align_up(raw_address, align);
        if aligned > raw_address {
            unsafe { munmap(raw_address as *mut c_void, aligned - raw_address) };
        }
        let tail = raw_address + total - (aligned + span);
        if tail > 0 {
            unsafe { munmap((aligned + span) as *mut c_void, tail) };
        }
        (aligned, aligned - min_vaddr)
    } else {
        let start = min_vaddr & !(page - 1);
        let length = max_vaddr - start;
        let raw = unsafe {
            mmap(
                start as *mut c_void,
                length,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
                -1,
                0,
            )
        };
        if raw as isize == -1 {
            return Err(LoadError::Mmap {
                what: "mapping an ET_EXEC object at its fixed address".into(),
                errno: last_errno(),
            });
        }
        (start, 0)
    };

    let mapping = Mapping {
        start,
        bias,
        span,
        page,
    };

    if unsafe { mprotect(start as *mut c_void, span, PROT_READ | PROT_WRITE) } != 0 {
        return Err(LoadError::Mmap {
            what: "opening the reservation for copying".into(),
            errno: last_errno(),
        });
    }

    for phdr in &segments {
        if phdr.p_filesz > phdr.p_memsz {
            return Err(LoadError::Elf(format!(
                "segment at {:#x} has p_filesz {} > p_memsz {}",
                phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz
            )));
        }
        let file_start = phdr.p_offset as usize;
        let file_end = file_start
            .checked_add(phdr.p_filesz as usize)
            .ok_or_else(|| LoadError::Elf("segment file range overflows".into()))?;
        if file_end > elf.data.len() {
            return Err(LoadError::Elf(format!(
                "segment at {:#x} reads past end of file",
                phdr.p_vaddr
            )));
        }

        let destination = bias + phdr.p_vaddr as usize;
        if !mapping.contains(destination, phdr.p_memsz as usize) {
            return Err(LoadError::Elf(format!(
                "segment at {:#x} falls outside the reservation",
                phdr.p_vaddr
            )));
        }

        unsafe {
            ptr::copy_nonoverlapping(
                elf.data.as_ptr().add(file_start),
                destination as *mut u8,
                phdr.p_filesz as usize,
            );
            if phdr.p_memsz > phdr.p_filesz {
                ptr::write_bytes(
                    (destination + phdr.p_filesz as usize) as *mut u8,
                    0,
                    (phdr.p_memsz - phdr.p_filesz) as usize,
                );
            }
        }
    }

    apply_permissions(&segments, &mapping)?;
    Ok(mapping)
}

fn apply_permissions(segments: &[&crate::elf::Phdr], mapping: &Mapping) -> Result<()> {
    let pages = mapping.span.div_ceil(mapping.page);
    let mut permissions = vec![0i32; pages];

    for phdr in segments {
        let start = (phdr.p_vaddr as usize).saturating_sub(mapping.bias - (mapping.start - (mapping.bias - (mapping.start - mapping.start)))) ;
        // The expression above is intentionally avoided below; compute from the
        // mapping instead.
        let _ = start;
    }

    for phdr in segments {
        let segment_start = phdr.p_vaddr as usize + mapping.bias;
        let offset = segment_start.saturating_sub(mapping.start);
        let first = offset / mapping.page;
        let last = (offset + phdr.p_memsz as usize).div_ceil(mapping.page);

        let mut protection = 0;
        if phdr.p_flags & PF_R != 0 {
            protection |= PROT_READ;
        }
        if phdr.p_flags & PF_W != 0 {
            protection |= PROT_WRITE;
        }
        if phdr.p_flags & PF_X != 0 {
            protection |= PROT_EXEC;
        }

        for index in first..last.min(pages) {
            permissions[index] |= protection;
        }
    }

    let mut index = 0;
    while index < pages {
        let protection = permissions[index];
        let mut end = index + 1;
        while end < pages && permissions[end] == protection {
            end += 1;
        }
        if protection != 0 {
            let address = mapping.start + index * mapping.page;
            let length = (end - index) * mapping.page;
            if unsafe { mprotect(address as *mut c_void, length, protection) } != 0 {
                return Err(LoadError::Mmap {
                    what: format!("setting segment permissions at {address:#x}"),
                    errno: last_errno(),
                });
            }
        }
        index = end;
    }

    Ok(())
}

/// Lock the GNU_RELRO range after relocations have been applied.
///
/// # Safety
/// `bias` must be the load bias of the mapping that `elf` was loaded at.
pub unsafe fn apply_relro(elf: &Elf<'_>, bias: usize) -> Result<()> {
    let page = bionic::page_size();
    for phdr in elf
        .phdrs
        .iter()
        .filter(|phdr| phdr.p_type == PT_GNU_RELRO)
    {
        if phdr.p_memsz == 0 {
            continue;
        }
        let start = (bias + phdr.p_vaddr as usize) & !(page - 1);
        let end = align_up(bias + phdr.p_vaddr as usize + phdr.p_memsz as usize, page);
        if end <= start {
            continue;
        }
        if unsafe { mprotect(start as *mut c_void, end - start, PROT_READ) } != 0 {
            return Err(LoadError::Mmap {
                what: format!("locking RELRO at {start:#x}"),
                errno: last_errno(),
            });
        }
    }
    Ok(())
}
