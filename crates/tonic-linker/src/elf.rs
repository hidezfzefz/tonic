//! Minimal ELF64 little-endian parser.
//!
//! Deliberately narrow: it understands exactly the structures a dynamic
//! x86-64 object needs in order to be mapped and relocated, and rejects
//! anything else with a message that names the field at fault. Section headers
//! are not parsed; the dynamic segment is the only metadata source.

use crate::error::{LoadError, Result};

pub const EM_X86_64: u16 = 62;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_PLTREL: i64 = 20;
pub const DT_JMPREL: i64 = 23;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_GNU_HASH: i64 = 0x6ffffef5;
pub const DT_FLAGS_1: i64 = 0x6ffffffb;

pub const DT_PLTREL_RELA: u64 = 7;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const SYM_SIZE: u64 = 24;
const RELA_SIZE: u64 = 24;

#[derive(Clone, Copy, Debug)]
pub struct Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Debug, Default)]
pub struct DynInfo {
    pub needed_offsets: Vec<u64>,
    pub soname_offset: Option<u64>,
    pub strtab: u64,
    pub strsz: u64,
    pub symtab: u64,
    pub syment: u64,
    pub hash: Option<u64>,
    pub gnu_hash: Option<u64>,
    pub rela: Option<u64>,
    pub relasz: u64,
    pub relaent: u64,
    pub jmprel: Option<u64>,
    pub pltrelsz: u64,
    pub pltrel: u64,
    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Option<u64>,
    pub init_arraysz: u64,
    pub fini_array: Option<u64>,
    pub fini_arraysz: u64,
    pub flags_1: u64,
}

pub struct Elf<'a> {
    pub data: &'a [u8],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_entry: u64,
    pub phdrs: Vec<Phdr>,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < EHDR_SIZE {
            return Err(LoadError::Elf(format!(
                "file is {} bytes, shorter than an ELF64 header ({EHDR_SIZE})",
                data.len()
            )));
        }
        if &data[0..4] != b"\x7fELF" {
            return Err(LoadError::Elf("bad magic (not \\x7fELF)".into()));
        }
        if data[4] != 2 {
            return Err(LoadError::Elf(format!(
                "ELF class {} found; only 64-bit objects are supported",
                data[4]
            )));
        }
        if data[5] != 1 {
            return Err(LoadError::Elf(format!(
                "ELF data encoding {} found; only little-endian is supported",
                data[5]
            )));
        }
        if data[6] != 1 {
            return Err(LoadError::Elf(format!(
                "ELF version {} found; expected 1",
                data[6]
            )));
        }

        let e_type = read_u16(data, 16)?;
        let e_machine = read_u16(data, 18)?;
        let e_version = read_u32(data, 20)?;
        if e_version != 1 {
            return Err(LoadError::Elf(format!("e_version {e_version}, expected 1")));
        }
        if e_machine != EM_X86_64 {
            return Err(LoadError::Elf(format!(
                "machine {e_machine} is not x86-64 ({EM_X86_64}); use the Android x86_64 split, not an arm64 one"
            )));
        }
        if e_type != ET_DYN && e_type != ET_EXEC {
            return Err(LoadError::Elf(format!(
                "e_type {e_type}; only ET_DYN (3) and ET_EXEC (2) are loadable"
            )));
        }

        let e_entry = read_u64(data, 24)?;
        let e_phoff = read_u64(data, 32)?;
        let e_phentsize = read_u16(data, 54)?;
        let e_phnum = read_u16(data, 56)?;

        if e_phnum == 0 {
            return Err(LoadError::Elf("no program headers".into()));
        }
        if e_phentsize as usize != PHDR_SIZE {
            return Err(LoadError::Elf(format!(
                "e_phentsize {e_phentsize}, expected {PHDR_SIZE}"
            )));
        }

        let table_len = (e_phnum as u64)
            .checked_mul(PHDR_SIZE as u64)
            .ok_or_else(|| LoadError::Elf("program header count overflows".into()))?;
        need(data, e_phoff as usize, table_len as usize)?;

        let mut phdrs = Vec::with_capacity(e_phnum as usize);
        for index in 0..e_phnum as usize {
            let offset = e_phoff as usize + index * PHDR_SIZE;
            phdrs.push(Phdr {
                p_type: read_u32(data, offset)?,
                p_flags: read_u32(data, offset + 4)?,
                p_offset: read_u64(data, offset + 8)?,
                p_vaddr: read_u64(data, offset + 16)?,
                p_filesz: read_u64(data, offset + 32)?,
                p_memsz: read_u64(data, offset + 40)?,
                p_align: read_u64(data, offset + 48)?,
            });
        }

        Ok(Elf {
            data,
            e_type,
            e_machine,
            e_entry,
            phdrs,
        })
    }

    pub fn dynamic(&self) -> Result<Option<DynInfo>> {
        let Some(phdr) = self
            .phdrs
            .iter()
            .find(|phdr| phdr.p_type == PT_DYNAMIC)
        else {
            return Ok(None);
        };

        if phdr.p_filesz % 16 != 0 {
            return Err(LoadError::Elf(format!(
                "PT_DYNAMIC size {} is not a multiple of 16",
                phdr.p_filesz
            )));
        }
        need(self.data, phdr.p_offset as usize, phdr.p_filesz as usize)?;

        let mut info = DynInfo {
            relaent: RELA_SIZE,
            syment: SYM_SIZE,
            ..DynInfo::default()
        };

        for index in 0..(phdr.p_filesz as usize / 16) {
            let offset = phdr.p_offset as usize + index * 16;
            let tag = read_i64(self.data, offset)?;
            let value = read_u64(self.data, offset + 8)?;
            match tag {
                DT_NULL => break,
                DT_NEEDED => info.needed_offsets.push(value),
                DT_SONAME => info.soname_offset = Some(value),
                DT_STRTAB => info.strtab = value,
                DT_STRSZ => info.strsz = value,
                DT_SYMTAB => info.symtab = value,
                DT_SYMENT => info.syment = value,
                DT_HASH => info.hash = Some(value),
                DT_GNU_HASH => info.gnu_hash = Some(value),
                DT_RELA => info.rela = Some(value),
                DT_RELASZ => info.relasz = value,
                DT_RELAENT => info.relaent = value,
                DT_JMPREL => info.jmprel = Some(value),
                DT_PLTRELSZ => info.pltrelsz = value,
                DT_PLTREL => info.pltrel = value,
                DT_INIT => info.init = Some(value),
                DT_FINI => info.fini = Some(value),
                DT_INIT_ARRAY => info.init_array = Some(value),
                DT_INIT_ARRAYSZ => info.init_arraysz = value,
                DT_FINI_ARRAY => info.fini_array = Some(value),
                DT_FINI_ARRAYSZ => info.fini_arraysz = value,
                DT_FLAGS_1 => info.flags_1 = value,
                _ => {}
            }
        }

        Ok(Some(info))
    }

    pub fn tls(&self) -> Option<Phdr> {
        self.phdrs
            .iter()
            .copied()
            .find(|phdr| phdr.p_type == PT_TLS)
    }
}

pub(crate) fn need(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| LoadError::Elf("offset overflow".into()))?;
    data.get(offset..end).ok_or_else(|| {
        LoadError::Elf(format!(
            "truncated: need {length} bytes at {offset}, file is {} bytes",
            data.len()
        ))
    })
}

pub(crate) fn read_u8(data: &[u8], offset: usize) -> Result<u8> {
    Ok(need(data, offset, 1)?[0])
}

pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = need(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = need(data, offset, 4)?;
    Ok(u32::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
    ]))
}

pub(crate) fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = need(data, offset, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn read_i64(data: &[u8], offset: usize) -> Result<i64> {
    Ok(read_u64(data, offset)? as i64)
}
