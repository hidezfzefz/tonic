#!/usr/bin/env python3
"""List dynamic symbols of an ELF64 image using only PT_DYNAMIC.

Section headers are optional: symbol count comes from DT_GNU_HASH (or DT_HASH),
addresses are mapped through PT_LOAD, and names are read from DT_STRTAB.

Usage:
    python3 tools/dynsym.py <elf> [--filter SUBSTR] [--json] [--summary]
"""

import argparse
import json
import struct
import sys

PT_LOAD = 1
PT_DYNAMIC = 2

DT_NULL = 0
DT_NEEDED = 1
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_GNU_HASH = 0x6FFFFEF5

STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "UNIQUE"}
STT = {
    0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
    5: "COMMON", 6: "TLS", 10: "GNU_IFUNC",
}
STV = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}


class Elf64:
    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        if data[4] != 2 or data[5] != 1:
            raise ValueError("only ELF64 little-endian is supported")

        self.data = data
        (self.e_type, self.e_machine, _, self.e_entry, self.e_phoff, self.e_shoff,
         _, self.e_ehsize, self.e_phentsize, self.e_phnum, _, self.e_shnum,
         _) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

        self.phdrs = []
        for i in range(self.e_phnum):
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = \
                struct.unpack_from("<IIQQQQQQ", data, self.e_phoff + i * self.e_phentsize)
            self.phdrs.append({
                "type": p_type, "flags": p_flags, "offset": p_offset,
                "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz,
            })

        self.dynamic = {}
        self.needed = []
        dyn = next((p for p in self.phdrs if p["type"] == PT_DYNAMIC), None)
        if dyn is None:
            raise ValueError("no PT_DYNAMIC segment")
        off = dyn["offset"]
        while off + 16 <= len(data):
            d_tag, d_val = struct.unpack_from("<qQ", data, off)
            if d_tag == DT_NULL:
                break
            if d_tag == DT_NEEDED:
                self.needed.append(d_val)
            else:
                self.dynamic.setdefault(d_tag, d_val)
            off += 16

    def vaddr_to_offset(self, addr):
        for p in self.phdrs:
            if p["type"] == PT_LOAD and p["vaddr"] <= addr < p["vaddr"] + p["filesz"]:
                return p["offset"] + (addr - p["vaddr"])
        return None

    def _read_str(self, strtab_off, strsz, index):
        if index >= strsz:
            return "<bad-name>"
        start = strtab_off + index
        end = self.data.find(b"\0", start, strtab_off + strsz)
        if end < 0:
            return "<unterminated>"
        return self.data[start:end].decode("utf-8", "replace")

    def _count_from_gnu_hash(self, addr):
        off = self.vaddr_to_offset(addr)
        if off is None:
            return None
        try:
            nbuckets, symoffset, bloom_size, _ = struct.unpack_from("<IIII", self.data, off)
        except struct.error:
            return None
        buckets_off = off + 16 + bloom_size * 8
        if buckets_off + nbuckets * 4 > len(self.data):
            return None
        buckets = struct.unpack_from(f"<{nbuckets}I", self.data, buckets_off)
        if not buckets or max(buckets) == 0:
            return symoffset
        chains_off = buckets_off + nbuckets * 4
        index = max(buckets)
        while chains_off + (index - symoffset + 1) * 4 <= len(self.data):
            (chain,) = struct.unpack_from("<I", self.data, chains_off + (index - symoffset) * 4)
            if chain & 1:
                return index + 1
            index += 1
        return None

    def _count_from_sysv_hash(self, addr):
        off = self.vaddr_to_offset(addr)
        if off is None:
            return None
        try:
            (nchain,) = struct.unpack_from("<I", self.data, off + 4)
        except struct.error:
            return None
        return nchain

    def symbols(self):
        symtab = self.dynamic.get(DT_SYMTAB)
        strtab = self.dynamic.get(DT_STRTAB)
        if symtab is None or strtab is None:
            raise ValueError("dynamic segment lacks DT_SYMTAB/DT_STRTAB")

        syment = self.dynamic.get(DT_SYMENT, 24)
        strsz = self.dynamic.get(DT_STRSZ, 0)
        sym_off = self.vaddr_to_offset(symtab)
        str_off = self.vaddr_to_offset(strtab)
        if sym_off is None or str_off is None:
            raise ValueError("DT_SYMTAB/DT_STRTAB do not fall inside a PT_LOAD segment")

        count = None
        source = None
        if DT_GNU_HASH in self.dynamic:
            count = self._count_from_gnu_hash(self.dynamic[DT_GNU_HASH])
            source = "DT_GNU_HASH"
        if count is None and DT_HASH in self.dynamic:
            count = self._count_from_sysv_hash(self.dynamic[DT_HASH])
            source = "DT_HASH"
        if count is None:
            raise ValueError("cannot determine dynamic symbol count (no usable hash table)")

        symbols = []
        for i in range(count):
            off = sym_off + i * syment
            if off + 24 > len(self.data):
                break
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", self.data, off)
            symbols.append({
                "index": i,
                "name": self._read_str(str_off, strsz, st_name),
                "bind": STB.get(st_info >> 4, f"BIND{st_info >> 4}"),
                "type": STT.get(st_info & 0xF, f"TYPE{st_info & 0xF}"),
                "visibility": STV.get(st_other & 0x3, f"VIS{st_other & 0x3}"),
                "defined": st_shndx != 0,
                "shndx": st_shndx,
                "value": st_value,
                "size": st_size,
            })
        return symbols, source, count

    def is_export(self, sym):
        return (sym["defined"] and sym["bind"] in ("GLOBAL", "WEAK", "UNIQUE")
                and sym["visibility"] in ("DEFAULT", "PROTECTED"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("elf", help="path to ELF64 file")
    parser.add_argument("--filter", metavar="SUBSTR", help="only names containing SUBSTR")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--summary", action="store_true", help="counts only, no table")
    args = parser.parse_args(argv)

    with open(args.elf, "rb") as fh:
        data = fh.read()

    try:
        elf = Elf64(data)
        symbols, source, count = elf.symbols()
    except (ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.filter:
        symbols = [s for s in symbols if args.filter in s["name"]]

    imports = [s for s in symbols if not s["defined"]]
    exports = [s for s in symbols if elf.is_export(s)]
    other = [s for s in symbols if s["defined"] and not elf.is_export(s)]

    if args.json:
        json.dump({
            "path": args.elf,
            "sections_present": elf.e_shnum > 0,
            "symbol_count": count,
            "count_source": source,
            "needed": [elf._read_str(elf.vaddr_to_offset(elf.dynamic[DT_STRTAB]),
                                      elf.dynamic.get(DT_STRSZ, 0), n) for n in elf.needed],
            "symbols": symbols,
        }, sys.stdout, indent=2)
        print()
        return 0

    str_off = elf.vaddr_to_offset(elf.dynamic[DT_STRTAB])
    strsz = elf.dynamic.get(DT_STRSZ, 0)
    needed = [elf._read_str(str_off, strsz, n) for n in elf.needed]

    print(f"file:    {args.elf}")
    print(f"type:    {'ET_DYN' if elf.e_type == 3 else f'ET_{elf.e_type}'}  "
          f"sections: {'present' if elf.e_shnum else 'stripped (e_shnum=0)'}")
    print(f"symbols: {count} ({source})  exports: {len(exports)}  "
          f"imports: {len(imports)}  local/other: {len(other)}")
    print(f"needed:  {', '.join(needed) if needed else '(none)'}")

    if args.summary:
        return 0

    print()
    header = f"{'idx':>4}  {'bind':<6} {'type':<9} {'vis':<9} {'ndx':>5}  {'value':>16} {'size':>8}  name"
    print(header)
    print("-" * len(header))
    for s in symbols:
        print(f"{s['index']:>4}  {s['bind']:<6} {s['type']:<9} {s['visibility']:<9} "
              f"{s['shndx']:>5}  {s['value']:>16x} {s['size']:>8}  {s['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
