#!/usr/bin/env python3
"""Resolve and disassemble DT_INIT_ARRAY constructors of a sectionless ELF64.

Constructor slots in a PIE/DSO usually hold zero in the file and are filled by
R_X86_64_RELATIVE relocations, so this reads DT_RELA as well as DT_INIT_ARRAY.
Disassembly uses `objdump -b binary`, because objdump -d needs section headers.

Usage:
    python3 tools/constructors.py <elf> [--bytes N] [--follow] [--json]
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dynsym import Elf64  # noqa: E402

DT_INIT = 12
DT_RELA = 7
DT_RELASZ = 8
DT_JMPREL = 23
DT_PLTRELSZ = 2
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27

R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8

RELOC_NAMES = {
    R_X86_64_GLOB_DAT: "GLOB_DAT",
    R_X86_64_JUMP_SLOT: "JUMP_SLOT",
    R_X86_64_RELATIVE: "RELATIVE",
}


def read_relocations(elf, data):
    out = []

    def read_table(table_vaddr, size):
        off = elf.vaddr_to_offset(table_vaddr)
        if off is None:
            return
        for i in range(size // 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off + i * 24)
            out.append({
                "offset": r_offset,
                "type": r_info & 0xFFFFFFFF,
                "sym_index": r_info >> 32,
                "addend": r_addend,
            })

    if DT_RELA in elf.dynamic:
        read_table(elf.dynamic[DT_RELA], elf.dynamic.get(DT_RELASZ, 0))
    if DT_JMPREL in elf.dynamic:
        read_table(elf.dynamic[DT_JMPREL], elf.dynamic.get(DT_PLTRELSZ, 0))
    return out


def resolve_constructors(elf, data, relocs):
    array = elf.dynamic.get(DT_INIT_ARRAY)
    if array is None:
        return []
    size = elf.dynamic.get(DT_INIT_ARRAYSZ, 0)
    by_offset = {}
    for r in relocs:
        by_offset.setdefault(r["offset"], []).append(r)

    out = []
    for i in range(size // 8):
        slot = array + i * 8
        hits = [r for r in by_offset.get(slot, []) if r["type"] == R_X86_64_RELATIVE]
        if hits:
            target = hits[0]["addend"]
            source = "RELATIVE"
        else:
            target = struct.unpack_from("<Q", data, elf.vaddr_to_offset(slot))[0]
            source = "raw"
        out.append({"index": i, "slot": slot, "target": target, "source": source})
    return out


def read_cstring(elf, data, vaddr, limit=80):
    off = elf.vaddr_to_offset(vaddr)
    if off is None:
        return None
    end = data.find(b"\0", off, min(off + limit, len(data)))
    if end < 0:
        return None
    raw = data[off:end]
    if len(raw) < 4 or any(b < 0x20 or b > 0x7E for b in raw):
        return None
    return raw.decode("ascii")


def reloc_name_map(elf, symbols, relocs):
    names = {}
    for r in relocs:
        if r["type"] in (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT) and r["sym_index"]:
            sym = symbols[r["sym_index"]]
            names[r["offset"]] = f"{sym['name']}[{RELOC_NAMES[r['type']]}]"
    return names


def annotate(line, elf, data, reloc_names):
    suffix = []
    for match in re.finditer(r"# 0x([0-9a-f]+)", line):
        addr = int(match.group(1), 16)
        if addr in reloc_names:
            suffix.append(reloc_names[addr])
            continue
        text = read_cstring(elf, data, addr)
        if text:
            suffix.append(f'"{text}"')
    if suffix:
        return line + "  ; " + ", ".join(dict.fromkeys(suffix))
    return line


def disassemble(elf, data, vaddr, nbytes, reloc_names):
    off = elf.vaddr_to_offset(vaddr)
    if off is None:
        return f"  <address {vaddr:#x} is not backed by a PT_LOAD segment>"
    chunk = data[off:off + nbytes]
    fd, path = tempfile.mkstemp(dir=".", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(chunk)
        proc = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel",
             f"--adjust-vma={vaddr:#x}", path],
            capture_output=True, text=True,
        )
    finally:
        os.unlink(path)

    lines = proc.stdout.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if re.match(r"^\s*[0-9a-f]+:", line)), len(lines))
    body = [annotate(line, elf, data, reloc_names) for line in lines[start:]]
    return "\n".join(body)


def leading_jump(disasm_text):
    for line in disasm_text.splitlines()[:4]:
        match = re.search(r"\bjmp\s+0x([0-9a-f]+)", line)
        if match:
            return int(match.group(1), 16)
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("elf")
    parser.add_argument("--bytes", type=int, default=96, help="bytes per constructor (default 96)")
    parser.add_argument("--follow", action="store_true", help="also disassemble a leading jmp target")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    data = open(args.elf, "rb").read()
    elf = Elf64(data)
    symbols, _, _ = elf.symbols()
    relocs = read_relocations(elf, data)
    names = reloc_name_map(elf, symbols, relocs)
    ctors = resolve_constructors(elf, data, relocs)

    if args.json:
        print(json.dumps({"path": args.elf, "constructors": ctors}, indent=2))
        return 0

    init = elf.dynamic.get(DT_INIT, 0)
    print(f"file: {args.elf}")
    print(f"INIT: {init:#x} (file {elf.vaddr_to_offset(init):#x})" if init else "INIT: none")
    print(f"INIT_ARRAY: {elf.dynamic.get(DT_INIT_ARRAY, 0):#x} "
          f"({len(ctors)} slots, DT_INIT_ARRAYSZ={elf.dynamic.get(DT_INIT_ARRAYSZ, 0)})")
    print(f"relocations: {len(relocs)}  named GOT slots: {len(names)}")
    print()

    for ctor in ctors:
        off = elf.vaddr_to_offset(ctor["target"])
        print(f"[{ctor['index']}] slot {ctor['slot']:#x} -> {ctor['target']:#x} "
              f"(file {off:#x}, {ctor['source']})")
        text = disassemble(elf, data, ctor["target"], args.bytes, names)
        print(text)
        if args.follow:
            target = leading_jump(text)
            if target is not None:
                print(f"    ; tail jmp -> {target:#x} (file {elf.vaddr_to_offset(target):#x})")
                print(disassemble(elf, data, target, args.bytes, names))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
