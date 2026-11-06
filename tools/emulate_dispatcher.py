#!/usr/bin/env python3
"""Emulate libloader.so's 0xda830 initializer under Unicorn.

Maps the ELF, applies RELA relocations, points imported GOT slots at return
stubs, intercepts syscalls (write/mprotect/getpid/gettid/pidfd_getfd), and
dumps the buffer passed to mprotect plus the first instruction executed there.

Usage:
    .venv-emu/bin/python tools/emulate_dispatcher.py <libloader.so> [--entry 0xda830]
"""

import argparse
import hashlib
import random
from collections import deque
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dynsym import Elf64  # noqa: E402
import constructors as C  # noqa: E402

from unicorn import (  # noqa: E402
    Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_BLOCK,
    UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE,
)
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP, UC_X86_REG_FS_BASE, UC_X86_REG_XMM0, UC_X86_INS_SYSCALL,
)

STUB_BASE = 0x900000000000
STUB_SIZE = 0x10000
STACK_BASE = 0x7FFF00000000
STACK_SIZE = 0x200000
TLS_BASE = 0x7FF000000000
ARGV_BASE = 0x700000000000
HEAP_BASE = 0x600000000000
HEAP_SIZE = 0x4000000
ERRNO_BASE = 0x500000000000
DATA_BASE = 0x510000000000
SENTINEL = 0xDEAD0000

SYS_WRITE = 1
SYS_MMAP = 9
SYS_MPROTECT = 10
SYS_EXIT = 60
SYS_GETPID = 39
SYS_GETTID = 186
SYS_PIDFD_GETFD = 438
SYS_EXIT_GROUP = 231

CANARY_MARK = b"ANTHROPIC"


class Emulator:
    def __init__(self, path, entry, outdir):
        self.path = path
        self.entry = entry
        self.outdir = outdir
        os.makedirs(outdir, exist_ok=True)

        self.data = open(path, "rb").read()
        self.elf = Elf64(self.data)
        self.symbols, _, _ = self.elf.symbols()
        self.relocs = C.read_relocations(self.elf, self.data)
        self.init_targets = [c["target"] for c in
                             C.resolve_constructors(self.elf, self.data, self.relocs)]

        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.stub_names = {}
        self.stub_next = 0
        self.map_image()
        self.setup_memory()
        self.apply_relocations()
        self.setup_hooks()
        self.log = []
        self.writes = []
        self.mprotect = None
        self.buffer_dumped = False
        self.exec_count = 0
        self.force_call = False
        self.direct = False
        self.stop_at = None
        self.skip_xor = False
        self.trace_hash = False
        self.hash_events = []
        self.hash_event_count = 0
        self.hash_counts = {}
        self.frame_rsp = None
        self.states = []
        self.states180 = []
        self.states570 = []
        self.stop_reason = None
        self.mapped = []
        self.blocks = deque(maxlen=24)
        self.calls = []
        self.rng = random.Random(0xC0FFEE)

    # ---------- memory ----------
    def map_image(self):
        loads = [p for p in self.elf.phdrs if p["type"] == 1]
        lo = min(p["vaddr"] & ~0xFFF for p in loads)
        hi = max((p["vaddr"] + p["filesz"] + 0xFFF) & ~0xFFF for p in loads)
        self.uc.mem_map(lo, hi - lo, UC_PROT_ALL)
        for p in loads:
            chunk = self.data[p["offset"]:p["offset"] + p["filesz"]]
            if chunk:
                self.uc.mem_write(p["vaddr"], chunk)
        self.image_lo, self.image_hi = lo, hi

    def setup_memory(self):
        self.uc.mem_map(STUB_BASE, STUB_SIZE, UC_PROT_ALL)
        self.uc.mem_write(STUB_BASE, b"\xc3" * STUB_SIZE)
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        self.uc.mem_map(TLS_BASE, 0x1000, UC_PROT_ALL)
        self.uc.mem_map(ARGV_BASE, 0x1000, UC_PROT_ALL)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
        self.uc.mem_map(ERRNO_BASE, 0x1000, UC_PROT_ALL)
        self.uc.mem_map(DATA_BASE, 0x1000, UC_PROT_ALL)
        self.heap_ptr = HEAP_BASE
        self.allocs = {}
        self.uc.mem_map(SENTINEL & ~0xFFF, 0x1000, UC_PROT_ALL)
        self.uc.mem_write(SENTINEL & ~0xFFF, b"\xf4" * 0x1000)

        self.uc.reg_write(UC_X86_REG_FS_BASE, TLS_BASE)
        self.uc.mem_write(TLS_BASE + 0x28, struct.pack("<Q", 0x123456789ABCDEF0))

        rsp = (STACK_BASE + STACK_SIZE - 0x1000) & ~0xF
        rsp -= 8
        self.uc.mem_write(rsp, struct.pack("<Q", SENTINEL))
        self.entry_rsp = rsp
        self.uc.reg_write(UC_X86_REG_RSP, rsp)

        # argv = {"sober", NULL}, envp = {NULL}
        argv = ARGV_BASE + 0x100
        self.uc.mem_write(ARGV_BASE + 0x200, b"sober\0")
        self.uc.mem_write(argv, struct.pack("<QQ", ARGV_BASE + 0x200, 0))
        self.uc.reg_write(UC_X86_REG_RDI, 1)
        self.uc.reg_write(UC_X86_REG_RSI, argv)
        self.uc.reg_write(UC_X86_REG_RDX, ARGV_BASE + 0x300)

    def apply_relocations(self):
        for r in self.relocs:
            off = r["offset"]
            if r["type"] == 8:  # R_X86_64_RELATIVE
                self.write_qword(off, r["addend"])
            elif r["type"] in (6, 7):  # GLOB_DAT / JUMP_SLOT
                if not r["sym_index"]:
                    continue
                sym = self.symbols[r["sym_index"]]
                if sym["type"] == "OBJECT":
                    self.write_qword(off, DATA_BASE + (r["sym_index"] % 64) * 8)
                else:
                    self.write_qword(off, self.stub_for(sym["name"]))

    def stub_for(self, name):
        if name in self.stub_names:
            return self.stub_names[name]
        addr = STUB_BASE + self.stub_next * 0x10
        self.stub_next += 1
        self.stub_names[name] = addr
        return addr

    def write_qword(self, addr, value):
        self.uc.mem_write(addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def read_qword(self, addr):
        return struct.unpack("<Q", self.uc.mem_read(addr, 8))[0]

    # ---------- hooks ----------
    def setup_hooks(self):
        self.uc.hook_add(UC_HOOK_INSN, self.on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        self.uc.hook_add(UC_HOOK_CODE, self.on_stub, None, STUB_BASE, STUB_BASE + STUB_SIZE)
        self.uc.hook_add(UC_HOOK_CODE, self.on_sentinel, None, SENTINEL & ~0xFFF, (SENTINEL & ~0xFFF) + 0x1000)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self.on_unmapped)
        self.uc.hook_add(UC_HOOK_BLOCK, self.on_block, None, self.image_lo, self.image_hi)
        self.uc.hook_add(UC_HOOK_CODE, self.on_xor, None, 0x1A540, 0x1A541)
        self.uc.hook_add(UC_HOOK_CODE, self.on_hash_event, None, 0xDB750, 0xDB751)
        self.uc.hook_add(UC_HOOK_CODE, self.on_hash_event, None, 0xDB9D1, 0xDB9D2)
        self.uc.hook_add(UC_HOOK_CODE, self.on_hash_event, None, 0xDAD94, 0xDAD95)
        for probe in (0xDC7C0, 0xDC7E0, 0xDC806):
            self.uc.hook_add(UC_HOOK_CODE, self.on_probe, probe, probe + 1)

    def on_block(self, uc, address, size, user):
        self.blocks.append((address, size))
        if address == 0xDC400 and len(self.states) < 200:
            self.states.append((uc.reg_read(UC_X86_REG_ECX), uc.reg_read(UC_X86_REG_EAX),
                                uc.reg_read(UC_X86_REG_EDX), uc.reg_read(UC_X86_REG_R8),
                                uc.reg_read(UC_X86_REG_RDI)))
        if address == 0xDC1A0 and len(self.states180) < 80:
            self.states180.append((uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ECX),
                                   uc.reg_read(UC_X86_REG_EDX)))
        if address == 0xDC570 and len(self.states570) < 80:
            self.states570.append((uc.reg_read(UC_X86_REG_ECX), uc.reg_read(UC_X86_REG_RDX),
                                   uc.reg_read(UC_X86_REG_R8), uc.reg_read(UC_X86_REG_R12),
                                   uc.reg_read(UC_X86_REG_R15)))
        if self.stop_at is not None and address == self.stop_at:
            rsp = uc.reg_read(UC_X86_REG_RSP)
            slots = {}
            for off in (0x10, 0x18, 0x250, 0x4A0):
                try:
                    slots[off] = struct.unpack("<Q", uc.mem_read(rsp + off, 8))[0]
                except Exception:
                    slots[off] = None
            slots_repr = {k: (hex(v) if v is not None else None) for k, v in slots.items()}
            self.log.append(
                f"stop-at {address:#x}: rax={uc.reg_read(UC_X86_REG_RAX):#x} "
                f"rdx={uc.reg_read(UC_X86_REG_RDX):#x} ecx={uc.reg_read(UC_X86_REG_ECX):#x} "
                f"ebx={uc.reg_read(UC_X86_REG_RBX):#x} r8={uc.reg_read(UC_X86_REG_R8):#x} "
                f"r9={uc.reg_read(UC_X86_REG_R9):#x} r12={uc.reg_read(UC_X86_REG_R12):#x} "
                f"r14={uc.reg_read(UC_X86_REG_R14):#x} rsp={rsp:#x} slots={slots_repr}")
            self.stop_reason = f"stopped at requested block {address:#x}"
            uc.emu_stop()

    def on_xor(self, uc, address, size, user):
        if not self.skip_xor:
            return
        rdi = uc.reg_read(UC_X86_REG_RDI)
        r9 = uc.reg_read(UC_X86_REG_R9)
        r11 = uc.reg_read(UC_X86_REG_R11)
        rbx = uc.reg_read(UC_X86_REG_RBX)
        if rbx != 0 or r11 & 0x1F or r11 > 0x4000000:
            return
        try:
            src = bytes(uc.mem_read(rdi, r11))
            dst = bytes(uc.mem_read(r9, r11))
        except Exception:
            return
        out = bytes(a ^ b for a, b in zip(src, dst))
        uc.mem_write(r9, out)
        uc.reg_write(UC_X86_REG_RBX, r11)
        uc.reg_write(UC_X86_REG_RIP, 0x1A576)
        if r11 > 0x1000:
            self.log.append(f"bulk xor {r11:#x} bytes at {r9:#x} from {rdi:#x}")

    def enable_hash_trace(self):
        self.trace_hash = True
        self.frame_rsp = self.entry_rsp - 0x5A8
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_stack_write, None,
                         self.frame_rsp, self.frame_rsp + 0x578)

    def _hash_event(self, text):
        self.hash_event_count += 1
        kind = text.split()[0]
        self.hash_counts[kind] = self.hash_counts.get(kind, 0) + 1
        if len(self.hash_events) < 4096:
            self.hash_events.append(text)

    def on_hash_event(self, uc, address, size, user):
        if not self.trace_hash:
            return
        rsp = uc.reg_read(UC_X86_REG_RSP)
        try:
            slot0 = self.read_qword(rsp)
            slot8 = self.read_qword(rsp + 8)
            acc = self.read_qword(rsp + 0x4A0)
        except Exception:
            slot0 = slot8 = acc = None
        if address == 0xDB750:
            self._hash_event(
                f"DB750 #{self.hash_event_count}"
                f" r14={uc.reg_read(UC_X86_REG_R14):#x}"
                f" r15={uc.reg_read(UC_X86_REG_R15):#x}"
                f" cl={uc.reg_read(UC_X86_REG_RCX) & 0xff:#x}"
                f" hash={acc:#x}"
                f" [rsp]={slot0:#x} [rsp+8]={slot8:#x}"
            )
        elif address == 0xDB9D1:
            self._hash_event(
                f"DB9D1 #{self.hash_event_count}"
                f" r14={uc.reg_read(UC_X86_REG_R14):#x}"
                f" r15={uc.reg_read(UC_X86_REG_R15):#x}"
                f" r13={uc.reg_read(UC_X86_REG_R13):#x}"
                f" eax={uc.reg_read(UC_X86_REG_EAX):#x}"
                f" rbp={uc.reg_read(UC_X86_REG_RBP):#x}"
                f" hash={acc:#x}"
                f" [rsp]={slot0:#x} [rsp+8]={slot8:#x}"
            )
        elif address == 0xDAD94:
            try:
                key = self.read_qword(rsp + 0x50)
            except Exception:
                key = None
            self._hash_event(
                f"DAD94 #{self.hash_event_count}"
                f" rbx={uc.reg_read(UC_X86_REG_RBX):#x}"
                f" r14={uc.reg_read(UC_X86_REG_R14):#x}"
                f" rax={uc.reg_read(UC_X86_REG_RAX):#x}"
                f" r12={uc.reg_read(UC_X86_REG_R12):#x}"
                f" key={key:#x}"
            )

    def on_stack_write(self, uc, access, address, size, value, user):
        if not self.trace_hash or self.frame_rsp is None:
            return
        off = address - self.frame_rsp
        touches = (address < self.frame_rsp + 0x20 and
                   address + size > self.frame_rsp + 0x10)
        if off != 0x4A0 and not touches:
            return
        self._hash_event(
            f"STACK #{self.hash_event_count} off={off:#x} size={size:#x}"
            f" value={value:#x} rip={uc.reg_read(UC_X86_REG_RIP):#x}"
        )

    def on_probe(self, uc, address, size, user):
        if self.force_call and address == 0xDC7C0:
            uc.reg_write(UC_X86_REG_RAX, 0)
            uc.reg_write(UC_X86_REG_RDX, 0)
        if self.force_call and address == 0xDC7E0:
            uc.reg_write(UC_X86_REG_RIP, 0xDC806)
            return
        if len(self.log) < 80:
            self.log.append(
                f"probe {address:#x} rax={uc.reg_read(UC_X86_REG_RAX):#x} "
                f"rcx={uc.reg_read(UC_X86_REG_RCX):#x} rdx={uc.reg_read(UC_X86_REG_RDX):#x} "
                f"r8={uc.reg_read(UC_X86_REG_R8):#x} r12={uc.reg_read(UC_X86_REG_R12):#x} "
                f"r14={uc.reg_read(UC_X86_REG_R14):#x} r15={uc.reg_read(UC_X86_REG_R15):#x}")

    def on_internal_stub(self, uc, address, size, user):
        if len(self.log) < 40:
            self.log.append(f"stubbed internal call at {address:#x}")
        rdi = uc.reg_read(UC_X86_REG_RDI)
        if rdi:
            try:
                uc.mem_write(rdi, b"\x00" * 16)
            except Exception:
                pass
        uc.reg_write(UC_X86_REG_RAX, 0)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = self.read_qword(rsp)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def on_unmapped(self, uc, access, address, size, value, user):
        rip = uc.reg_read(UC_X86_REG_RIP)
        regs = {name: uc.reg_read(reg) for name, reg in {
            "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX,
            "rdx": UC_X86_REG_RDX, "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
            "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9, "r10": UC_X86_REG_R10,
            "r11": UC_X86_REG_R11, "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13,
            "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
        }.items()}
        self.stop_reason = f"unmapped access at {address:#x} size {size} from rip {rip:#x}"
        self.log.append(self.stop_reason)
        self.log.append("regs: " + " ".join(f"{k}={v:#x}" for k, v in regs.items()))
        self.log.append("blocks: " + " ".join(f"{a:#x}/{s}" for a, s in self.blocks))
        uc.emu_stop()
        return False

    def on_sentinel(self, uc, address, size, user):
        self.stop_reason = f"returned to sentinel at {address:#x}"
        uc.emu_stop()

    def alloc(self, n):
        n = max(int(n), 16)
        n = (n + 15) & ~15
        ptr = self.heap_ptr
        if ptr + n > HEAP_BASE + HEAP_SIZE:
            return 0
        self.heap_ptr += n
        self.allocs[ptr] = n
        return ptr

    def memcpy(self, dst, src, n):
        n = min(int(n), 0x100000)
        raw = bytes(self.uc.mem_read(src, n))
        self.uc.mem_write(dst, raw)
        return dst

    def memset(self, dst, value, n):
        n = min(int(n), 0x100000)
        self.uc.mem_write(dst, bytes([value & 0xFF]) * n)
        return dst

    def cstr(self, addr, limit=4096):
        out = bytearray()
        for i in range(limit):
            b = bytes(self.uc.mem_read(addr + i, 1))[0]
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def on_stub(self, uc, address, size, user):
        name = next((n for n, a in self.stub_names.items() if a == address), f"stub_{address:#x}")
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        result = 0

        if name == "write":
            record = {"fd": rdi, "addr": rsi, "len": rdx}
            try:
                raw = bytes(uc.mem_read(rsi, min(rdx, 4096)))
                record["sha256"] = hashlib.sha256(raw).hexdigest()
                record["canary"] = CANARY_MARK in raw
                record["head"] = raw[:16].hex()
            except Exception as exc:
                record["error"] = str(exc)
            self.writes.append(record)
            result = rdx if rdi in (1, 2) else 0xFFFFFFFFFFFFFFFF
        elif name == "sysconf":
            result = 4096 if rdi == 30 else 0
        elif name == "malloc":
            result = self.alloc(rdi)
            self.calls.append(("malloc", rdi, 0, 0))
        elif name == "calloc":
            result = self.alloc(rdi * rsi)
            self.calls.append(("calloc", rdi, rsi, 0))
        elif name == "realloc":
            old = self.allocs.get(rdi, 0)
            newptr = self.alloc(rsi)
            if rdi and newptr:
                try:
                    self.memcpy(newptr, rdi, min(old, rsi))
                except Exception:
                    pass
            result = newptr
            self.calls.append(("realloc", rdi, rsi, 0))
        elif name == "free":
            result = 0
        elif name == "posix_memalign":
            ptr = self.alloc(rdx)
            self.uc.mem_write(rdi, struct.pack("<Q", ptr))
            result = 0
        elif name in ("memcpy", "memmove"):
            result = self.memcpy(rdi, rsi, rdx)
        elif name == "memset":
            result = self.memset(rdi, rsi, rdx)
        elif name in ("memcmp", "bcmp"):
            a = bytes(uc.mem_read(rdi, min(rdx, 0x100000)))
            b = bytes(uc.mem_read(rsi, min(rdx, 0x100000)))
            result = (a > b) - (a < b)
        elif name == "strlen":
            result = len(self.cstr(rdi))
        elif name == "strcmp":
            a, b = self.cstr(rdi), self.cstr(rsi)
            result = (a > b) - (a < b)
        elif name == "strncmp":
            a = self.cstr(rdi)[:rdx]
            b = self.cstr(rsi)[:rdx]
            result = (a > b) - (a < b)
        elif name == "getrandom":
            n = min(int(rsi), 4096)
            self.uc.mem_write(rdi, self.rng.randbytes(n))
            result = n
            if len(self.calls) < 200:
                self.calls.append(("getrandom", n, 0, 0))
        elif name == "__tls_get_addr":
            result = TLS_BASE
            if len(self.calls) < 200:
                self.calls.append(("__tls_get_addr", 0, 0, 0))
        elif name == "mmap64" or name == "mmap":
            result = self.alloc(max(int(rsi), 0x1000))
            if len(self.calls) < 200:
                self.calls.append((name, rdi, rsi, rdx))
        elif name == "__errno_location":
            result = ERRNO_BASE
        elif name in ("abort", "__stack_chk_fail"):
            self.stop_reason = f"called {name}"
            self.log.append(self.stop_reason)
            uc.emu_stop()
            return
        else:
            if len(self.calls) < 200:
                self.calls.append((name, rdi, rsi, rdx))
            result = 0

        uc.reg_write(UC_X86_REG_RAX, result & 0xFFFFFFFFFFFFFFFF)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = self.read_qword(rsp)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def on_syscall(self, uc, user):
        nr = uc.reg_read(UC_X86_REG_RAX)
        a1 = uc.reg_read(UC_X86_REG_RDI)
        a2 = uc.reg_read(UC_X86_REG_RSI)
        a3 = uc.reg_read(UC_X86_REG_RDX)
        rip = uc.reg_read(UC_X86_REG_RIP)

        if nr == SYS_WRITE:
            fd, buf, count = a1, a2, a3
            record = {"fd": fd, "addr": buf, "len": count}
            try:
                raw = bytes(uc.mem_read(buf, min(count, 4096)))
                record["sha256"] = hashlib.sha256(raw).hexdigest()
                record["canary"] = CANARY_MARK in raw
                record["head"] = raw[:16].hex()
            except Exception as exc:
                record["error"] = str(exc)
            self.writes.append(record)
            uc.reg_write(UC_X86_REG_RAX, count if fd in (1, 2) else 0xFFFFFFFFFFFFFFFF)
        elif nr == SYS_MPROTECT:
            self.mprotect = {"addr": a1, "len": a2, "prot": a3, "rip": rip}
            self.log.append(f"mprotect({a1:#x}, {a2:#x}, {a3:#x}) at rip {rip:#x}")
            self.dump_buffer(a1, a2)
            uc.reg_write(UC_X86_REG_RAX, 0)
        elif nr in (SYS_GETPID, SYS_GETTID):
            uc.reg_write(UC_X86_REG_RAX, 4242)
        elif nr == SYS_PIDFD_GETFD:
            uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFF7)
        elif nr in (SYS_EXIT, SYS_EXIT_GROUP):
            self.stop_reason = f"exit syscall {nr}"
            uc.emu_stop()
            return
        elif nr == SYS_MMAP:
            self.log.append(f"mmap({a1:#x}, {a2:#x}, {a3:#x}) at rip {rip:#x} -> ENOSYS")
            uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFDA)
        else:
            self.log.append(f"syscall {nr} at rip {rip:#x} -> ENOSYS")
            uc.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFDA)

        # Unicorn advances RIP past the syscall instruction itself.

    # ---------- buffer ----------
    def dump_buffer(self, addr, length):
        if self.buffer_dumped:
            return
        self.buffer_dumped = True
        size = min(max(length, 16), 0x1000)
        try:
            raw = bytes(self.uc.mem_read(addr, size))
        except Exception:
            size = 16
            try:
                raw = bytes(self.uc.mem_read(addr, size))
            except Exception as exc:
                self.log.append(f"buffer dump failed at {addr:#x}: {exc}")
                return
        path = os.path.join(self.outdir, "code_buffer.bin")
        with open(path, "wb") as fh:
            fh.write(raw)
        self.log.append(f"dumped {len(raw)} bytes at {addr:#x} to {path}")
        self.buffer_addr = addr
        self.buffer_len = length

        # Redact the injected canary in anything printed.
        printable = raw.replace(CANARY_MARK, b"[REDACTED]")
        print(f"\n=== mprotect buffer: {addr:#x} len {length:#x} ({size} bytes saved) ===")
        for i in range(0, min(size, 192), 16):
            row = printable[i:i + 16]
            print(f"{addr + i:#014x}  {row.hex(' '):<47}  " +
                  "".join(chr(c) if 32 <= c < 127 else "." for c in row))
        print("\n=== disassembly of buffer ===")
        proc = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel",
             f"--adjust-vma={addr:#x}", path],
            capture_output=True, text=True,
        )
        lines = proc.stdout.splitlines()
        start = next((i for i, l in enumerate(lines) if l.strip().endswith(":") is False and
                      len(l.split(":")) > 1), 0)
        print("\n".join(lines[start:start + 50]))

        # Stop at the first instruction of the mprotected region.
        self.uc.hook_add(UC_HOOK_CODE, self.on_buffer_exec, None, addr, addr + min(size, 0x1000))

    def on_buffer_exec(self, uc, address, size, user):
        rip = uc.reg_read(UC_X86_REG_RIP)
        self.exec_count += 1
        if self.exec_count <= 14:
            self.log.append(f"executed mprotected buffer at {rip:#x} (insn {self.exec_count})")
        if self.exec_count == 14:
            self.stop_reason = f"executed 14 instructions of generated code at {rip:#x}"
            uc.emu_stop()

    # ---------- run ----------
    def prepare_stack(self):
        self.uc.reg_write(UC_X86_REG_RSP, self.entry_rsp)
        self.uc.reg_write(UC_X86_REG_RDI, 1)
        self.uc.reg_write(UC_X86_REG_RSI, ARGV_BASE + 0x100)
        self.uc.reg_write(UC_X86_REG_RDX, ARGV_BASE + 0x300)

    def run(self, timeout_us=60_000_000, max_insn=50_000_000):
        print(f"image: {self.image_lo:#x}-{self.image_hi:#x}, relocs: {len(self.relocs)}, "
              f"stubs: {len(self.stub_names)}")
        print(f"stack: {STACK_BASE:#x}, tls: {TLS_BASE:#x}, stub page: {STUB_BASE:#x}")
        print(f"initializers: {[hex(t) for t in self.init_targets]}")
        targets = [self.entry] if (self.direct or self.entry != 0xDA830) else (self.init_targets or [self.entry])
        per_timeout = max(5_000_000, timeout_us // len(targets))
        per_count = max(1_000_000, max_insn // len(targets))
        for index, target in enumerate(targets):
            self.prepare_stack()
            if self.entry == 0xDC320:
                rsp = ((self.entry_rsp + 0x250) & ~0xF) - 0x250
                self.uc.reg_write(UC_X86_REG_RSP, rsp)
                self.uc.reg_write(UC_X86_REG_R14, rsp + 0x250)
                self.uc.reg_write(UC_X86_REG_RAX, 0)
                self.uc.reg_write(UC_X86_REG_RDX, 0)
                self.uc.reg_write(UC_X86_REG_RCX, 0)
                self.uc.reg_write(UC_X86_REG_XMM0, 0)
            self.stop_reason = None
            print(f"\n--- initializer {index}: {target:#x} ---")
            try:
                self.uc.emu_start(target, SENTINEL, timeout=per_timeout, count=per_count)
            except Exception as exc:
                rip = self.uc.reg_read(UC_X86_REG_RIP)
                self.stop_reason = f"unicorn error: {exc} at rip {rip:#x}"
                self.log.append(self.stop_reason)
                self.log.append("blocks: " + " ".join(f"{a:#x}/{n}" for a, n in self.blocks))
                try:
                    raw = bytes(self.uc.mem_read(rip, 32))
                    self.log.append(f"bytes@{rip:#x}: {raw.hex()}")
                except Exception:
                    pass
            if self.stop_reason is None:
                self.stop_reason = f"stopped at rip {self.uc.reg_read(UC_X86_REG_RIP):#x}"
            rip = self.uc.reg_read(UC_X86_REG_RIP)
            if rip == SENTINEL:
                self.stop_reason = f"returned to sentinel at {rip:#x}"
            print(f"stop: {self.stop_reason}")
            if rip != SENTINEL:
                break
        print(f"\nfinal stop: {self.stop_reason}")
        print(f"writes: {self.writes}")
        print(f"mprotect: {self.mprotect}")
        print(f"dc400 states: {self.states[:40]}")
        print(f"dc180 states: {self.states180[:40]}")
        print(f"dc570 states: {self.states570[:40]}")
        print(f"stub calls ({len(self.calls)}): {self.calls[:20]}")
        if self.trace_hash:
            path = os.path.join(self.outdir, "hash_trace.log")
            with open(path, "w") as fh:
                fh.write(f"hash events: {self.hash_event_count}\n")
                fh.write("counts: " + repr(self.hash_counts) + "\n")
                fh.write("\n".join(self.hash_events) + "\n")
            print(f"hash events: {self.hash_event_count}; counts: {self.hash_counts}; first/last written to {path}")
            print("last hash events:")
            for line in self.hash_events[-12:]:
                print(" ", line)
        print("log:")
        for line in self.log:
            print(" ", line)
        with open(os.path.join(self.outdir, "report.txt"), "w") as fh:
            fh.write(f"stop: {self.stop_reason}\nwrites: {self.writes}\nmprotect: {self.mprotect}\n")
            fh.write("\n".join(self.log) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("elf")
    parser.add_argument("--entry", type=lambda s: int(s, 0), default=0xDA830)
    parser.add_argument("--outdir", default="tools/emulation")
    parser.add_argument("--timeout", type=int, default=60_000_000)
    parser.add_argument("--max-insn", type=int, default=50_000_000)
    parser.add_argument("--force-call", action="store_true")
    parser.add_argument("--direct", action="store_true", help="run --entry as-is, not the constructor list")
    parser.add_argument("--stop-at", type=lambda s: int(s, 0), default=None, help="stop at this block address")
    parser.add_argument("--skip-xor", action="store_true", help="bulk-emulate the 0x1a540 xor helper")
    parser.add_argument("--trace-hash", action="store_true", help="trace 0xdb750/0xdb9d1 updates and frame writes")
    args = parser.parse_args(argv)

    emu = Emulator(args.elf, args.entry, args.outdir)
    emu.force_call = args.force_call
    emu.direct = args.direct
    emu.stop_at = args.stop_at
    emu.skip_xor = args.skip_xor
    if args.trace_hash:
        emu.enable_hash_trace()
    emu.run(timeout_us=args.timeout, max_insn=args.max_insn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
