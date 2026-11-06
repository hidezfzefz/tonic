# `0xda830` dispatcher emulation

Target: installed `libloader.so` from `org.vinegarhq.Sober` 1.8.0
(`7b6430c7...62cb9d26`), SHA-256
`9fb3c201bcadca0fd22c0afdeff25af759aecc631f3816a2e63f6b0d147c3da5`.

Sandbox: Unicorn 2.1.4 in `.venv-emu`, x86-64 user-mode. PT_LOAD images are
mapped at vaddr 0; private stack, TLS, heap, argument and stub pages are used.
Imports are resolved to return stubs and syscalls are intercepted. No target
code was executed natively and no host syscall is issued by emulated code.

Harness: `tools/emulate_dispatcher.py`. With no `--entry` argument it runs the
five `DT_INIT_ARRAY` constructors in order (`0x15e630`, `0x12a970`, `0x130080`,
`0x180b0`, `0xfcd90`) so the dispatcher sees the globals set by the earlier
constructors.

## Gate trace

The handoff is selected by this comparison in the `0xdc570` state machine:

```
0xdc7a3  cmp ecx, 0xceb3e876
0xdc7a9  je  0xdc7c0
```

A focused run entering at `0xdc180` reached that comparison with
`ecx=0xceb3e876` and took the branch to `0xdc7c0` (block trace
`0xdc7a3/8 0xdc7c0/32`). The handoff block is therefore reachable; the full
constructor run does not reach it because it spends its budget in the
allocator/formatting path (`stopped at rip 0x13ed21`, `mprotect: None`).

The handoff context is built by the block at `0xdc320`:

```
0xdc104  pxor      xmm0, xmm0
0xdc108  lea       r14, [rsp+0x250]
0xdc320  movzx     eax, cl
0xdc323  movd      xmm1, eax
0xdc327  pshufb    xmm1, xmm0        ; xmm0 == 0 -> 16 zero bytes
0xdc32c  movdqa    [rsp+0x250], xmm1
0xdc335  ... 12x: mov byte [rsp+0x250+i], 0x90
0xdc394
0xdc7c0  lea       rsi, [rax+rdx]
0xdc7c4  add       rsi, 0x10
0xdc7c8  mov       eax, 10           ; mprotect
0xdc7cd  mov       edx, 5            ; PROT_READ|PROT_EXEC
0xdc7d2  mov       rdi, r14
0xdc7de  syscall
0xdc806  call      r14
```

`r14` is the address of the 16-byte stack stub. The stub bytes are:

```
90 90 90 90 90 90 90 90 90 90 90 90 00 00 00 00
```

Twelve NOPs followed by four zero bytes at `[rsp+0x250]`. The address is
`rsp+0x250`, which is not page-aligned; Linux `mprotect` requires a
page-aligned address, so the real syscall returns `EINVAL` regardless of
the length. The execution trace below is therefore a forced/emulated
continuation, not evidence of a successful JIT handoff.

## Runtime capture

Because the full constructor path did not reach the block, the handoff was
entered with its required context: `--entry 0xdc320`, `r14 = rsp+0x250`,
`rax = rdx = 0`, and `xmm0 = 0`. This still runs the real stub-builder, the
`0xdc400` state machine, the gate at `0xdc7a3`, and the `0xdc7c0` mprotect.

Unforced handoff run (no `--force-call`):

```
mprotect(0x7fff001ff240, 0x2000000010, 0x5) at rip 0xdc7de
dumped 16 bytes at 0x7fff001ff240 to tools/emulation/code_buffer.bin
unmapped access at 0x2ed21271 size 8 from rip 0xdc804
```

The large length comes from the state at `0xdc7c0` when the pre-handoff
register setup is skipped; on a real kernel that `mprotect` would fail. The
bytes after the syscall then execute `imul eax,[rax],0xa6000f` and
`fld qword [rax]`; with the resulting small `rax` the `fld` faults at
`0xdc804`, so `call r14` at `0xdc806` is not reached on this exact state.

Forced-call run (`--force-call`): `rax=rdx=0` at `0xdc7c0` makes the length
`0x10`, and the decoy at `0xdc7e0`-`0xdc804` is skipped to enter the call.

```
mprotect(0x7fff001ff240, 0x10, 0x5) at rip 0xdc7de
dumped 16 bytes at 0x7fff001ff240 to tools/emulation/code_buffer.bin
executed mprotected buffer at 0x7fff001ff240 (insn 1)
...
executed mprotected buffer at 0x7fff001ff24c (insn 13)
executed mprotected buffer at 0x7fff001ff24e (insn 14)
stop: executed 14 instructions of generated code at 0x7fff001ff24e
```

The first 12 executed instructions are the NOP sled (`+0x00` through `+0x0b`).
Instruction 13 at `+0x0c` is `00 00` (`add byte ptr [rax], al`), followed by
the same at `+0x0e`. Execution was stopped after instruction 14. This is a
NOP sled that immediately falls into zero bytes, not a functional JIT body.

## State map

`tools/emulation/STATE_MAP.md` contains the complete `0xdc180` and
`0xdc570` transition tables and the selected chain into `0xdc320`.

The conditional handoff path is:

```
0xda830 outer tables
  -> 0xdc0fd  (eax=0, ebx=0xad45d216, r14=rsp+0x250)
  -> 0xdc15b  (ebx matches -> 0xdc180)
  -> 0xdc180  (eax=0x7dc1d493, cl=0, edx=0)
  -> 0xdc1a0 ten-state chain -> 0xdc320
  -> 0xdc400 nine-state bridge -> 0xdc570
  -> 0xdc570 eleven-state chain -> 0xdc7c0
```

The `0xdc180` chain is:
`7dc1d493 -> a94de82c -> 01ccf49b -> b7e02cec -> cb6cc027 ->
e8463540 -> 1cc8aad8 -> d9d93c57 -> f6d9fc74 -> 66e9c638 -> 0xdc320`.

The `0xdc570` chain is:
`5459b603 -> 8eeaabc4 -> 3889b4bd -> 06d65c6a -> 83d0aac4 ->
79fbc18b -> 753e1f14 -> 18afa069 -> b559ad0d -> 904c660a ->
d13eefe4 -> ceb3e876 -> 0xdc7c0`.

`0x26692ed3` and `0x79fbc18b` are real intermediate states reached by
fall-through/NOP padding; they do not appear as separate block-hook events.

A direct `0xda830` entry reaches `0xdc0cc` with
`rax=0x528a9f7829eca2f7` and `rdx=0x1fad`. The mismatch takes `0xdc82d`;
the observed `[rsp+0x18]=0` and
`[rsp+0x4a0] & 0xba2d8279b70bf69f = 0x120882782108a297 != 0` send it to
the canary/`gettid` path instead of `0xdc0fd`. The chain below is therefore
conditional/forced, not the normal direct-entry outcome.

### Hash derivation and result

The gate value is a 64-bit hash, not a table lookup. Across 512
`0xdb9d1` folds and 40 `0xdb750` rotations, the observed recurrence is
`rbp = 0x115 + gettid*(slot+index)`, `hash ^= rbp`, then
`hash = rol64(hash,3) ^ 0x2ea951568e4b9f81` on odd slots at indices
3, 10, 17, 24, and 31. The full trace is `tools/emulation/hash_trace.log`.

The final observed hash is `0x528a9f7829eca2f7`; `rdx` is the fixed
constant `0x1fad` from the constant-only `0xdbef0` decoder. Replaying all
default Linux PID values (`1..4194304`) found zero equality hits and zero
`(hash & 0xba2d8279b70bf69f)==0` hits.

The fallback flag is structurally zero, not merely a lucky observation.
At `0xdaaef`, the real state is `rax=0x1092` (gettid), `r12=0`, `r14=1`,
and `[rsp+0x250]=1`. With the fixed nonzero key, `sete cl` cannot be true:
`rdx|rcx` is nonzero whether `r14` is zero or nonzero. `setl bl` is false
because `0x1092 > 0=r12`. `0xdad94` and `0xdadae` therefore propagate
`bl=0` into `[rsp+0x18]`. No legitimate initialization can set this flag;
only a forced key/`r14`/`r12` state could. The focused capture is
`tools/emulation/flag_gate.log`.

No normal-state route selects `0xdc0fd`; the handoff chain remains reachable
only with forced conditions.

## Dump provenance

`tools/emulation/code_buffer.bin` is the runtime capture from the forced
handoff: 16 bytes, SHA-256
`c8c0c7ac9f04cd1038dbd85f20caf89ab6bec96a14f2695d01587a18636bafc0`.
`tools/emulation/code_buffer.static.bin` is the equivalent static
reconstruction from the store instructions; the bytes are identical.
`tools/emulation/handoff_run.log` is the clean forced-handoff/call log.

Caveat: the entry at `0xdc320` and the skip of the `0xdc7e0` decoy are
instrumentation to isolate the handoff. The full constructor run still does not
reach the gate, and the natural handoff state faults before `call r14`.

Reproduction:

```
.venv-emu/bin/python tools/emulate_dispatcher.py <libloader.so> \
  --entry 0xdc320 --force-call --timeout 10000000
```
