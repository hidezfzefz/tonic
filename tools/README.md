# REA — reverse-engineering toolchain (local)

Cloned from <https://github.com/morluto/rea> at v6.8.0 and built locally so it can
be used for the Sober work without installing anything system-wide.

- `tools/rea/` — upstream clone (MIT), with `dist/` built. ~1.1 GB including git
  history and `node_modules`.
- `tools/node/` — project-local Node 24.22.1. The host Node is v26.8.1, which is
  below REA's floor (`^22.23.4 || ^24.22.1 || >=26.12.1`).
- `tools/dynsym.py` — dependency-free PT_DYNAMIC symbol lister (see below).
- `tools/constructors.py` — resolves `DT_INIT_ARRAY` through RELA and disassembles
  each constructor with GOT/string annotations.

## Setup already performed

```bash
cd tools/rea
npm ci                 # 739 packages
npm run build:cached   # turbo: metadata:check, compile, artifacts:skills
```

## Running

REA requires the local Node on `PATH`; `scripts/rea.mjs` refuses the host Node.

```bash
cd tools/rea
PATH="$PWD/../node/bin:$PATH" node scripts/rea.mjs --version   # 6.8.0
PATH="$PWD/../node/bin:$PATH" node scripts/rea.mjs doctor --json
PATH="$PWD/../node/bin:$PATH" node scripts/rea.mjs inspect-binary-hardening <elf> --format md
```

v6.8.0 exposes 188 CLI commands and 241 MCP tools.

`--format json` cannot be combined with `--token-limit` / `--token-offset`
(`UNSUPPORTED_OUTPUT_COMBINATION`). Use `--filter-output` or `--format md`.

## Provider coverage on this machine

| Capability | Status |
| --- | --- |
| Desktop artifact graph, ELF/view inspections, evidence records | works |
| Native decompilation (Ghidra, IDA, Hopper, jadx, Kuna) | unavailable — none installed |
| `inspect-binary-layout` | unavailable — needs `REA_PWNTOOLS_PYTHON` with pwntools 4.15.0, pyelftools 0.33, Unicorn 2.1.2 |
| Host setup automation | REA classifies this host (Gentoo) as `unsupported_host` |

REA never installs Python packages or decompilers itself, so those paths stay
blocked until the user supplies them.

## What REA found on Sober 1.8.0

Target: `org.vinegarhq.Sober`, branch `stable`, commit
`7b6430c703e8178baa536062099fc5a1e0c7cf213c0789695fa7660b62cb9d26` (2026-10-05
refresh). Flatpak `files/` tree digest
`6fead8632e2ac45505103dae48f28e24e557a9a23c596624b53cd1ce2a447b00`.

| Binary | Bytes | SHA-256 |
| --- | --- | --- |
| `bin/sober` | 7,595,664 | `202ba56849a2de40e5988339e2b3cee383af3360b8f587cc95f6eb3563046e72` |
| `bin/libloader.so` | 4,077,169 | `9fb3c201bcadca0fd22c0afdeff25af759aecc631f3816a2e63f6b0d147c3da5` |
| `bin/libbadcpu.so` | 390,104 | `ad394c74dcb166313e773d99f8d40dee6b4dd123840f0ef4bb5a5dae1429c22d` |
| `bin/sober_services` | 1,132,328 | — (`inspect-elf-notes` rejects its note table) |

Key observations:

- **All four ELF images are section-header-stripped**: `e_shoff = 0`, `e_shnum = 0`,
  `readelf -S` reports "There are no sections in this file." Program headers and
  the dynamic segment are intact, so the binaries still load normally.
- `libloader.so` is `DYN`, entry `0x0`, `RUNPATH $ORIGIN`, `BIND_NOW`, and
  `DT_NEEDED`: `libbadcpu.so`, `libgcc_s.so.1`, `libc.so.6`,
  `ld-linux-x86-64.so.2`. Needing `ld-linux-x86-64.so.2` as a library means it
  uses the dynamic loader's own API rather than reimplementing it.
- `readelf -d libloader.so` reports `SYMTAB 0x3e2028`, `STRTAB 0x3e4000`,
  `STRSZ 2255`, `GNU_HASH 0x14e8`, so a `.dynsym`-equivalent table exists.
  It is reachable only by walking `PT_DYNAMIC`.
- REA's `inspect-native-exports` therefore returns `coverage.status:
  "unsupported"` for this loader ("The ELF has no section headers; enumerating
  dynamic symbols from the dynamic segment is not implemented"). `nm -D` says
  "no symbols"; `objdump -T` prints an empty `DYNAMIC SYMBOL TABLE`.
- Any symbol-level work on Sober — ours or REA's — needs a PT_DYNAMIC/GNU-hash
  walker, not section-header tooling.
- `inspect-desktop-application` on the `files/` tree found no runtime candidates
  or component markers: Sober is a native GTK/Flatpak app, not an Electron or
  Unity bundle, so that heuristic has nothing to report.

Raw evidence records are `ev_*` IDs printed by each command; re-running the same
command on the same bytes reproduces them.

## Dynamic symbols without section headers

`tools/dynsym.py` walks `PT_DYNAMIC` (`DT_SYMTAB`, `DT_STRTAB`, `DT_STRSZ`,
`DT_GNU_HASH`, with a `DT_HASH` fallback) and maps addresses through `PT_LOAD`,
so it works on images where `readelf`, `nm -D` and `objdump -T` see nothing.

```bash
python3 tools/dynsym.py <elf> [--filter SUBSTR] [--json] [--summary]
```

Results for Sober 1.8.0 (control: the host's glibc):

| Image | Dynamic symbols | Exports | Imports |
| --- | ---: | ---: | ---: |
| `bin/libloader.so` | 162 | 0 | 162 |
| `bin/libbadcpu.so` | 56 | 0 | 56 |
| `bin/sober` | 1002 | 0 | 1002 |
| `/lib64/libc.so.6` (control) | 3187 | 3166 | 21 |

- Every dynamic symbol in the three Sober images has `st_shndx = 0`: they import
  libc/libgcc/loader functions but export nothing at all.
- `sober` lists `libloader.so` in `DT_NEEDED`, and `libloader.so` lists
  `libbadcpu.so`, yet those dependencies cannot satisfy a symbol reference. They
  are present for their initializers/side effects, not their API: `libloader.so`
  has entry `0x0` and `INIT_ARRAYSZ` 40 (five function pointers).
- Practical consequence: `dlsym` on these images has nothing to find, so any
  hooking has to target constructors or internal offsets rather than exported
  names.

`--filter` and `--json` make the output usable for scripted comparisons; the
symbol count is derived from the GNU hash chains, not from section headers.

## INIT_ARRAY constructors

`tools/constructors.py <elf> [--bytes N] [--follow] [--json]` resolves each
`DT_INIT_ARRAY` slot through `DT_RELA` (`R_X86_64_RELATIVE`), disassembles the
target from raw bytes, and annotates rip-relative operands that land on a
relocated GOT slot or a printable string.

`libloader.so` has five slots (all zero in the file, filled by RELATIVE):

| # | Slot | Target | File | Role |
| --- | --- | --- | --- | --- |
| 0 | `0x188030` | `0x15e630` | `0x15e630` | Saves `argc`/`argv` in BSS `0x3e19f8`/`0x3e1a00` |
| 1 | `0x188038` | `0x12a970` | `0x12a970` | Guarded one-time init; `sysconf(30)` (`_SC_PAGESIZE`) cached at `0x3e1990` |
| 2 | `0x188040` | `0x130080` | `0x130080` | Sets byte `0x3e19b0 = 1` |
| 3 | `0x188048` | `0x180b0` | `0x180b0` | Tail-jumps to CRT `frame_dummy`/`register_tm_clones` at `0x18030` |
| 4 | `0x188050` | `0xfcd90` | `0xfcd90` | Tail-jumps to `0xda830`, an obfuscated dispatcher |

`DT_INIT` at `0x17000` is the stock `_init` (`__gmon_start__` check), not
application logic.

No constructor stores into the GOT or calls `mprotect`; the only rip-relative
stores are the three BSS globals above. Constructor 4 calls `write` twice with
fd `-1` against a string table and issues a raw `getpid` syscall (`eax=0x27`),
then runs an obfuscated state machine. On this evidence, load time captures
startup context and page size — it does not install hooks or patch the GOT.

## Dispatcher emulation (`0xda830`)

`tools/emulate_dispatcher.py` runs the five `DT_INIT_ARRAY` constructors in
order under Unicorn, stubs imports, and logs syscalls/writes. It reproduces the
two `write(-1, ...)` calls. The unmodified full constructor path stops in the
bulk-XOR helper at `0x1a540`; with `--skip-xor` it advances into a statically
linked zlib inflate stage around `0x13e...`, but still does not reach the
`mprotect` / `call r14` handoff. The gate is
`0xdc7a3: cmp ecx,0xceb3e876; je 0xdc7c0`.

A focused handoff run (`--entry 0xdc320 --force-call`) captures the real
16-byte stack stub at `[rsp+0x250]` and demonstrates the mprotect and call:
12 `0x90` NOPs followed by four zero bytes. The stub address is not
page-aligned, so a real `mprotect` returns `EINVAL`; the call trace is a
forced emulator continuation. The unforced state faults at the
decoy `fld` at `0xdc804` before the call. See
`tools/emulation/FINDINGS.md`; `tools/emulation/code_buffer.bin` is the runtime
capture and `handoff_run.log` is the execution log. The complete
0xdc180/0xdc570 state-transition map is in
`tools/emulation/STATE_MAP.md`.

### Regression check

```bash
python3 -m unittest discover -s tools/emulation -p 'test_*.py' -v
```

The test models the `0xdaaef` flag calculation and checks the captured normal
state, every default `gettid` value, and the forced-state counterexamples. It
does not require the ELF, Unicorn, or the generated logs.

## MCP registration (not applied)

```bash
cd tools/rea
PATH="$PWD/../node/bin:$PATH" node scripts/rea.mjs setup --client freebuff
```

This would write `~/.agents/mcp.json`, which is user-level configuration outside
this project. It was deliberately not run: it would not attach REA to the current
chat session, and project work should not mutate the user's MCP config without an
explicit request.

## Limits

- Static analysis is limited to shipped artifacts. The dispatcher section
  records controlled Unicorn emulation; no code was decompiled.
- The Flatpak `files/` digest commits to paths and read ranges, not every byte.
- Hashes identify the exact installed build; a Sober update invalidates them.
