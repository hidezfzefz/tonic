# Tonic

**A native, auditable Roblox runtime for Linux.**

[![status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)](#status)
[![platform: Linux x86-64](https://img.shields.io/badge/platform-Linux%20x86--64-blue)](#compatibility)
[![license: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](#license)

Tonic runs the official x86-64 Android build of Roblox as native Linux code:
no Wine, no Android container, and no CPU translation. The engine is loaded
unmodified into a process the runtime controls, behind a small compatibility
layer for the Android interfaces it expects.

The goal is a runtime a user can audit, reproduce, and reason about — not
another opaque compatibility layer.

[Design brief](BRIEF.md) · [Architecture](ARCHITECTURE.md) · [Loader findings](tools/emulation/FINDINGS.md) · [Tooling](tools/README.md) · [Regression test](tools/emulation/test_daaef_flag.py)

> **Status: pre-alpha.** There is no playable client, installer, release, or
> supported install path yet. This repository currently contains the design
> documents, a partial ELF-loader prototype, and the tooling used to study the
> Android loader path. Do not expect `cargo run` to launch Roblox.

## About

Roblox does not ship a Linux client, and its Windows client no longer runs
under Wine since Hyperion. The existing route for most Linux users is a
closed-source Android runtime. Tonic asks a narrower question: what would it
take to build that runtime from scratch as a specified, auditable system?

The design deliberately avoids the shortcuts that would make it easier to
ship:

- **No binary translation.** Roblox ships real x86-64 Android machine code.
  Tonic executes it directly; only missing CPU features are emulated.
- **No container.** The engine and the host share an address space through a
  ported bionic linker, rather than marshalling hundreds of native entry
  points across a boundary.
- **No engine patching.** `libroblox.so` is loaded exactly as Roblox signed it.
- **No hidden surface.** The launcher, engine, and web view are separate
  processes with an explicit IPC protocol.
- **No anti-cheat or attestation bypass.** The boundary is documented, not
  worked around.

The runtime targets x86-64 Linux with Flatpak, Wayland first and X11 as a
supported fallback. Kernel 5.11 or newer is required for `syscall user
dispatch`, the mechanism that lets the runtime intercept Android-specific
syscalls without ptrace or a full emulator.

## Status

| Area | State |
| --- | --- |
| Design brief and architecture | Draft v1 — [BRIEF.md](BRIEF.md), [ARCHITECTURE.md](ARCHITECTURE.md) |
| Rust workspace | Scaffold; not buildable yet |
| ELF loader prototype | Partial — ELF parsing and `PT_LOAD` mapping in [`crates/tonic-linker`](crates/tonic-linker) |
| bionic ↔ glibc compatibility | Design; generated `sysconf` table in `build.rs` |
| JNI VM and GameActivity shell | Design |
| Graphics, audio, input | Design |
| Playable client | Not started |
| Loader analysis | Dispatcher path mapped; `0xdaaef` fallback flag regression green |

The Rust workspace is intentionally incomplete at this stage. `tonic-linker`
has the ELF parser and segment mapper, but is not yet wired through a `lib.rs`;
`tonic-run` has no `main.rs`. The analysis tooling and regression test are
runnable now.

## Architecture

The runtime is split so that a hung engine cannot freeze the launcher, and so
that a browser compromise cannot reach the engine's session:

```text
tonic-shell (GTK4) ──unix socket──> tonic-run (one per profile)
  launcher / settings                 ├─ GameActivity shell + JNI VM
  install / updates                   ├─ Android framework shims
                                      ├─ bionic ↔ glibc compatibility
                                      ├─ bionic ELF linker
                                      └─ libroblox.so (unmodified, signed)

tonic-web (WebKitGTK) ──narrow bridge──> Roblox web pages
  separate process, ephemeral store
```

- **`tonic-shell`** owns install, profiles, settings, updates, and diagnostics.
  It never loads the engine.
- **`tonic-run`** hosts the engine, JNI VM, Android framework shims, graphics,
  audio, and input. One process per profile.
- **`tonic-web`** hosts Communities, Marketplace, and Profile content in a
  separate WebKitGTK process.

The engine is loaded in-process because it exchanges raw function pointers
with the host: libc, libm, GLES/EGL, pthread entry points, and framework
callbacks. A process boundary there would require per-symbol marshalling for
over a thousand entry points. Flatpak confinement, the absence of a plugin
API, and the split launcher compensate for sharing an address space with the
engine.

The full design — including the bionic ABI hazards, the GameActivity
lifecycle, graphics and audio paths, sandbox arguments, and performance
budgets — is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Loader research

The first bring-up target is the Android loader path used by the reference
runtime. The analysis is performed under Unicorn in user mode; no target code
is executed natively, and emulated code issues no host syscalls.

Two results define the current state:

- The loader images have **no section headers**. Their dynamic symbols are
  reachable only by walking `PT_DYNAMIC`, `DT_SYMTAB`, `DT_STRTAB`, and the GNU
  hash table. `tools/dynsym.py` exists for that reason; section-header tools
  report an empty image.
- The `0xda830` dispatcher path is mapped through its `0xdc180`/`0xdc570`
  state machines. The normal constructor path does not reach the `0xdc0fd`
  handoff; the observed `0xdaaef` fallback flag is structurally zero under
  the normal table state. The focused handoff capture is a forced emulator
  continuation, not evidence of a working JIT handoff.
- With the constructor harness's bulk-XOR helper bypassed, the path advances
  into a statically linked zlib inflate stage. The dispatcher is therefore
  downstream of an unpacking step; the compressed input and destination are
  not yet mapped.

The `0xdaaef` regression test runs without the ELF, Unicorn, or generated
logs:

```bash
python3 -m unittest discover -s tools/emulation -p 'test_*.py' -v
```

It checks the captured normal state, every PID in the default Linux range,
representative `r14` values, and forced states that prove the model can
produce a nonzero flag. Current result: **4 tests pass**.

See [FINDINGS.md](tools/emulation/FINDINGS.md) for the handoff trace and
[STATE_MAP.md](tools/emulation/STATE_MAP.md) for the complete dispatcher map.

## Compatibility

There is no compatibility list yet, because no client runs. The v1 target is:

- x86-64 Linux, Flatpak distribution;
- Wayland first, X11 through `fallback-x11`;
- kernel 5.11+ with `syscall user dispatch`;
- GLES2 + EGL as the mandatory bring-up path;
- Vulkan as the optional/default-when-stable backend.

Not in v1: ARM hosts, Windows, macOS, Meta Quest/VR, Steam Deck-specific
tuning, Roblox Studio, or a plugin API. Some experiences require Android
Remote Attestation and will refuse to join with Roblox's error 318. That is a
permanent boundary of this project.

## Development

The analysis tooling is usable now. The runtime is not.

### Regression check

```bash
python3 -m unittest discover -s tools/emulation -p 'test_*.py' -v
```

No third-party Python packages are needed. The generated logs and capture
files are intentionally excluded from Git; the test carries the captured state
directly.

### Loader tooling

`tools/dynsym.py` reads dynamic symbols from a section-header-stripped ELF:

```bash
python3 tools/dynsym.py <path-to-elf> --summary
```

`tools/constructors.py` resolves `DT_INIT_ARRAY` constructors and disassembles
them with GOT/string annotations. See [tools/README.md](tools/README.md) for
the local REA toolchain and the dispatcher emulation harness.

### Rust workspace

`cargo check` does not pass yet. The workspace is committed as a scaffold so
the interfaces and ABI checks are visible before the loader is wired together.
There is no shippable binary.

## What Tonic will not do

| Non-goal | Reason |
| --- | --- |
| Defeat Hyperion, Play Integrity, or Android Remote Attestation | Not ours to break; affected experiences get Roblox's own error |
| Run modified APKs or inject into the engine | The engine stays unmodified and signature-checked |
| Broker Google or Roblox credentials | The runtime never holds a user's Google account |
| Fabricate a device identity | No Play device spoofing |
| Provide a plugin API | A plugin that reaches the engine socket is a security liability |
| Collect telemetry | Diagnostics stay local unless the user shares them |

## Disclaimer

Tonic is an independent interoperability and research project. It is not
affiliated with, authorized by, or endorsed by Roblox Corporation or
VinegarHQ. “Roblox” is a trademark of Roblox Corporation.

This repository does not include or distribute Roblox or Sober binaries,
APKs, firmware, cryptographic keys, or proprietary libraries. Users are responsible for
obtaining and using any binaries in accordance with applicable laws and their
respective license terms. The project does not promise that Roblox will
continue to permit non-Android hosts; if the platform blocks this approach,
the client stops working and the project will say so rather than evade the
block.

## License

Tonic is licensed under the **GNU General Public License, version 3 or later**
(GPL-3.0-or-later). The workspace declaration is in [Cargo.toml](Cargo.toml).

## Prior art

Tonic is only tractable because of open-source work that came before it:

- [mcpelauncher-linker](https://github.com/minecraft-linux/mcpelauncher-linker)
  (MIT) — the Android linker lineage this loader follows.
- [libjnivm](https://github.com/minecraft-linux/libjnivm) (MIT) — the JNI VM
  approach.
- [AOSP bionic](https://android.googlesource.com/platform/bionic/)
  (Apache-2.0/BSD) — the bionic ABI constants and behaviour.
- [AGDK GameActivity](https://github.com/android/games-samples) (Apache-2.0) —
  the activity, surface, input, and IME contract.
- [Cordial](https://github.com/luohoa97/cordial) (GPL-3.0) — published design
  notes and findings, read as prior art.
- [Sober](https://vinegarhq.org/Sober/) (VinegarHQ, closed source) — a behavioural
  reference for configuration, file layout, error surfaces, and the “native,
  no translation” stance.

The design brief records what is taken from each and what is deliberately not:
[BRIEF.md §6](BRIEF.md#6-prior-art-and-what-to-take-from-each).
