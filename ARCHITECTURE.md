# Architecture — Tonic runtime

**Status:** Draft v1, 2026-11-06.
**Companion document:** [BRIEF.md](BRIEF.md).
**Scope:** how a Sober-style runtime is structured, why each layer exists, and what must be
measured before it can be claimed to work. No code yet; this is the design the code will follow.

---

## 0. The ten decisions, up front

| # | Decision | Consequence |
|---|---|---|
| D1 | Execute Roblox's x86-64 Android code **natively**; no binary translation | Only CPU *feature* gaps are emulated (`SIGILL` handler) |
| D2 | Load `libroblox.so` **into our own process** with a ported bionic linker | Engine and host share an address space and call each other by function pointer; no IPC marshalling of 1000+ symbols |
| D3 | **Never modify** the engine or the APK | Signature pinning is meaningful; anti-cheat posture stays defensible |
| D4 | **APK signature verified before extraction**, always | An untrusted mirror becomes acceptable; a corrupted build is impossible to install silently |
| D5 | **GLES2 + EGL is the mandatory path**; Vulkan is an optional upgrade | Bring-up is debuggable; "Future" lighting needs the Vulkan path but its absence cannot brick the client |
| D6 | Launcher and engine run in **separate processes**; the engine is never forked from the launcher | A hung engine cannot freeze the UI; profiles are trivially isolated |
| D7 | **Flatpak only** for v1 | Reproducible runtime, GPU device permission, sandbox around foreign code |
| D8 | **No plugin API**, no in-process scripting | Removes the largest realistic attack surface |
| D9 | **No attestation bypass** | Some experiences will refuse to join; documented, not worked around |
| D10 | Web content runs in a **separate WebKitGTK process** with a narrow bridge | Communities/Marketplace work without giving the engine's process a browser |

---

## 1. Principles

1. **Trace before you disassemble.** Log the call that failed, not the address it crashed at.
   Every wrapper we own is a place to put a name.
2. **Symbols, not offsets.** Nothing may depend on a build-specific address. If a fix cannot be
   expressed against an exported symbol or a documented interface, it is a workaround and gets
   an issue number and a removal plan.
3. **The engine is a black box we host, not a program we patch.** All adaptation happens in the
   layer beneath it.
4. **Fail visibly.** A missing stub must log and return a defined value; a silent `abort` costs
   more time than a wrapper costs anything.
5. **State the confidence.** `[verified]`, `[reported]`, `[inferred]` — every claim about the
   engine in our docs carries one. The Sober-OSS project is the cautionary tale: its behavioural
   observations held up, its architectural conclusions did not.

---

## 2. Process and component model

```
┌──────────────────────────┐        ┌──────────────────────────────────────────┐
│  tonic-shell (GTK4)      │  IPC   │  tonic-run  (one per profile)            │
│  launcher / settings /   │◄──────►│  ┌────────────────────────────────────┐  │
│  install / updates       │  unix  │  │ app shell: GameActivity lifecycle  │  │
└──────────────────────────┘ socket │  ├────────────────────────────────────┤  │
        │                           │  │ JNI VM (libjnivm) + framework stubs│  │
        │ spawns                    │  ├────────────────────────────────────┤  │
        ▼                           │  │ framework libs: libandroid, EGL,   │  │
┌──────────────────────────┐        │  │ GLES, OpenSL ES, liblog, jnigraphics│ │
│  tonic-web (WebKitGTK)   │        │  ├────────────────────────────────────┤  │
│  webview helper process  │        │  │ bionic/glibc shim + symbol table   │  │
└──────────────────────────┘        │  ├────────────────────────────────────┤  │
                                    │  │ bionic linker (ELF load, relocs)   │  │
                                    │  ├────────────────────────────────────┤  │
                                    │  │ libroblox.so  (unmodified, signed) │  │
                                    │  └────────────────────────────────────┘  │
                                    │  window · graphics · audio · input       │
                                    └──────────────────────────────────────────┘
```

**Why the engine is in-process (D2).** The engine and the host exchange raw function pointers:
the runtime hands `libroblox.so` host-provided `libm`, zlib, GLES2/EGL, pthread entry points and
hundreds of stubs as addresses. A process boundary there would need per-symbol marshalling for
over a thousand entry points, callbacks in both directions, and struct-layout translation on
every call. The cost is that the engine shares our address space — accepted, and compensated for
by Flatpak confinement, `seccomp` where compatible, and having no plugin surface (D8).

**Why the launcher is out-of-process (D6).** The launcher must survive an engine crash, report
it, and offer a restart. It also owns install/update, which must not be blocked by a hung game.
The shell may exit while a game runs; reopening reconnects over the same socket.

**IPC (`tonic.runtime/1`).** Length-prefixed JSON over `$XDG_RUNTIME_DIR/tonic/<profile>.sock`
(`SOCK_STREAM`), peer credentials checked with `SO_PEERCRED` (same UID, same sandbox). Messages:
`hello{protocol, pid, build}`, `launch{place_id, auth_token_ref, flags}`, `state{created →
engine_loaded → app_ready → in_experience → exited}`, `log{level, target, message}`,
`crash{signal, backtrace}`, `settings{...}`, `ping/pong`. Version skew is a hard error, not a
best-effort decode. JSON because a user can `socat` it and read it; there is no performance case
for binary here.

**Lifecycle.** `Created → EngineLoaded → AppReady(Landing) → InExperience → LeftExperience →
Exited`. Each transition is an IPC `state` event, so the launcher can distinguish "hung loading
the engine" from "hung starting the app" from "hung joining a place" — three different bugs that
otherwise all look like a black window.

---

## 3. Build acquisition and trust

### 3.1 Where the build comes from

Three routes, in order of preference:

1. **User-supplied APKs.** The user provides `base.apk` and `split_config.x86_64.apk`. Nothing is
   downloaded by us; the app explains why both files are needed (Sober's manual-install UI has
   the same requirement and the same "Invalid Bundle" failure when one is missing).
2. **Signature-pinned mirror.** We fetch from a third-party distributor, but only after verifying
   that Roblox signed the bytes. The mirror sees who asked; it cannot forge Roblox's key. This is
   the only convenient route that does not make us a credential broker.
3. **Google Play with a device identity.** Sober's route. Rejected for v1: it puts us in the
   business of holding somebody's Google authentication (BRIEF §4.2, R6).

### 3.2 Verification, before extraction

```
receive APK → parse ZIP → locate signing block (APK Signing Block v2/v3)
            → verify digests over the archive → extract leaf cert
            → compare cert against pinned Roblox certificate set
            → parse AndroidManifest (package com.roblox.client, versionCode, minSdk)
            → confirm split_config has lib/x86_64/ and the split's required versionCode matches base
            → only now: extract
```

Non-negotiables: verification happens on the **file**, not on a stream we are simultaneously
extracting; extraction writes into a fresh temp directory and is renamed into place; ZIP entries
are rejected for absolute paths, `..`, symlinks and duplicate names (zip-slip); the pinned
certificate set lives in the binary, not in user-writable config.

### 3.3 The build store

```
$XDG_DATA_HOME/tonic/builds/<abi>/<versionCode>/
    .content-sha256          # hash over the extracted tree
    .signer                  # cert fingerprint actually verified
    lib/x86_64/libroblox.so
    assets/…                 # whatever the engine expects to read
```

Content-addressed by *what it is*, keyed by `(abi, versionCode)`. Installs are atomic
(`renameat2(RENAME_NOREPLACE)`), old builds are retained for rollback, and the store is
append-only from the user's perspective: a failed update never leaves a half-written engine.
One profile pins one build; two profiles may run two different builds side by side.

### 3.4 Updates

Two independent trust roots, never conflated:

- **Our releases:** Ed25519-signed manifest, signature checked by the launcher before download,
  rollback on failure.
- **Roblox builds:** Roblox's APK certificate, pinned; version selection is explicit, and we
  never silently switch a profile to a newer engine because a mirror advertised one.

---

## 4. The runtime stack

Layers are ordered bottom-up; each is a crate with a narrow interface and its own tests.

### L0 — Host syscalls

The engine makes Linux syscalls directly, as an Android process would. On x86-64 we get
`syscall user dispatch`, which lets the runtime intercept the engine's `syscall` instructions
without a ptrace supervisor and re-dispatch the ones that differ between Android and desktop
Linux. This is the mechanism that makes "native, no emulator, no container" possible; it is also
why ARM is a different project.

Responsibilities: filter interesting syscalls (`openat`, `stat`, `futex`, `prctl`, `getrandom`,
`ioctl`), rewrite Android-specific paths (`/system`, `/data/data/<pkg>`, `/proc/self/…` views),
and pass everything else straight through at native speed.

### L1 — ELF loader

A port of the Android linker (the minecraft-linux `mcpelauncher-linker` lineage, MIT) with the
pieces a host loader needs:

- parse ELF headers, map `PT_LOAD` segments at their virtual addresses, apply `mprotect`;
- resolve `DT_NEEDED` against our symbol table, not the host's `ld.so`;
- relocate (RELA, IRELATIVE, TLS relocations), run `.init_array` constructors;
- set up TLS per bionic's layout, not glibc's;
- refuse a mismatched `e_machine` with a readable error (a real risk when a user supplies an
  arm64 APK).

Measured expectation from prior art: mapping and running all constructors of a 116 MB engine
takes tens of milliseconds, not seconds. `[reported]` — must be re-measured on our loader.

**`libbadcpu` (x86-64-v2 gap filler).** Installs a `SIGILL` handler, decodes the faulting x86-64
instruction, emulates it (POPCNT, MOVBE, LZCNT, TZCNT, ANDN, BLSI, BLSMSK, BLSR), advances `RIP`.
It must ship with a **differential test**: for each instruction, execute it natively on a capable
CPU and through the emulator, compare the full register file and flags. Prior art's version had
no correctness test at all — that is not acceptable here.

### L2 — bionic ↔ glibc shim

This is where most silent failures live. The rule: **shared symbol names do not imply shared ABI.**
Known divergences that must be handled by construction, not discovered by crash:

| Divergence | bionic | glibc | How it presents if unhandled |
|---|---|---|---|
| `sysconf` selectors | `_SC_PAGESIZE` = 39 | 39 = `_SC_BC_STRING_MAX` | Engine asks page size, gets 1000, allocator aborts. 145 of 147 constants differ → **generate** the table |
| `pthread_cond_t` | 32 bytes | 48 bytes | `pthread_cond_init` writes past the object during static init |
| `sem_t` | 16 bytes | 32 bytes | Same class of corruption |
| `__sF` (legacy stdio) | `FILE` array | absent | glibc walks its stream list at exit and reports an invalid handle *after* everything succeeded |
| TLS model | bionic layout | glibc layout | Relocations resolve, then thread-locals read garbage |
| `__cxa_atexit` / `atexit` ordering | bionic semantics | glibc semantics | Destructors run in the wrong order at shutdown |

Design: a generated constant table checked into the repo with the AOSP revision it came from, and
a compile-time layout assertion suite (`static_assert`, plus a Rust `const` check) that fails the
build if the host's structures drift. `--host-libc` may exist as a **diagnostic**, never as the
design.

### L3 — Framework libraries

Implemented as host libraries exposing Android's ABI, loaded by the linker into the engine's
namespace.

| Android library | What we provide | Notes |
|---|---|---|
| `libandroid.so` | `ANativeWindow`, `AAssetManager`, `ALooper`, `AConfiguration` | Small and fully specified; do it properly |
| `libEGL.so` / `libGLESv2.so` | Passthrough to Mesa with Android's config/attribute semantics | The mandatory graphics path (D5) |
| `libOpenSLES.so` | OpenSL ES → PipeWire | Roblox uses OpenSL ES, **not AAudio** `[reported]` |
| `liblog.so` | Structured logging into our ring buffer + stderr | The single most useful debugging surface |
| `libjnigraphics.so` | `AndroidBitmap_*` | Small |
| `libmediandk.so` | Stubs that log and fail cleanly | Off the startup path; video decode is v2 |
| `libzstd-jni`, `libeigen_blas`, `librenderscript-toolkit` | Present as shipped by the APK; loaded normally | Linked ≠ used; confirm with logging stubs |

Anything not implemented is a **logging stub that returns a defined failure**, counted in
`STATUS.md`. "Stubbed" must never mean "silently returns 0".

### L4 — JNI VM and the Java side

The engine is a native library with a Java shell around it. We need enough of a VM to satisfy it:

- `libjnivm` (MIT) provides `JavaVM`, `JNIEnv`, class/method resolution and object lifetimes.
- **Static registration**: 693 `Java_*` exports (518 in `libroblox.so`) resolve by symbol name, so
  our dispatcher maps `Java_<class>_<method>` to the engine's exported function; there is no
  `RegisterNatives` table to recover.
- **Framework classes** the engine touches are implemented in the VM layer (or in Kotlin/Java
  compiled ahead of time where a real class is simpler than a stub).
- **Initialisation order matters more than completeness.** `JNI_OnLoad` cannot be called in
  isolation: on Android the order is *VM → Java app → `GameActivity.initializeNativeCode` called
  from Java with a real Activity*. Calling `JNI_OnLoad` directly leaves engine globals null, and
  worker threads started earlier dereference them. The app shell (L5) is therefore part of the
  loader's correctness, not a finishing touch.
- **Exceptions escaping threads we did not start** cannot be caught; install a `terminate` handler
  that prints thread, `what()` and a backtrace. Without it the failure is a core dump with no
  information.

### L5 — App shell and the GameActivity contract

Roblox uses AGDK **GameActivity** (Apache-2.0), which is the best news in the project: the entire
activity/surface/input/IME contract is readable source.

Sequence to implement, in order:

1. Create `JavaVM`, install the framework stubs.
2. Construct the app's Java entry (`com.roblox.client` activity classes present in the dex).
3. Instantiate `GameActivity`, attach the native window, call `initializeNativeCode` **from Java**
   with a real Activity — exactly as Android would.
4. Drive lifecycle: `onCreate → onStart → onResume → onWindowFocusChanged → onSurfaceCreated →
   onSurfaceChanged(w,h) → onSurfaceRedrawNeeded`, and the matching teardown.
5. Pump input and IME events into the GameActivity input queue (`AInputEvent` structures with the
   correct `source`, `action`, `metaState` and timestamps).
6. Report `APP_READY` when the engine says so — not when we think it should.

FastFlags go through `com.roblox.client.flags.FlagJniInterface`, not through file patching. The
engine re-fetches its settings periodically; our override layer must answer that JNI call, and
must document that flags changed mid-session can be reverted by Roblox's own refresh.

### L6 — Window, input, IME

**Window.** One top-level surface per profile. Wayland (`xdg-shell`) first, X11 fallback.
Frameless vs decorated is a setting; fullscreen uses the compositor's fullscreen protocol, not a
borderless hack, so gamescope and KWin rules behave.

**Pointer.** Relative motion requires `zwp_relative_pointer_v1` + `zwp_pointer_constraints_v1`
(lock/confine). On X11, fall back to `XGrabPointer` + raw motion. Pointer capture must be
released by the same gesture that acquired it, including on crash (the launcher clears it).

**Keyboard.** `xkbcommon` keymap from the compositor; a table mapping evdev keysyms to Android
keycodes; modifier and repeat semantics tested against the engine's own expectations.

**IME.** `zwp_text_input_v3` where available; otherwise a GTK IM context in the webview helper or
a dedicated helper. Requirements: preedit visible, commit, delete-surrounding-text, and cursor
rect updates so candidate windows land near the caret. The prior art implements the text field as
a real GTK widget; that is a legitimate approach and should be evaluated before writing a custom
IME bridge.

**Gamepad.** evdev/SDL gamepad → Android `AInputEvent` with the right `AXIS_*` codes, behind the
`allow_gamepad_permission` toggle (default off, matching Sober's default). Glyph branding will be
wrong on non-Xbox pads; that is cosmetic and should be stated, not hidden.

**Touch.** Not emulated. Desktop mode is the product; `enable_mobile_home_screen` exists for users
who want the phone UI.

### L7 — Graphics

Two backends behind one interface, selected by setting with automatic fallback:

**GLES2 + EGL (bring-up path, always available).**
- `eglGetPlatformDisplay(EGL_PLATFORM_WAYLAND_KHR | EGL_PLATFORM_X11_KHR)`, ES2/ES3 configs with
  a depth/stencil buffer and the alpha mode the engine asks for.
- `ANativeWindow` wraps the `wl_surface`/`xcb_window_t`; `eglCreateWindowSurface` on it;
  `eglSwapInterval(1)` by default, 0 allowed.
- Mesa's GLES implementation is the driver; Zink is the compatibility answer when a driver's GLES
  is weak, and must be selectable.

**Vulkan (default once stable).**
- The engine `dlopen`s `libvulkan.so.1`; we provide a loader shim that enumerates the host ICD and
  adds `VK_KHR_wayland_surface` / `VK_KHR_xcb_surface` support.
- Surface creation from the native window handle, swapchain with FIFO (vsync) default and MAILBOX
  opt-in, `VK_KHR_present_wait` used when available for frame pacing.
- "Future" lighting and high quality settings require this path. If Vulkan fails, fall back to GLES
  and say so in the log and in the UI — never a black window.

**Deliberate omissions:** HDR, variable-rate shading, ray tracing, multi-GPU selection. All are
later, and none is promised.

**Known-hard matrix** (state per driver, do not average): Mesa RADV (AMD), ANV (Intel), NVIDIA
proprietary (Flatpak runtime extension required), llvmpipe (software, must warn), hybrid laptops
(render on the discrete GPU explicitly — `__NV_PRIME_RENDER_OFFLOAD`/`DRI_PRIME` documented, not
auto-magicked), KWin/COSMIC/wlroots window creation quirks.

### L8 — Audio

OpenSL ES is the engine's API; PipeWire is the host's graph (PulseAudio fallback).

- Buffer target 10–20 ms, stereo, 48 kHz; device changes handled without restarting the engine.
- Microphone is a **separate permission** (Flatpak `--device=all` is not acceptable; use the
  pulseaudio socket permission where the runtime supports it) and is off until the user enables
  voice chat.
- Volume, mute, and "audio device disappeared" are explicit states, not silent no-ops.

---

## 5. Launcher (tonic-shell)

GTK4 + libadwaita, one window: library/landing, install state, settings, diagnostics. It owns:

- first-run flow (choose automatic or manual install, verify, extract, progress);
- profile list and creation (each profile = data dir + pinned build);
- settings (the config keys below), FastFlags editor with validation;
- update checks for us and for Roblox builds;
- crash reporting UI (copy backtrace, open issue URL — no automatic upload).

It never touches the engine's memory, never loads `libroblox.so`, and never runs as the same
process as a game.

---

## 6. Configuration and profiles

Config is JSON at `$XDG_CONFIG_HOME/tonic/config.json`, flat, every key documented, defaults that
match the reference implementation where the key is the same:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allow_gamepad_permission` | bool | `false` | Enable gamepad input |
| `close_on_leave` | bool | `true` | Exit the game process when leaving an experience |
| `discord_rpc_enabled` | bool | `false` | Discord presence |
| `discord_rpc_show_join_button` | bool | `false` | Join button on presence |
| `enable_gamemode` | bool | `true` | Feral GameMode while running |
| `enable_hidpi` | bool | `false` | Scale with monitor DPI |
| `enable_mobile_home_screen` | bool | `false` | Phone UI instead of desktop UI |
| `fflags` | object | `{}` | FastFlags overrides (validated, applied over JNI) |
| `graphics_optimization_mode` | enum | `"balanced"` | `quality` / `balanced` / `performance` |
| `server_location_indicator_enabled` | bool | `false` | Show datacenter location on join |
| `renderer` | enum | `"auto"` | `auto` / `vulkan` / `opengl` |

Rules: unknown keys are preserved, not dropped; invalid JSON falls back to defaults with a visible
warning and the broken file kept as `config.json.bad`; a config write is atomic (temp + rename).
Profiles live at `$XDG_DATA_HOME/tonic/profiles/<id>/` with their own engine data, cookies and
local settings; the build store is shared and read-only to profiles.

---

## 7. Auth, secrets, and the web view

**Sign-in.** Roblox's own flow: in-app web sign-in and the "sign in on another device" code path.
We never see the password (it is typed into Roblox's page), and we never proxy it.

**Token storage.** `libsecret` when a keyring is available (Flatpak has a portal-backed secret
service); otherwise a `0600` file in the profile dir with an explicit warning in Settings. Tokens
are referenced by handle across IPC — the launcher asks the runtime to launch with a token *ref*,
never with the token in the message. No token, cookie or header is ever written to a log; the log
scrubber has a test that feeds it known-shaped secrets and asserts they are redacted.

**Web view.** WebKitGTK in `tonic-web`, a separate process, with:

- its own ephemeral data store per session, cookie jar shared with the engine **only** for Roblox
  domains and only through an explicit bridge;
- a narrow JS bridge: a fixed set of message names, JSON payloads, size-limited, no eval, no
  arbitrary file access;
- the window mapped to the engine's request via the IPC `open_web{url, rect}` message, and closed
  by the same lifecycle that opened it.

Communities, Marketplace and Profile are the reason this exists (BRIEF C6). If v1 defers them to
an external browser, the architecture stays valid; the shell just opens the URL instead.

---

## 8. Networking

- TLS via the runtime's own stack (BoringSSL or OpenSSL, whichever the Flatpak runtime pins), with
  the sandbox's CA bundle; no certificate pinning of our own — Roblox rotates endpoints.
- HTTP/2 where the engine asks for it; no transparent proxy of our own. `HTTP_PROXY`/`HTTPS_PROXY`
  from the environment are honoured and visible in `--diagnostics`.
- Clock skew breaks auth: `--diagnostics` reports host time, NTP sync state, and the offset the
  server reported.
- DNS failures, captive portals and IPv6-only networks get distinct, human error messages.

---

## 9. Flatpak sandbox

`finish-args`, deliberately minimal:

```
--share=network
--socket=wayland
--socket=fallback-x11
--socket=pulseaudio
--device=dri
--filesystem=xdg-run/pipewire-0
--talk-name=org.freedesktop.secrets        # token storage
--talk-name=org.freedesktop.portal.Desktop
```

No `--filesystem=home`, no `--device=all`, no `--allow=devel`, no host PID namespace. Manual APK
import goes through the **file chooser portal**, so we receive a file descriptor, not a path into
the user's home. The engine's data lives inside the sandbox; nothing it writes is visible to the
host.

Sandbox caveats to test, not assume: `syscall user dispatch` under the runtime's seccomp profile,
`prctl` availability, `/proc` visibility, and GPU device nodes for the NVIDIA runtime extension.

---

## 10. Observability

| Surface | Contents | Default |
|---|---|---|
| Structured log | JSON lines: level, target, message, build, profile | On, local only |
| Ring buffer | Last 5,000 engine-side events, dumped on crash | On |
| `--diagnostics` | GPU/ICD, driver, session type, kernel, seccomp, build store state, pinned cert fingerprint | On demand |
| `TONIC_TRACE=1` | Every wrapped libc/framework call with arguments and return values | Off |
| Crash handler | Signal, thread, `what()`, symbolized backtrace, last 20 log lines | On |

Symbolization needs the engine's stripped state handled honestly: we symbolize *our* frames and
report engine offsets, not fake names. Privacy: logs contain place IDs and timestamps, not tokens,
cookies, or account identifiers; `--export-logs` produces a scrubbed archive.

---

## 11. Security and threat model

**Assets:** the user's Roblox session, their local files, their machine.

**Adversaries:** a malicious APK or mirror; a malicious web page in the embedded browser; a
compromised dependency; a local unprivileged process; our own bugs.

| Threat | Control |
|---|---|
| Malicious APK / mirror | Signature pin **before** extraction; ZIP hardening; atomic install; no execution from the download directory |
| Engine exploit (it is 116 MB of foreign code) | Flatpak sandbox, no host filesystem, no plugin surface, seccomp where compatible |
| WebView compromise | Separate process, narrow bridge, no file access, ephemeral store |
| IPC spoofing | `SO_PEERCRED`, per-profile socket in `$XDG_RUNTIME_DIR`, protocol version handshake |
| Secret leakage | Token refs over IPC, log scrubber with tests, `0600` fallback, never in crash dumps |
| Supply chain | Vendored deps with provenance + licence files, pinned hashes, reproducible Flatpak build, `cargo deny`/`cargo audit` in CI |
| Update hijack | Ed25519-signed manifest for our releases; Roblox cert pin for builds; no silent build switching |
| Attestation pressure | Documented boundary (D9); no evasion code, ever |

**Explicit non-controls:** we do not attempt to detect or defeat debugging, VM detection, Play
Integrity, Hyperion, or any Roblox anti-cheat. If the platform decides a non-Android host is not
welcome, the client stops working and we say why.

---

## 12. Performance budgets

Targets for the reference machine (mid-range discrete GPU, 6-core CPU, 1080p), to be replaced by
measurements as soon as there are any:

| Metric | Budget |
|---|---|
| Launcher cold start → window | < 1.5 s |
| Engine map + relocations + constructors | < 150 ms |
| Install (verify + extract) | < 10 s for 150 MB |
| Frame time p99 in a representative experience | ≤ 1.5× Windows client on the same GPU |
| RSS after warm-up | < 2.0 GB |
| RSS growth over a 2-hour soak | < 5% |
| Input latency added by our layer | < 1 frame |

Rules: no performance claim without a method (machine, driver, scene, resolution, measured
percentile); numbers that contradict each other are reported as contradictory, not averaged.

---

## 13. Testing strategy

**Unit.** sysconf table vs a captured Android table (all 147 constants); struct-layout assertions;
ZIP hardening (traversal, symlink, duplicate, zip-bomb); signature verification with valid,
tampered, wrong-key and truncated fixtures; protocol encode/decode with version skew.

**Loader.** A synthetic ELF fixture exercising every relocation type; a real-engine smoke test that
maps `libroblox.so`, resolves relocations and runs constructors (skipped when no APK is present,
never vendored); 100-run loop for flakiness.

**Conformance.** GameActivity's own sample app must reach `APP_READY` before Roblox is attempted.
Android logcat traces from a real device are the golden reference for event ordering; compare
sequences, not timestamps.

**Graphics.** A matrix of `vulkaninfo` + first-frame + 10-minute run across RADV/ANV/NVIDIA/llvmpipe
and Wayland/X11. A backend that cannot create a swapchain must fall back and log, and the fallback
is itself a test.

**Input.** Scripted event replay (keyboard, pointer lock, IME commit, gamepad axes) with assertions
on what the app shell received; a 10,000-event fuzz for crashes and stuck modifiers.

**Soak.** 2-hour session, 20 join/leave cycles, memory and handle counts sampled; leaks fail the
build.

**Security.** Dependency audit, secret-scanning of logs, sandbox escape checklist (no host paths
reachable, no portal bypass), and a manual review of every place we parse untrusted bytes.

**Release gate.** The test stage is a gate: a release with a red matrix does not ship, and a known
failure is listed in `STATUS.md` with an issue link rather than hidden.

---

## 14. Failure-mode playbook

Symptom → first place to look. This table is the most valuable page in the repository during
bring-up.

| Symptom | Most likely layer | First check |
|---|---|---|
| `abort` during static constructors | L2 | `TONIC_TRACE=1`: `sysconf`, `pthread_cond_init`, `sem_init` |
| Everything resolves, then exit code 0 with no window | L1/L5 | Were constructors run? Was `initializeNativeCode` called from Java? |
| `JNI_OnLoad` hangs or throws on a worker thread | L4 | JavaVM global set before threads start? terminate handler installed? |
| Landing screen renders, join gives a black frame | L7 | Swapchain create result, surface format, `eglSwapBuffers` error |
| "Invalid Bundle" on manual install | L0/store | base + x86_64 split both present and version-matched? |
| Error 318 on join | — | Android Remote Attestation; out of scope, tell the user plainly |
| No window on KWin/COSMIC/wlroots | L6 | xdg-shell version, explicit sync, surface commit ordering |
| NVIDIA: crash before Vulkan loads | L7 | Flatpak GL runtime extension present? ICD matches the sandbox? |
| Audio crackles or dies on device change | L8 | PipeWire quantum, buffer size, device hotplug handling |
| Stuck modifier after alt-tab | L6 | Focus-out release path; pointer/keyboard grab cleanup |

---

## 15. Roadmap and decision log

Milestones are defined in BRIEF §9. The work order inside M1–M4:

1. Loader + symbol table + trace wrappers (M1).
2. bionic shim with generated constants + layout asserts (M1).
3. libjnivm + framework stubs to `APP_READY` (M2).
4. EGL/GLES surface + input (M3).
5. Auth, deep-link join, audio, IME, gamepad (M4).
6. Vulkan backend + settings + profiles (M5).
7. Security review, test matrix, launch checklist (M6).

**ADRs to write before the code they govern:**

| ADR | Question | Current lean |
|---|---|---|
| ADR-001 | Native x86-64 execution, no translator | Accept |
| ADR-002 | In-process engine load | Accept |
| ADR-003 | APK signature pin mandatory; mirror allowed | Accept |
| ADR-004 | No anti-cheat/attestation bypass | Accept (non-negotiable) |
| ADR-005 | Licence: GPL-3.0-or-later vs permissive clean-room | **Open — blocking** |
| ADR-006 | Window stack: SDL3 for v1 vs native Wayland | SDL3 for v1, native later |
| ADR-007 | Renderer order: GLES bring-up, Vulkan default | Accept |
| ADR-008 | Flatpak-only distribution | Accept |
| ADR-009 | One process per profile; shared read-only build store | Accept |
| ADR-010 | No plugin API in v1 | Accept |

---

## Sources

- Sober documentation (FAQ, Installation, Configuration, Troubleshooting), vinegarhq.org/Sober.
- Cordial `docs/findings.md`, `docs/analysis/roblox-build-architecture.md`, `docs/status.md`,
  `docs/fastflags.md`, `CONTRIBUTING.md` — github.com/luohoa97/cordial (GPL-3.0), read as prior
  art under BRIEF C9.
- AOSP bionic; AGDK GameActivity (Apache-2.0); `mcpelauncher-linker`, `android_bionic`,
  `libjnivm`, `fake-jni` (MIT).
- Android Translation Layer — gitlab.com/android_translation_layer, NLnet project page.
- Roblox Help, "Android Remote Attestation"; Roblox DevForum Linux summary thread.
- OMG! Ubuntu, "Play Roblox on Linux without Wine, using Sober", 2026-10-04.

Claims about the engine above are `[reported]` from the cited prior art unless marked otherwise;
none has been independently measured by this project yet. That is the first thing M1 changes.
