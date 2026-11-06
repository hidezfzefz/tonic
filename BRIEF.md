# Brief — Tonic: a native Roblox runtime for Linux

**Codename:** Tonic (a sober drink; the name is a placeholder).
**Status:** Draft v1, 2026-11-06. Nothing built yet.
**Companion document:** [ARCHITECTURE.md](ARCHITECTURE.md) — the runtime design this brief scopes.

---

## 1. The problem

Roblox does not ship a Linux client, and its Windows client no longer runs under Wine since
Hyperion. The main route for most people is **Sober**, VinegarHQ's closed-source runtime for
the **Android** build of Roblox. Sober is good, but:

- it is closed source, so nobody outside VinegarHQ can audit what runs with their session;
- it is Flatpak-only by policy, with no library API and no plugin surface, so nothing can build on it;
- it has no public specification of the Android→Linux gap it bridges, so every alternative
  rediscovers the same ground.

A second, open implementation exists — **Cordial** (GPL-3.0, Rust) — and it proves the
approach is tractable. This project asks a narrower question: *what would it take to rebuild
that runtime from scratch, as a specified, auditable system?* The deliverable of this phase is
a brief and an architecture, not a shipping client.

---

## 2. What "reverse engineer Sober" means here

Three different activities get called reverse engineering. Only two are in scope.

| Activity | In scope | Why |
|---|---|---|
| **Behavioural specification** — observe Sober's documented config, file layout, UI states, error surfaces, and the Android build's own interfaces | Yes | Public docs, the app's own config, and the APK's exported JNI surface are fair game and sufficient |
| **Clean-room reimplementation** — write our own runtime against that specification and against open-source prior art | Yes | This is the actual work; every component below is ours or a permissively licensed dependency |
| **Decompiling Sober's binaries** | **No** | Closed source, and unnecessary: the thing being bridged (Roblox's APK) is documented enough to work against directly |

We study Sober's *behaviour and public documentation*, and Cordial's *published design notes*.
We do not copy Sober's code (we cannot read it), and we do not copy Cordial's code unless we
accept its GPL-3.0 licence for the whole project (see §5, licensing).

Equally important: **we do not modify, patch, or repackage Roblox's engine.** The runtime loads
`libroblox.so` exactly as Roblox signed it, and the APK never leaves the user's machine.

---

## 3. Target user and platform

**Primary user:** a Linux desktop player on x86-64 with a Vulkan-capable GPU who wants to run
Roblox experiences without Wine, a VM, or an Android container, and who wants to be able to read
the code that holds their session.

**v1 platform:** x86-64 Linux, Flatpak, Wayland first with X11 as a supported fallback.
Kernel ≥ 5.11 (Sober's stated floor; the runtime depends on `syscall user dispatch`, which is
x86-64-only — the same constraint VinegarHQ cites for declining ARM).

**Deliberately not v1:** ARM hosts, Meta Quest / VR, Steam Deck-specific tuning, Windows, macOS.

---

## 4. Scope

### 4.1 In scope for v1

1. **First-run install** — automatic download of the official x86-64 Android build, or manual
   import of `base.apk` + `split_config.x86_64.apk`, with signature verification before
   anything is extracted.
2. **Sign-in** — Roblox account sign-in inside the client, including the "sign in on another
   device" flow, with tokens stored locally and never transmitted anywhere but Roblox.
3. **Launch an experience** — reach the app shell (landing), load an experience, render frames,
   play audio, leave cleanly.
4. **Desktop input** — keyboard and mouse with proper pointer capture, IME text entry with
   preedit, gamepad support behind an explicit permission toggle.
5. **Settings** — graphics mode (quality/balanced/performance), OpenGL fallback, HiDPI scaling,
   mobile-vs-desktop home screen, FastFlags, Discord RPC (off by default), GameMode.
6. **Profiles** — more than one account or build, isolated data directories, one engine process
   each.
7. **Diagnostics** — `--diagnostics`, structured logs, crash backtraces a user can paste into
   an issue, and a trace mode that names the native call that failed.
8. **Updater** — our own signed releases, plus a pinned, verified Roblox build store.

### 4.2 Out of scope (hard non-goals)

| Non-goal | Reason |
|---|---|
| Defeating Hyperion, Play Integrity, or Android Remote Attestation | Anti-cheat and attestation are not ours to break. Games that demand attestation will fail with Roblox's own error (318) and we will say so, not work around it. |
| Running modified APKs or injecting into the engine | The engine is loaded unmodified; asset overlays, if ever added, are the same non-destructive surface-level feature Sober and Bloxstrap already ship in the open. |
| Credential brokering / Google Play device spoofing | The runtime never holds a user's Google account or fabricates a device identity. |
| ARM64 or ARM→x86 translation | The Quest build ships no x86 code; emulating it is a different project with a bad GPU story. |
| Roblox Studio | Studio has no Android build; use Vinegar (Wine) for that. |
| Plugin API | A plugin that can reach the engine's socket is a security liability; v1 has none. |
| Multi-instance *within one process* | Profiles get separate processes, not a shared engine. |
| Telemetry | Off. Any diagnostics stay on disk unless the user pastes them somewhere. |

---

## 5. Constraints that shape everything

**C1 — The engine is 116 MB of stripped x86-64.** `libroblox.so` is `115,995,376` bytes, built
by NDK r28c for Android 26, stripped, and compiled to an **x86-64-v2 baseline**. It cannot be
debugged by reading; it can only be observed. Everything about the working method follows from
this: trace first, disassemble last.

**C2 — No CPU translation is needed on x86-64.** Roblox ships a complete x86-64 Android build
(`split_config.x86_64.apk`, 52.8 MB, `lib/x86_64/` with 11 objects). The runtime executes
Roblox's own machine code directly. Only **CPU feature gaps** (SSE4.2, POPCNT, BMI1) need
emulation, via a `SIGILL` handler — which is exactly what Sober's `libbadcpu.so` does.

**C3 — The Android surface is small but ABI-hostile.** 13 Android libraries in the `DT_NEEDED`
union and 644 undefined symbols, of which 490 are libc/libm/libdl. The hard part is not the
count; it is that **shared symbol names do not imply shared ABI** — bionic's `sysconf`
selectors, `pthread_cond_t` (32 vs 48 bytes) and `sem_t` (16 vs 32 bytes) all diverge silently.

**C4 — The framework contract is readable.** Roblox uses AGDK **GameActivity**, which is
Apache-2.0. The activity/surface/input/IME contract can be read instead of guessed. JNI is
registered **statically**: 693 `Java_*` exports resolve by name, so there is no
`RegisterNatives` table to recover.

**C5 — FastFlags are an interface, not a file format.** `com.roblox.client.flags.FlagJniInterface`
is a documented JNI surface; our settings layer should speak it rather than post-process config.

**C6 — Web content needs a web view.** Communities, Marketplace and Profile are WebView-hosted
activities (`RobloxWebActivity`). A real client needs an embedded browser and a cookie/bridge
story; Sober uses WebKitGTK for this. It is not optional polish.

**C7 — Attestation is a wall, not a bug.** Some experiences require Android Remote Attestation
and will refuse any non-Play-Integrity device. That boundary is permanent for this project.

**C8 — The target moves.** Roblox ships a new Android build every few weeks. Anything keyed to a
build's internals (addresses, offsets) is a bug waiting to happen; everything must be keyed to
symbols, exported interfaces, and documented behaviour.

**C9 — Licensing is a design input.** Cordial is GPL-3.0-or-later. If we read its code and
derive from it, we are a GPL-3.0 project. If we want a permissive licence, we must work from
AOSP bionic (Apache-2.0/BSD), `mcpelauncher-linker` (MIT), `libjnivm` (MIT), and the public
GameActivity sources, and not from Cordial's implementation. **Decision needed before the first
line of loader code** (see ARCHITECTURE §15, ADR-005).

**C10 — Distribution is part of the product.** Flatpak is the only sane target: a reproducible
runtime, a GPU device permission, and a sandbox that contains a 116 MB binary we did not write.
Sober reached the same conclusion for the same reason.

---

## 6. Prior art and what to take from each

| Project | Licence | What it is | What we take | What we do not |
|---|---|---|---|---|
| **Sober** (VinegarHQ) | Closed | The reference implementation: Android runtime for Roblox, Flatpak `org.vinegarhq.Sober` | The behavioural spec: config keys, file layout, error surfaces, install flow, the "no translation, X11/Wayland native" stance | Its binaries, its internals, its closedness |
| **Cordial** | GPL-3.0 | Open-source reimplementation in Rust; bionic linker + libjnivm, in-process engine load | Published findings (ABI divergences, API inventory, IPC shape, failure modes) as *reading*, subject to C9 | Code, unless we adopt GPL-3.0 |
| **mcpelauncher / minecraft-linux** | MIT | Android linker ported to Linux, bionic adaptations, JNI VM (`libjnivm`) | The loader and JNI VM, vendored as dependencies | Their app-specific glue |
| **ATL** (Android Translation Layer) | GPL-3.0 | Reimplements Android *framework* APIs on GTK4/desktop Linux | Design lessons on framework stubbing and app-per-process isolation | Its GTK-centric architecture; Roblox needs a game surface, not widgets |
| **Waydroid** | GPL-3.0 | Full Android container | Nothing architectural | The container: wrong resource profile, wrong GPU path |
| **Vinegar** | — | Roblox Studio on Linux via Wine | Proof that the Studio side is a separate, solved problem | Any part of it |

The single most useful conclusion from the prior art: **the hard part has open-source
precedent.** Sober's own attribution credits ChristopherHX, MCMrARM and AOSP — the
minecraft-linux stack. That is the difference between "write an Android linker" and "port and
adapt a working MIT-licensed one".

---

## 7. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Roblox blocks non-Play-Integrity clients entirely | Medium | Fatal | No evasion. Keep the client indistinguishable from an ordinary Android app in what it *does*; accept the outcome if it comes |
| R2 | Attestation-gated experiences become the norm | Medium | High | Document the boundary; do not promise what we cannot deliver |
| R3 | Engine update breaks the loader | High, recurring | Medium | Symbol-keyed integration, a build-pinned store, a canary build channel, fast rollback |
| R4 | bionic/glibc ABI mismatch surfaces in a new code path | High | Medium | Generated constant tables, compile-time layout asserts, differential tests against captured Android behaviour |
| R5 | Graphics bring-up stalls (NVIDIA, KWin/COSMIC, hybrid laptops) | High | High | GLES path first for bring-up, Vulkan behind a switch, a GPU matrix in CI-ish testing, honest per-driver status |
| R6 | Account action taken against users | Low (per VinegarHQ's public position) | High | No modification, no automation, no credential brokering; state the risk in the README |
| R7 | Licence contamination (GPL code into a permissive project) | Medium | Medium | C9 decision first; dependency allow-list; provenance file per vendored component |
| R8 | Sandbox escape via the engine or the web view | Low | High | Flatpak confinement, no host filesystem, WebKit in its own process, no plugins, seccomp where compatible |

---

## 8. Success criteria

Measured, not asserted:

1. **It runs.** Signed-in user reaches the landing screen, launches one experience, moves, hears
   audio, and exits cleanly — 20/20 consecutive launches on the reference machine.
2. **It is fast enough.** ≥ 60 fps at 1080p in a representative experience on a mid-range
   discrete GPU, with frame-time p99 within 1.5× of the Windows client on the same hardware.
   No number without a measurement and the machine it was measured on.
3. **It is stable.** Crash-free session rate ≥ 95% over a 7-day dogfood period; no unbounded
   memory growth in a 2-hour soak (< 5% RSS growth after warm-up).
4. **It is auditable.** A third party can reproduce the release binary from the published
   source and the pinned Flatpak runtime, and read every line that touches their session.
5. **It is honest.** Every known-broken area is listed in `STATUS.md` with an issue number, and
   no UI control exists that does nothing.

---

## 9. Milestones

| M | Name | Exit condition |
|---|---|---|
| **M0** | Spec and skeleton | This brief + architecture approved; licence decided; Flatpak skeleton builds and opens an empty window |
| **M1** | Engine loads | `libroblox.so` mapped by our linker, relocations resolved, static constructors complete, exit 0 — 100 consecutive runs |
| **M2** | App shell | JavaVM + GameActivity path reaches `APP_READY` (landing) with a real surface; no frame required yet |
| **M3** | Pixels | First rendered frame; EGL/GLES path green on Mesa; input moves the camera |
| **M4** | Playable | Sign-in, join by deep link, audio, IME, pointer capture, gamepad; 30-minute session without a crash |
| **M5** | Vulkan + settings | Vulkan backend default on capable GPUs, GLES fallback; full settings surface; profiles |
| **M6** | Ship | Security review closed, test matrix green, launch checklist done, Flatpak published |

The security review, test stage and launch checklist are **gates**, not milestones that can be
skipped by declaring the previous one done.

---

## 10. Open questions

1. **Licence:** GPL-3.0-or-later (can learn from Cordial directly) or permissive clean-room?
   Everything downstream depends on this. *Owner: project lead. Blocking for M1.*
2. **Build source:** user-supplied APK only, or signature-pinned third-party mirror, or Google
   Play with a device identity (Sober's route)? The mirror route is the only one that is both
   convenient and does not make us a credential broker — but it needs a pinned certificate and a
   clear warning. *Blocking for M0.*
3. **Window stack:** SDL3 for v1 (fast, batteries included) or native Wayland/xdg-shell from the
   start (more control, more work)? See ARCHITECTURE ADR-006.
4. **Web view:** WebKitGTK helper process, or defer Communities/Marketplace to an external
   browser in v1? Deferring is honest and smaller; not deferring is a better product.
5. **Profiles:** separate data directories only, or separate Flatpak installs? The former is
   simpler; the latter isolates tokens better.
6. **Naming and branding:** "Tonic" is a codename. A real name must not imply affiliation with
   Roblox or VinegarHQ, and must not be confusable with Sober.

---

## Sources

- Sober FAQ, Installation, Configuration, Troubleshooting — vinegarhq.org/Sober (accessed 2026-11-06).
- Cordial repository, `docs/findings.md`, `docs/analysis/roblox-build-architecture.md`,
  `docs/status.md`, `CONTRIBUTING.md` — github.com/luohoa97/cordial (GPL-3.0).
- Android Translation Layer — gitlab.com/android_translation_layer, NLnet project page.
- minecraft-linux (`mcpelauncher-linker`, `android_bionic`, `libjnivm`) — github.com/minecraft-linux.
- OMG! Ubuntu, "Play Roblox on Linux without Wine, using Sober", 2026-10-04.
- Roblox DevForum, "Roblox on Linux (Everything summarized in 1 post)", updated 2026.
- NixOS Wiki, "Sober"; Roblox Help, Android Remote Attestation.
