# JIT dispatcher state maps

Target: installed `libloader.so` from `org.vinegarhq.Sober` 1.8.0
(`7b6430c7...62cb9d26`), SHA-256
`9fb3c201bcadca0fd22c0afdeff25af759aecc631f3816a2e63f6b0d147c3da5`.

All addresses are virtual addresses. `cl` means the low byte of `ecx`.
The full constructor path does not reach this chain in the current Unicorn
sandbox; it stops in allocator code at `0x13ed21`. The chain below was reached
by entering the handoff with its required context and tracing the state tables.

## 1. Entry into the chain

The outer function at `0xda830` sets up its obfuscated tables with:

```
0xda8a9  mov eax, 0x08d8d18c
0xda8ae  xor ecx, ecx
0xda8ba  xor edx, edx
```

Its JIT handoff is:

```
0xdc0fd  xor eax, eax
0xdc0ff  mov ebx, 0xad45d216
0xdc104  pxor xmm0, xmm0
0xdc108  lea r14, [rsp+0x250]
0xdc110  jmp 0xdc15b
0xdc15b  cmp ebx, 0xad45d216
0xdc161  je 0xdc180
```

Before `0xdc0fd`, the block at `0xdc0cc` sets the pointers/constants used by
the later table and checks the data-dependent handoff gate:

```
0xdc0f4  cmp rax, rdx
0xdc0f7  jne 0xdc82d
```

If `rax == rdx`, the direct handoff is `0xdc0fd`. If not, `0xdc82d` can still
reach `0xdc0fd`:

```
0xdc82d  movabs rax, 0xba2d8279b70bf69f
0xdc837  mov [rsp+0x250], rax
0xdc83f  lea rax, [rsp+0x250]
0xdc847  mov rax, [rsp+0x4a0]
0xdc84f  test [rsp+0x250], rax
0xdc857  je 0xdc0fd
0xdc85d  cmp byte [rsp+0x18], 0
0xdc862  jne 0xdc0fd
```

### Observed direct-entry gate

A direct `0xda830` run reaches `0xdc0cc` with:

```
rax = 0x528a9f7829eca2f7
rdx = 0x1fad
ecx = 0xa3c6ed30
```

`rax != rdx`, so it takes `0xdc82d`. At that point the relevant stack slots are:

```
[rsp+0x4a0] = 0x528a9f7829eca2f7
[rsp+0x18]  = 0
[rsp+0x10]  = 1
```

The fallback test is:

```
0xba2d8279b70bf69f & 0x528a9f7829eca2f7
  = 0x120882782108a297 != 0
```

and `[rsp+0x18] == 0`, so neither `0xdc857` nor `0xdc862` jumps to
`0xdc0fd`. The run follows `0xdc868`, performs a `gettid` syscall, writes the
103-byte canary buffer, resets the outer table at `0xdc8cb`, and later stops
in allocator code at `0x13ed06`. **The unmodified direct entry does not reach
the `0xdc0fd` handoff in this environment.** The equality path is conditional,
not the normal entry path.

### `0xdb750` / `0xdb9d1` hash derivation

The 64-bit value tested at `0xdc0f4` is built by two update sites. All 512
`0xdb9d1` events and 40 `0xdb750` events from the direct run were logged in
`tools/emulation/hash_trace.log`:

```
0xdb9d1:
    rbp  = 0x115 + gettid * (slot + index)
    hash ^= rbp

0xdb750:
    hash = rol64(hash, 3) ^ 0x2ea951568e4b9f81
```

`slot` is `[rsp]` and runs from 0 through 15; `index` is `r14` and runs from 0
through 31. `gettid` is the result of syscall `0xba`; the harness returns
`4242` (`0x1092`), so `r13=0x1092`. The rotate is reached on odd `slot` values
at indices 3, 10, 17, 24, and 31. The formula reproduced every logged `rbp`
and every hash transition with zero mismatches; the final value is:

```
hash = 0x528a9f7829eca2f7
```

`rdx` is independent of this hash. The `0xdbef0` decoder is driven only by
constants and its initial `ecx=0xac7cbdff`, and terminates with
`rdx=0x1fad`. The equality test therefore requires the 64-bit hash to be
exactly the small fixed value `0x1fad`.

The other fallback condition comes from a separate flag, not from the hash.
At `0xdaa80`, `r12=0`; the table path to `0xdaaef` has `rax=0x1092` (the
gettid value), `r12=0`, and `r14=1`, with `[rsp+0x250]=1`. `0xdaaef` computes:

```
rcx = key ^ r14          ; key = 0x7afc4394e610c6e4
rdx = r14 ^ r12          ; r12 = 0
or rdx, rcx
sete cl
cmp rax, r12
setl bl
or bl, cl
```

`sete cl` is structurally zero: with `r12=0` and a nonzero key, `rdx|rcx`
is nonzero whether `r14` is zero (then `rcx=key`) or nonzero (then `rdx=r14`).
`setl bl` is also zero because `rax=0x1092 > 0=r12`. Thus `bl=0` regardless
of the initialized `r14` value. `0xdad94` stores this zero into
`[rsp+0x250]`; `0xdadae` copies it to `[rsp+0x18]`; `0xdadd2` sets
`[rsp+0x10]=1`. The memory-write trace shows no later write to
`[rsp+0x18]` before `0xdc0cc`.

The full default Linux PID range (`1..4194304`) was replayed through the
derived update sequence:

```
checked=4194304  hash==0x1fad: 0  (hash & 0xba2d8279b70bf69f)==0: 0
```

No value in that range selects either the equality route or the mask-zero
fallback, and the separate flag is structurally zero (see below). The unmodified table state
therefore cannot select `0xdc0fd`; the observed canary path is the actual
result, not a harness artifact.

Effective handoff state:

```
eax = 0
ebx = 0xad45d216
ecx = whatever the table left in ecx
edx = whatever the table left in edx
r14 = rsp + 0x250
```

`0xdc15b` immediately selects `0xdc180` because `ebx` already equals
`0xad45d216`.

## 2. `0xdc180`: stub-builder selector

Entry:

```
0xdc180  mov eax, 0x7dc1d493
0xdc185  xor ecx, ecx       ; cl = 0
0xdc187  xor edx, edx       ; edx = 0
0xdc189  jmp 0xdc1a0
```

The selected path is a straight ten-state chain:

| # | `eax` | `cl` | `edx` | case | operation | next `eax` |
|---:|---|---|---|---|---|---|
| 0 | `7dc1d493` | `00` | `00000000` | `dc1f9` | `cl=e5`, `edx=d48c3cbf`, `eax^=edx` | `a94de82c` |
| 1 | `a94de82c` | `e5` | `d48c3cbf` | `dc28f` | `cl+=f6`, `edx=a8811cb7`, `eax^=edx` | `01ccf49b` |
| 2 | `01ccf49b` | `db` | `a8811cb7` | `dc262` | `cl=perm(cl)`, `edx=b62cd877`, `eax^=edx` | `b7e02cec` |
| 3 | `b7e02cec` | `db` | `b62cd877` | `dc222` | `cl=perm(cl)`, `edx=7c8ceccb`, `eax^=edx` | `cb6cc027` |
| 4 | `cb6cc027` | `db` | `7c8ceccb` | `dc2f8` | `cl+=46`, `edx=232af567`, `eax^=edx` | `e8463540` |
| 5 | `e8463540` | `21` | `232af567` | `dc1cb` | `cl+=6f`, `edx=f48e9f98`, `eax^=edx` | `1cc8aad8` |
| 6 | `1cc8aad8` | `90` | `f48e9f98` | `dc307` | `edx=c511968f`, `eax^=edx` | `d9d93c57` |
| 7 | `d9d93c57` | `90` | `c511968f` | `dc29e` | `cl=perm(cl)`, `edx=2f00c023`, `eax^=edx` | `f6d9fc74` |
| 8 | `f6d9fc74` | `09` | `2f00c023` | `dc2cb` | `cl=perm(cl)`, `edx=90303a4c`, `eax^=edx` | `66e9c638` |
| 9 | `66e9c638` | `90` | `90303a4c` | `dc18b` | `cmp eax,66e9c638` | `0xdc320` |

`perm(cl)` is the nibble/bit-pair permutation at `0xdc222`/`0xdc262`:

```
rol cl,4
cl = ((cl & 0x33) << 2) | ((cl >> 2) & 0x33)
cl = ((cl & 0x55) << 1) | ((cl >> 1) & 0x55)
```

It maps `90 -> 09` and `09 -> 90`; `db` is a fixed point.

Dispatch conditions (`0xdc1a0`, signed comparisons):

```
eax > f6d9fc73        -> dc1e0
eax <= cb6cc026       -> dc210
eax == cb6cc027       -> dc2f8
eax == d9d93c57       -> dc29e
eax == e8463540       -> dc1cb
else                   xor eax,edx; loop

dc1e0: eax <= 1cc8aad7 -> dc250
       eax == 1cc8aad8 -> dc307
       eax == 7dc1d493 -> dc1f9
       else            -> dc18b
dc210: eax == a94de82c -> dc28f
       eax == b7e02cec -> dc222
       else            -> xor eax,edx; loop
dc250: eax == f6d9fc74 -> dc2cb
       eax == 01ccf49b -> dc262
       else            -> xor eax,edx; loop
dc18b: eax == 66e9c638 -> dc320
       else            -> xor eax,edx; loop
```

The target predicate is therefore exactly:

```
0xdc18b: cmp eax, 0x66e9c638
0xdc190: je  0xdc320
```

The `0xdc320` block consumes the final `cl=0x90`:

```
0xdc320  movzx eax, cl
0xdc323  movd xmm1, eax
0xdc327  pshufb xmm1, xmm0     ; zero xmm0 -> all bytes = cl
0xdc32c  movdqa [rsp+0x250], xmm1
0xdc335  ... 12 stores of 0x90
0xdc395  mov ecx, 0x70df2a3a
0xdc39a  xor eax, eax
0xdc39c  xor edx, edx
0xdc39e  jmp 0xdc400
```

Resulting buffer: twelve `90` bytes followed by four `00` bytes.

## 3. `0xdc400`: bridge from stub builder to mprotect selector

The selected path starts with `ecx=0x70df2a3a`, `eax=0`, `edx=0`.

| # | `ecx` | case | operation | next `ecx` |
|---:|---|---|---|---|
| 0 | `70df2a3a` | `dc428` | `edx=9fa32a31`, `eax=r8`, `ecx^=edx` | `ef7c000b` |
| 1 | `ef7c000b` | `dc3a0` | transform `rax`, `edx=c9152ed8`, `ecx^=edx` | `26692ed3` |
| 2 | `26692ed3` | `dc4e1` | `shld rax,rax,26`, `edx=fcaf2a58`, `ecx^=edx` | `dac6048b` |
| 3 | `dac6048b` | `dc4d2` | `add rax,rdi`, `edx=57daff6a`, `ecx^=edx` | `8d1cfbe1` |
| 4 | `8d1cfbe1` | `dc4c1` | `shld rax,rax,39`, `edx=1a6baf5a`, `ecx^=edx` | `977754bb` |
| 5 | `977754bb` | `dc45c` | `bswap rax`, `edx=7cb3b7ed`, `ecx^=edx` | `ebc4e356` |
| 6 | `ebc4e356` | `dc4b0` | `shld rax,rax,24`, `edx=f2d2b881`, `ecx^=edx` | `19165bd7` |
| 7 | `19165bd7` | `dc484` | `xor rax,r9`, `edx=7dc44701`, `ecx^=edx` | `64d21cd6` |
| 8 | `64d21cd6` | `dc4f2` | compare; equal -> `dc4fa` | `5459b603` |

At `0xdc4fa` the bridge seeds the next table and jumps:

```
0xdc4fa  mov ecx, 0x5459b603
0xdc4ff  xor edx, edx
0xdc501  xor esi, esi
0xdc503  movabs r8, 0x4433cb4e25169056
0xdc50d  jmp 0xdc570
```

`0xdc3a0` ends with a 13-byte NOP at `0xdc3f3` and falls through to
`0xdc400`; `0x26692ed3` is a real logical state but not a separate block-hook
event. The same is true of `0x79fbc18b` in the next table.

## 4. `0xdc570`: mprotect-target selector

Selected path from `ecx=0x5459b603`:

| # | `ecx` | case | operation | next `ecx` |
|---:|---|---|---|---|
| 0 | `5459b603` | `dc752` | `rdx=r8`, `esi=dab31dc7`, `ecx^=esi` | `8eeaabc4` |
| 1 | `8eeaabc4` | `dc772` | `bswap rdx`, `esi=b6631f79`, `ecx^=esi` | `3889b4bd` |
| 2 | `3889b4bd` | `dc5ac` | `perm(rdx)`, `esi=3e5fe8d7`, `ecx^=esi` | `06d65c6a` |
| 3 | `06d65c6a` | `dc743` | `rdx+=r12`, `esi=8506f6ae`, `ecx^=esi` | `83d0aac4` |
| 4 | `83d0aac4` | `dc50f` | `perm(rdx)`, `esi=fa2b6b4f`, `ecx^=esi` | `79fbc18b` |
| 5 | `79fbc18b` | `dc6c4` | `bswap rdx`, `esi=0cc5de9f`, `ecx^=esi` | `753e1f14` |
| 6 | `753e1f14` | `dc792` | `shld rdx,rdx,1a`, `esi=6d91bf7d`, `ecx^=esi` | `18afa069` |
| 7 | `18afa069` | `dc781` | `shld rdx,rdx,1a`, `esi=adf60d64`, `ecx^=esi` | `b559ad0d` |
| 8 | `b559ad0d` | `dc761` | `shld rdx,rdx,31`, `esi=2515cb07`, `ecx^=esi` | `904c660a` |
| 9 | `904c660a` | `dc640` | `perm(rdx)`, `esi=417289ee`, `ecx^=esi` | `d13eefe4` |
| 10 | `d13eefe4` | `dc6eb` | `perm(rdx)`, `esi=1f8d0792`, `ecx^=esi` | `ceb3e876` |
| 11 | `ceb3e876` | `dc7a3` | compare; equal -> `dc7c0` | mprotect |

Dispatch conditions (`0xdc570`, signed comparisons):

```
signed(ecx) <= 06d65c69  -> dc610
signed(ecx) >  5459b602  -> dc6a0
ecx == 06d65c6a          -> dc743
ecx == 18afa069          -> dc781
ecx == 3889b4bd          -> dc5ac
else                      -> dc7ab

dc610: signed(ecx) > b559ad0c -> dc6d3
       ecx == 83d0aac4        -> dc50f
       ecx == 8eeaabc4        -> dc772
       ecx == 904c660a        -> dc640
       else                    -> dc7ab

dc6a0: ecx == 5459b603 -> dc752
       ecx == 753e1f14 -> dc792
       ecx == 79fbc18b -> dc6c4
       else             -> dc7ab

dc6d3: ecx == b559ad0d -> dc761
       ecx == d13eefe4 -> dc6eb
       else             -> dc7a3

dc7a3: ecx == ceb3e876 -> dc7c0
       else             -> dc7ab
```

The `dc7ab` fallback is `xor ecx,esi; jmp 0xdc570`; the selected chain does
not take it.

At `0xdc7c0`:

```
0xdc7c0  lea rsi, [rax+rdx]
0xdc7c4  add rsi, 0x10
0xdc7c8  mov eax, 10          ; mprotect
0xdc7cd  mov edx, 5           ; PROT_READ|PROT_EXEC
0xdc7d2  mov rdi, r14
0xdc7de  syscall
0xdc806  call r14
```

## 5. Conditional handoff path

This is the chain that follows once `0xdc0fd` is selected. It is **not** the
direct-entry outcome above; it requires the `0xdc0f4` equality or one of the
`0xdc857`/`0xdc862` fallback conditions.

```
0xda830  outer tables (data-dependent)
   -> 0xdc0cc  seed r12/rdi/r8/r9
   -> 0xdc0f4  cmp rax,rdx
   -> 0xdc0fd  eax=0; ebx=ad45d216; r14=rsp+0x250
   -> 0xdc15b  cmp ebx,ad45d216
   -> 0xdc180  eax=7dc1d493; cl=0; edx=0
   -> 0xdc1a0  ten-state 0xdc180 chain
   -> 0xdc320  build 12 NOPs + 4 zero bytes
   -> 0xdc400  nine-state bridge
   -> 0xdc4f2  ecx=5459b603
   -> 0xdc570  eleven-state selector
   -> 0xdc7a3  ecx=ceb3e876
   -> 0xdc7c0  mprotect(r14, length, PROT_READ|PROT_EXEC)
   -> 0xdc806  call r14
```

The two state sequences in compact form:

```
0xdc180 eax:
7dc1d493 a94de82c 01ccf49b b7e02cec cb6cc027
e8463540 1cc8aad8 d9d93c57 f6d9fc74 66e9c638

0xdc570 ecx:
5459b603 8eeaabc4 3889b4bd 06d65c6a 83d0aac4
79fbc18b 753e1f14 18afa069 b559ad0d 904c660a
d13eefe4 ceb3e876
```

The first branch that selects `0xdc320` is `0xdc190` from `0xdc18b`, after
the ten-state chain. The final branch that selects `0xdc7c0` is `0xdc7a9`
from `0xdc7a3`, after the eleven-state chain. Reaching either requires the
conditional `0xdc0fd` entry first.

## Caveats

- Direct entry from `0xda830` reaches `0xdc0cc` but does not reach
  `0xdc0fd`; the observed gate values are recorded above.
- The `0xdc0fd -> 0xdc320 -> 0xdc570 -> 0xdc7c0` chain is conditional/forced;
  it requires the handoff gate conditions, not just the normal entry state.
- `0xdc39a`/`0xdc39c` force `eax=0` and `edx=0` before the bridge; the
  register state at `0xdc7c0` still depends on the preceding table's `r8`,
  `r12`, and `rdi` values.
- `0xdc320` stores the 16-byte stub at `[rsp+0x250]`. `r14` is not
  page-aligned, so a real Linux `mprotect` on that address returns `EINVAL`;
  the Unicorn hook returns success and the call trace is a forced continuation
  after the failed protection change.
