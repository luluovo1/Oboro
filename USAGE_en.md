# OLLVM-NDK Obfuscation Usage Manual

[English](./USAGE_en.md) | [简体中文](./USAGE.md)

> This document is the detailed supplement to the [README](./README.md), covering the **flag quick reference** and **before/after obfuscation comparisons** (IDA disassembly views / Graph View).
> For quick start, see [README · Quick Start](./README.md#quick-start).

## ⚠️ Flag Syntax Rule

Every LLVM option after `-mllvm` **must carry its own `-` prefix**:

```bash
# ✅ Correct
clang -O2 -mllvm -irobf-bcf file.c -o file

# ❌ Wrong (missing the leading -)
clang -O2 -mllvm irobf-bcf file.c -o file
```

---

## Flag Quick Reference

All obfuscation flags are passed to the compiler via `-mllvm -<flag>`.

| Flag | Value | Default | Description |
|:---|:---:|:---:|:---|
| **Entry** | | | |
| `-irobf` | bool | false | Master switch (use with a config file) |
| `-oboro-cfg` | string | "" | Path to a JSON obfuscation config file |
| `-irobf-level` | int | 0 | Default strength 0-3 for every pass that has a level; per-pass `level` in config wins |
| **OLLVM originals** | | | |
| `-irobf-indbr` | `[=table\|full\|dual]` | off | Indirect branches. No value = `table` (page table); `full` = unconditional `br` too; `dual` = two-target `blockaddress`. All three modes run in the late pipeline |
| `-irobf-icall` | bool | false | Indirect calls |
| `-irobf-indgv` | bool | false | Indirect global variables |
| `-irobf-fla` | bool | false | Control-flow flattening |
| `-irobf-cse` | bool | false | String encryption |
| `-irobf-cie` | bool | false | Integer constant encryption |
| `-irobf-cfe` | bool | false | Floating-point constant encryption |
| `-irobf-rtti` | bool | false | Erase MSVC RTTI |
| **New features** | | | |
| `-irobf-bcf` | `[=0..100]` | off | Bogus control flow v2. No value = strength 70 |
| `-irobf-decoy` | `[=0..100]` | off | Runtime decoy paths (independent of BCF). No value = 30% of sites become decoy diamonds, the rest pure poison |
| `-irobf-rename` | bool | false | Rename internal functions, globals and aliases. Only symbols that still exist are renamed (O1+ inlines most of them). Debug info is out of scope; use `-g0` or `strip --strip-debug` for release builds |
| `-irobf-aux` | `[=wrap,shuffle,split]` | off | Structural passes. No value = all three |

### Per-feature sub-config (config only)

Each feature accepts only its own fields; a field outside its domain prints a warning and is ignored.

| Feature | Field | Default | Meaning |
|:---|:---|:---:|:---|
| `indbr` | `mode` | `table` | `table` / `full` / `dual` |
| | `split` | 0 | Split blocks to at most N instructions before indirection |
| | `level` | 0 | Decryption loop layers 1-3 |
| `icall` / `indgv` / `cie` / `cfe` | `level` | 0 | Per-pass strength |
| `cse` | `shared` | false | One shared decryptor per module (size first) |
| `bcf` | `strength` | 70 | Site probability 0-100 |
| | `budget` | 16 | Absolute site cap per function (0 = none) |
| | `budget_pct` | 20 | Percentage of eligible blocks (0 = off) |
| `decoy` | `ratio` | 30 | Share of sites that become decoy diamonds (0-100); the rest are pure poison |
| | `pollute` | false | L3 value pollution |
| | `probe` | `__oboro_probe` | App-provided probe symbol |
| `aux` | `wrap` | 100 | Forwarding wrapper probability |
| | `shuffle` | true | Basic block layout randomisation |
| | `split` | 3 | Maximum splits per function |

Global fields: `seed` / `randomSeed`, `ptrauth`, `deny`, `patterns`.

### Boundaries of the auxiliary passes

| Item | Behaviour |
|---|---|
| `-irobf-aux=wrap` | 100% by default, size grows noticeably. Only ABI-safe functions are wrapped (`main`, varargs, `alwaysinline`, `byval`/`sret`/`inalloca` and the probe symbol are skipped) |
| `-irobf-aux=shuffle` | Reorders basic blocks only, never changes the CFG |
| `-irobf-aux=split` | At most `aux.split` cuts per function (default 3, max 7) |
| `-irobf-indbr` (all modes) | Runs in the late pipeline: at PipelineStart the later SimplifyCFG folds single-target `indirectbr` back into `br` (39 branches became 13 in testing). The trade-off is that the decryption code is no longer optimized, so the binary is 10-20% larger than an early mount |
| `-irobf-indbr=dual` | Two-target `blockaddress`, **no block splitting** (`indbr.split` has no effect in dual mode), mutually exclusive with page-table mode |

Hidden testing switches (never for production): `-irobf-bcf_pred`, `-irobf-bcf_topo`, `-irobf-force-decoy`, `-irobf-force-real`, `-irobf-debug-names`.

---

## Supported Flags in Detail

### Basics

| Flag | Description |
|---|---|
| `-mllvm -irobf` | Globally enable all obfuscation passes enabled in the config file |

---

### Control-Flow Obfuscation

#### Control-Flow Flattening (FLA)
```bash
-mllvm -irobf-fla
```
Puts all basic blocks of a function into a switch-loop dispatcher, hiding the original control-flow structure. The switch values are XOR-encrypted to defeat IDA value tracking.

> Functions with more than 50 basic blocks are skipped: flattening makes the dispatcher and PHI count explode (zlib `inflate`/`deflate` did not converge in 90s without the cap).

#### Bogus Control Flow (BCF) v2
```bash
-mllvm -irobf-bcf=70      # optional, per-block injection probability 0~100, default 70
-mllvm -irobf-bcf_pred=3       # optional, force predicate family 1~12 (0=random, testing)
```

Injects an **opaque-predicate diamond** into every basic block: the true edge runs the
original code, the false edge is a never-executed dead block carrying an
anti-decompiler payload. The predicate is chosen **at random per compilation** from
12 mathematical families (all wraparound-safe on 2^64 and pre-filtered against
InstSimplify folding), combined with randomized input transforms, randomized
polarity flips, and a 1-in-5 chance of a two-family composition.

Production weights only use the rule-engine-proof families (5/8 consecutive
products, 9/11 popcount, 12 eight-term product): measured with the d810 proxy
(`obftest/d810_proxy.py`), their rule-fold rate is **0%**. Families 1/2/3/4/7
(bit0 identities) and 6/10 (MBA identities) are foldable by a rule engine, so
their weights are zero and they remain reachable only via `-irobf-bcf_pred` for
regression tests.

The payload is randomized as well: AArch64 uses SP-convergence poisoning
(`add sp, sp, #random`, producing Hex-Rays `sp-analysis failed`); x86_64 uses random
byte sequences that create JUMPOUTs (jumping into the middle of an instruction).
The old fixed fingerprints (`#0x100` / `B8 11 11 11 11`) are gone.

**Effect**: IDA's graph view fills with diamonds, decompilation quality collapses or
fails outright; this is the strongest lever against automated pipelines and LLM-based
reverse-engineering agents.

```bash
# Force 100% injection on all blocks
clang -O2 -mllvm -irobf-bcf=100 test.c -o test
```

> Runtime safety: the predicate is mathematically always true, so the dead block is
> never executed. Safety comes from unreachability, not from "an unbalanced stack
> that happens to work".

**Exception handling**: functions using Itanium EH (Android/Linux,
`__gxx_personality_v0`) are instrumented normally, but `landingpad`/EH-pad blocks
and `invoke` terminators are never rewritten, so unwind edges and LSDA call-site
ranges stay intact. Scoped EH (Windows MSVC funclets / Wasm) is still skipped
entirely: calls inside a funclet require an operand bundle, and crossing funclet
boundaries with a diamond is not worth the risk.

#### decoy Anti-Emulation (independent mechanism, orthogonal to BCF, off by default)

decoy is a **runtime misleading mechanism independent of BCF**, not a BCF variant:
BCF's decision is a statically-true opaque predicate (against static analysis),
while decoy's decision is a **runtime probe result** (against emulators/debuggers)
and the decoy path genuinely executes when the environment is suspicious.  They
share the site/branch generation code but have completely different mathematical
foundations and purposes.

The toolchain performs **no environment detection of any kind**. Detection lives in
your app and is exposed through a weak symbol `__oboro_probe` (non-zero = real path,
zero = decoy path):

```c
// Your app source (not part of the toolchain repo)
extern "C" int __oboro_probe(void);
extern "C" int __oboro_probe(void) {
    // Your detection: emulator / cloud phone / debugger / tampering ... up to you
    return suspicious ? 0 : 1;
}
```

**Enabling**: `-irobf-decoy[=ratio]` turns it on globally (30% of functions by default), or use a
**function annotation** / **config pattern** for per-function control. decoy is its own
feature domain and does not depend on `-irobf-bcf`.

```c
__attribute__((annotate("+decoy")))          // enable decoy for this function (L1)
__attribute__((annotate("^decoy=50")))       // 50% of this function's sites become decoys
__attribute__((annotate("+decoy_pollute")))  // upgrade to L3 value pollution
```

```json
{ "patterns": [
  { "match": "Crypto::**", "bcf": { "enable": true, "decoy": 80, "decoy_pollute": true } }
] }
```

| Level | Behavior | Runtime result |
|---|---|---|
| **L1 reconverge** | Decoy block runs pure register noise, then falls into the real block which recomputes everything | **Fully correct** (trace/CFG noise only) |
| **L3 pollution** | Decoy block is a clone of the original with a safe constant mutation, jumping straight to the successor | **Wrong but executable** (the analyst gets untrustworthy results) |

L3 has hard def-use filters: if the mutated value can reach a division/remainder,
memory address, array index, call argument, branch condition, indirect jump,
FP→int conversion, or atomic operation, the site automatically falls back to L1.
At most 4 L3 sites per function by default.

**Transport**: two shares (`env ^ K1`, `env ^ K2`) whose keys are derived from
function addresses (ASLR-randomized) and never stored; both shares are verified on
every call, and a mismatch sets a sticky `tampered` flag that routes the rest of the
process through decoys. No runtime sampling.

Testing knobs (hidden): `-mllvm -irobf-force-decoy`, `-mllvm -irobf-force-real`.
The probe symbol comes from config: `"decoy": {"probe": "my_probe"}`.

> No probe, not initialized, or a probe with a wrong signature → the real path is
> used (fail-open), so artifacts stay stable on real devices, emulators, cloud
> phones, and any architecture.

**Deployment constraints (measured)**:

| Scenario | Result |
|---|---|
| probe and obfuscated code in the same TU / same .so | ✅ works (recommended; `hidden` visibility is enough) |
| multiple obfuscated .so files, each with its own probe | ✅ each binds its own probe (independent under RTLD_LOCAL, measured) |
| probe in a static `libprobe.a`, plain link | ❌ **not extracted** (the toolchain's weak definition already satisfies the reference) → decoy silently disabled |
| probe in a static lib + `-Wl,--whole-archive` | ✅ works (measured) |
| cross-.so dependency (A.so's probe used by B.so) | ❌ unsupported; the probe must be in the same link unit as each obfuscated .so |

---

### Indirection Obfuscation

#### Indirect Branches (INDBR)
```bash
-mllvm -irobf-indbr
-mllvm -irobf-level=1        # optional, encryption loop layers, higher = stronger
```

#### Indirect Calls (ICALL)
```bash
-mllvm -irobf-icall
```
Replaces direct function calls with calls indirected through the encrypted page table; the function address is decrypted dynamically at runtime.

#### Indirect Global Variables (INDGV)
```bash
-mllvm -irobf-indgv
```
Global variable accesses are indirected through the encrypted page table, preventing static localization of globals by reverse-engineering tools.

---

### Data Obfuscation

#### String Encryption (CSE)
```bash
-mllvm -irobf-cse
```
All string literals are only decrypted at runtime, defeating `strings` and direct plaintext extraction in IDA.

#### Integer Constant Encryption (CIE)
```bash
-mllvm -irobf-cie
-mllvm -irobf-level=1          # optional
```
Integer constants are protected with runtime decryption.

#### Floating-Point Constant Encryption (CFE)
```bash
-mllvm -irobf-cfe
```
Floating-point constants are encrypted.

---

### Others

#### RTTI Erasure (RTTI)
```bash
-mllvm -irobf-rtti
```
Erases C++ RTTI information, preventing reverse-engineering tools from recovering class structure from type info (experimental).

---

## Recommended Combinations

### Standard obfuscation (low performance impact)
```bash
-mllvm -irobf-cse \
-mllvm -irobf-icall \
-mllvm -irobf-indbr
```

### Strong obfuscation (medium)
```bash
-mllvm -irobf-fla \
-mllvm -irobf-icall \
-mllvm -irobf-indbr \
-mllvm -irobf-cse \
-mllvm -irobf-bcf=80
```

### Maximum obfuscation (full)
```bash
-mllvm -irobf-fla \
-mllvm -irobf-icall \
-mllvm -irobf-indbr \
-mllvm -irobf-level=1 \
-mllvm -irobf-indgv \
-mllvm -irobf-cse \
-mllvm -irobf-cie \
-mllvm -irobf-bcf=100
```

---

## Using a Config File (oboro) ⭐ Recommended

Managing policy through a JSON config file is recommended — **you only touch the build
script, never the source**:

```bash
-mllvm -oboro-cfg=obf_config.json
```

### Full example

```json
{
  "bcf":  { "enable": true, "strength": 70, "budget": 16, "budget_pct": 20 },
  "decoy": { "enable": true, "ratio": 30 },
  "fla":  { "enable": true },
  "cse":  { "enable": true },

  "seed": "0123456789abcdef0123456789abcdef",

  "deny": ["MyCodec::*", "vendor::**"],

  "patterns": [
    { "match": "crypto::aes::**", "decoy": { "ratio": 80, "pollute": true } },
    { "match": "License::verify", "decoy": { "ratio": 50 } },
    { "file": "*generated_*.cpp", "bcf": { "enable": false } }
  ]
}
```

### Fields

| Field | Meaning |
|---|---|
| `<pass>.enable` | On/off switch (`true`/`false`) |
| `indbr.mode` | `table` / `full` / `dual` |
| `indbr.split` | Split blocks to at most N instructions before indirection (0 = off) |
| `indbr.level` / `icall.level` / `indgv.level` | 0 = module-wide shared page table (size first), 1-3 = per-function table + decryption loop layers |
| `cie.level` / `cfe.level` | Encryption strength 0-3, default 2 (0 = a single subtraction, weakest) |
| `bcf.strength` | Site probability 0-100 (default 70) |
| `bcf.budget_pct` | Fraction of eligible blocks to protect, 0-100 (default 20). With `budget` also 0 it falls back to 16/20%, **not unlimited** |
| `bcf.budget` | Absolute BCF site cap (0 = none; min(pct, cap) applies) |
| `decoy.ratio` | Fraction of functions entering decoy paths (0-100, default 30) |
| `decoy.pollute` | L3 value pollution (default false) |
| `decoy.probe` | App-provided probe symbol (default `__oboro_probe`) |
| `aux.wrap` / `aux.shuffle` / `aux.split` | Wrapper probability / block layout randomisation / splits per function |
| `cse.shared` | `true` = one shared i8/i16 decryptor per module with runtime lengths (size first); default is one decryptor per string (anti-analysis first). **Config only; there is no command-line flag** |
| `seed` / `randomSeed` | Fixed 32-hex (16-byte) PRNG seed for **tests / audits / bug reproducers only**; unset means a fresh random seed per build (production default). Do not reuse a seed across versions |
| `deny` | **Red-zone list**: matched functions are never obfuscated, even by annotation |
| `patterns[].match` | Match demangled function names (class/namespace) |
| `patterns[].file` | Match the source file name (no path) |
| `patterns[].decoy.ratio` | Per-rule decoy ratio override |
| `patterns[].decoy.pollute` | Per-rule L3 switch override |
| `patterns[].bcf.strength` | Per-rule BCF probability override |
| `patterns[].bcf.budget_pct` | Per-rule BCF percentage (0 = inherit global) |
| `patterns[].bcf.budget` | Per-rule absolute BCF cap (0 = inherit global) |

> A field outside its feature domain prints a warning and is ignored (for example `level` under `fla`).

### Matching rules

| Pattern | Matches | Does not match |
|---|---|---|
| `test` | global `test` only | `Class::test`, `ns::test` |
| `Class::*` | one level of members under `Class` | globals, deeper nesting |
| `Class::**` | any depth under `Class` | globals |
| `**::test` | `test` at any scope (including global) | — |
| `**` | every function | — |

`*` never crosses `::`; `**` does (same model as ProGuard). Overloads are matched by
name without parameters (all overloads of the same name match); `operator*` contains
a literal `*` and cannot be matched exactly by a pattern — use a function annotation.

### Priority chain (more specific wins)

```
1. Red zone (built-in hard floor)   never obfuscated, annotations cannot override
2. deny list (config)               never obfuscated
3. Yellow zone (built-in default)   skipped unless unlocked by a per-function
                                    annotation or an exact-name pattern
4. Function annotation
5. Class/namespace pattern
6. File pattern
7. CLI flags (assembled by .mk / CMake)
8. Config global
9. Built-in default
```

### Built-in safety floor

| Level | Covered | Notes |
|---|---|---|
| 🔴 Red | weak functions (all STL template instances), C++ runtime glue (`__cxa_`/`__gxx_`/`_GLOBAL__`), static ctor/dtor list functions, `operator new/delete` | Never obfuscated; **annotations cannot override** (a compile-time warning is emitted) |
| 🟡 Yellow | constructors, destructors, other `operator`s | Skipped by default; only a per-function `+bcf` annotation or an **exact function name** pattern (no `*` at all) + `enable:true` unlocks them |

The safety floor applies uniformly to **all 8 obfuscation/encryption passes**
(BCF/FLA/INDBR/ICALL/INDGV/CSE/CIE/CFE) and cannot be bypassed from the command line.

### Structural safety skips

The following function/call shapes cannot coexist with CFG rewriting; every pass
skips them automatically (also not overridable by annotations or config):

| Shape | Reason |
|---|---|
| coroutine (`llvm.coro.*` / presplit) | state-machine protos and suspend points depend on the original CFG |
| convergence (`llvm.experimental.convergence.*`) | tokens must stay inside the convergence region |
| GC statepoint (`gc.statepoint/result/relocate`) | stack maps encode exact call sites |
| `inalloca` / `preallocated` | caller-owned argument storage; indirect calls change the ABI |
| `naked` / `returns_twice` | prologue / return contract forbids inserted blocks |
| FLA: functions with unreachable blocks | LowerSwitch does not terminate on unreachable cycles |
| FLA: allocas not at the entry top or outside the entry block | flattening can put an alloca and its use in different cases, breaking dominance |

---

## Before / After Obfuscation Comparisons

All comparison views below are IDA Pro disassembly views (Graph View).

---

### BCF Bogus Control Flow

**Source code**

<img src="images/code_bcf.png" width="800px">

| Original disassembly (no obfuscation) | After `-irobf-bcf=100` |
|:---:|:---:|
| <img src="images/bcf_org.png" width="400px"> | <img src="images/bcf.png" width="400px"> |

---

### FLA Control-Flow Flattening

**Source code**

<img src="images/code_fla.png" width="800px">

| Original disassembly (no obfuscation) | After `-irobf-fla` |
|:---:|:---:|
| <img src="images/fla_org.png" width="400px"> | <img src="images/fla.png" width="400px"> |

---

### INDBR Indirect Branches

**Source code**

<img src="images/code_indbr.png" width="800px">

| Original disassembly (no obfuscation) | After `-irobf-indbr -irobf-level=3` |
|:---:|:---:|
| <img src="images/indbr_org.png" width="400px"> | <img src="images/indbr.png" width="400px"> |

---

### ICALL Indirect Calls

**Source code**

<img src="images/code_icall.png" width="800px">

---

### CSE String Encryption

**Source code**

<img src="images/code_cse.png" width="800px">

---

### CIE Integer Constant Encryption

**Source code**

<img src="images/code_cie.png" width="800px">

---

### CFE Floating-Point Constant Encryption

**Source code**

<img src="images/code_cfe.png" width="800px">

---

## Verifying the Obfuscation

```bash
# Compile a plain version for comparison
clang -O2 test.c -o test_plain.exe

# Compile the obfuscated version
clang -O2 -mllvm -irobf-bcf=100 test.c -o test_bcf.exe

# Load both into IDA and compare the disassembly views (Graph View)
```
