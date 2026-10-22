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

| Flag | Type | Default | Description |
|:---|:---:|:---:|:---|
| `-irobf` | bool | false | Globally enable obfuscation (used together with a config file) |
| `-irobf-fla` | bool | false | Control-flow flattening: scatter all basic blocks into a switch dispatcher · [before/after](#fla-control-flow-flattening) |
| `-irobf-bcf` | bool | false | Bogus control flow: inject branches that can never be taken · [before/after](#bcf-bogus-control-flow) |
| `-irobf-bcf_prob` | int | 70 | BCF injection probability (0-100); higher = denser protection |
| `-irobf-bcf_budget_pct` | int | 20 | Fraction of eligible blocks to protect per function, 0-100; 0 = no percentage (falls back to 20% when budget is also 0) |
| `-irobf-bcf_budget` | int | 0 | Absolute site cap (0 = none); when >0, the smaller of the two applies, and it applies alone when the percentage is 0 |
| `-irobf-indbr` | bool | false | Indirect branches: jump targets decrypted at runtime · [before/after](#indbr-indirect-branches) |
| `-level-indbr` | int | 0 | Indirect-branch encryption loop layers (1 recommended, 3+ with caution) |
| `-irobf-indbr_full` | bool | false | Route unconditional `br` through the encrypted page table too (full CFG edge indirection). Under O2, single-target `indirectbr` may be folded back; multi-target conditional edges survive |
| `-irobf-indbr_split` | int | 0 | Split basic blocks to at most N instructions before indirection (0 = off, max 256 new blocks per function) |
| `-irobf-icall` | bool | false | Indirect calls: function addresses decrypted at runtime · [before/after](#icall-indirect-calls) |
| `-level-icall` | int | 0 | Indirect-call encryption loop layers (1 recommended) |
| `-irobf-indgv` | bool | false | Indirect global variables: global access addresses decrypted at runtime |
| `-level-indgv` | int | 0 | Global-variable encryption loop layers (1 recommended; Lv3 is extremely costly) |
| `-irobf-ptrauth` | bool | false | AArch64 PAC: a module constructor signs indirect pointer tables and uses authenticate them (requires `+pauth`; off by default, opt-in only). Config key: `"ptrauth": true`. **Note**: incompatible with Darwin arm64e `-fptrauth-init-fini`, which signs existing ctor entries while this pass inserts a raw one; dyld authentication fails and the process crashes before `main` |
| `-irobf-cse` | bool | false | String encryption: C string literals decrypted at runtime · [before/after](#cse-string-encryption) |
| `-irobf-cie` | bool | false | Integer constant encryption (e.g. `0xDEADBEEF`) · [before/after](#cie-integer-constant-encryption) |
| `-level-cie` | int | 0 | Integer constant encryption strength |
| `-irobf-cfe` | bool | false | Floating-point constant encryption (double/float literals) · [before/after](#cfe-floating-point-constant-encryption) |
| `-level-cfe` | int | 0 | Floating-point constant encryption strength |
| `-irobf-rtti` | bool | false | Erase C++ RTTI type information (experimental) |
| `-oboro-cfg` | string | "" | Path to a JSON obfuscation config file |

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

#### Bogus Control Flow (BCF) v2
```bash
-mllvm -irobf-bcf
-mllvm -irobf-bcf_prob=70      # optional, per-block injection probability 0~100, default 70
-mllvm -irobf-bcf_budget_pct=20   # optional, protect 20% of eligible blocks (default)
-mllvm -irobf-bcf_budget=16       # optional, absolute cap; min(pct, cap) applies
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
clang -O2 -mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100 test.c -o test
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

**Eligibility gate**: decoy can only be enabled by a **function annotation** or a
**config pattern**. Command-line flags (.mk / CMake) can never open it — this prevents
one global flag from spreading decoy over every function.

```c
__attribute__((annotate("+bcf_decoy")))          // enable decoy for this function (L1)
__attribute__((annotate("^bcf_decoy=50")))       // 50% of BCF sites become decoys
__attribute__((annotate("+bcf_decoy_pollute")))  // upgrade to L3 value pollution
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

Testing knobs (hidden): `-mllvm -irobf-force-decoy`, `-mllvm -irobf-force-real`,
`-mllvm -irobf-probe-symbol=xxx`.

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
-mllvm -level-indbr=1        # optional, encryption loop layers, higher = stronger
```

#### Indirect Calls (ICALL)
```bash
-mllvm -irobf-icall
-mllvm -level-icall=1        # optional
```
Replaces direct function calls with calls indirected through the encrypted page table; the function address is decrypted dynamically at runtime.

#### Indirect Global Variables (INDGV)
```bash
-mllvm -irobf-indgv
-mllvm -level-indgv=1        # optional
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
-mllvm -level-cie=1          # optional
```
Integer constants are protected with runtime decryption.

#### Floating-Point Constant Encryption (CFE)
```bash
-mllvm -irobf-cfe
-mllvm -level-cfe=1          # optional
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
-mllvm -irobf-bcf -mllvm -irobf-bcf_prob=80
```

### Maximum obfuscation (full)
```bash
-mllvm -irobf-fla \
-mllvm -irobf-icall \
-mllvm -level-icall=1 \
-mllvm -irobf-indbr \
-mllvm -level-indbr=1 \
-mllvm -irobf-indgv \
-mllvm -irobf-cse \
-mllvm -irobf-cie \
-mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100
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
  "bcf":  { "enable": true, "level": 1 },
  "fla":  { "enable": true },
  "cse":  { "enable": true },

  "seed": "0123456789abcdef0123456789abcdef",

  "deny": ["MyCodec::*", "vendor::**"],

  "patterns": [
    { "match": "crypto::aes::**", "bcf": { "decoy": 80, "decoy_pollute": true } },
    { "match": "License::verify", "bcf": { "decoy": 50 } },
    { "file": "*generated_*.cpp", "bcf": { "enable": false } }
  ]
}
```

### Fields

| Field | Meaning |
|---|---|
| `<pass>.enable` | On/off switch (`true`/`false`) |
| `<pass>.level` | Encryption strength 0~3 (CIE/CFE/INDBR/ICALL/INDGV) |
| `bcf.budget_pct` | Fraction of eligible blocks to protect, 0-100 (default 20) |
| `bcf.budget` | Absolute BCF site cap (0 = none; min(pct, cap) applies) |
| `cse.shared` | `true` = one shared i8/i16 decryptor per module with runtime lengths (size first); default is one decryptor per string (anti-analysis first). **Config only; there is no command-line flag** |
| `seed` / `randomSeed` | Fixed 32-hex (16-byte) PRNG seed for **tests / audits / bug reproducers only**; empty means a random seed per build (production default). Never reuse one seed across releases |
| `deny` | **Red-zone list**: matched functions are never obfuscated, even by annotation |
| `patterns[].match` | Match demangled function names (class/namespace) |
| `patterns[].file` | Match the source file name (no path) |
| `patterns[].bcf.decoy` | decoy eligibility + ratio (0~100) |
| `patterns[].bcf.decoy_pollute` | L3 value-pollution switch |
| `patterns[].bcf.budget_pct` | Per-rule BCF percentage (0 = inherit global) |
| `patterns[].bcf.budget` | Per-rule absolute BCF cap (0 = inherit global) |

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

| Original disassembly (no obfuscation) | After `-irobf-bcf -irobf-bcf_prob=100` |
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

| Original disassembly (no obfuscation) | After `-irobf-indbr -level-indbr=3` |
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
clang -O2 -mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100 test.c -o test_bcf.exe

# Load both into IDA and compare the disassembly views (Graph View)
```
