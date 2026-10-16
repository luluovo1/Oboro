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
| `-irobf-indbr` | bool | false | Indirect branches: jump targets decrypted at runtime, triggering IDA JUMPOUT · [before/after](#indbr-indirect-branches) |
| `-level-indbr` | int | 0 | Indirect-branch encryption loop layers (1 recommended, 3+ with caution) |
| `-irobf-icall` | bool | false | Indirect calls: function addresses decrypted at runtime · [before/after](#icall-indirect-calls) |
| `-level-icall` | int | 0 | Indirect-call encryption loop layers (1 recommended) |
| `-irobf-indgv` | bool | false | Indirect global variables: global access addresses decrypted at runtime |
| `-level-indgv` | int | 0 | Global-variable encryption loop layers (1 recommended; Lv3 is extremely costly) |
| `-irobf-cse` | bool | false | String encryption: C string literals decrypted at runtime · [before/after](#cse-string-encryption) |
| `-irobf-cie` | bool | false | Integer constant encryption (e.g. `0xDEADBEEF`) · [before/after](#cie-integer-constant-encryption) |
| `-level-cie` | int | 0 | Integer constant encryption strength |
| `-irobf-cfe` | bool | false | Floating-point constant encryption (double/float literals) · [before/after](#cfe-floating-point-constant-encryption) |
| `-level-cfe` | int | 0 | Floating-point constant encryption strength |
| `-irobf-rtti` | bool | false | Erase C++ RTTI type information (experimental) |
| `-samsara-cfg` | string | "" | Path to a JSON obfuscation config file |

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

#### Bogus Control Flow (BCF) ⭐ New
```bash
-mllvm -irobf-bcf
-mllvm -irobf-bcf_prob=70   # optional, injection probability 0~100, default 70
```
Injects a bogus branch guarded by an **opaque predicate** (`(x*(x+1))%2==0`, always true) into every basic block, building an **irreducible CFG**.

**Effect**: makes IDA Hex-Rays decompilation fail with `optimizations loop too much`.

Example:
```bash
# Force 100% injection on all blocks
clang -O2 -mllvm -irobf-bcf -mllvm -irobf-bcf_prob=100 test.c -o test
```

---

### Indirection Obfuscation

#### Indirect Branches (INDBR)
```bash
-mllvm -irobf-indbr
-mllvm -level-indbr=1        # optional, encryption loop layers, higher = stronger
```
Branch targets are XOR-decrypted at runtime through an encrypted page table, so IDA cannot statically resolve jump targets (triggers `JUMPOUT`).

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

## Using a Config File (samsara)

A JSON config file can be used instead of command-line flags:
```bash
-mllvm -samsara-cfg=obf_config.json
```

The config file allows per-function obfuscation levels; see the attribute annotation mechanism in `Flattening.cpp` / `ObfuscationOptions.cpp`.

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
