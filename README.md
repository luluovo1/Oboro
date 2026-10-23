# Oboro — Android NDK Obfuscator

[![Build NDK OLLVM Toolchain](https://github.com/luluovo1/Oboro/actions/workflows/build-ndk-ollvm.yml/badge.svg)](https://github.com/luluovo1/Oboro/actions/workflows/build-ndk-ollvm.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.TXT)
[![LLVM Version](https://img.shields.io/badge/LLVM-21.0.0-red.svg)](https://llvm.org/)
[![NDK Version](https://img.shields.io/badge/NDK-r30-green.svg)](https://developer.android.com/ndk)

<p align="center">
  <a href="./README.md"><img src="https://img.shields.io/badge/README-English-2980b9?style=for-the-badge" alt="English"/></a>
  <a href="./README.zh-CN.md"><img src="https://img.shields.io/badge/README-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-c0392b?style=for-the-badge" alt="简体中文"/></a>
</p>

> [!CAUTION]
> **⚠️ Important Notice: This repository is departing from upstream**
>
> Starting with commit [`7596be6`](https://github.com/luluovo1/Oboro/commit/7596be6880a2118c36d46953ecf4314fc4fa8829) (2026-10-16 17:44 UTC), this repository will **gradually detach from LLVM upstream ([llvm/llvm-project](https://github.com/llvm/llvm-project)) and [KomiMoe/Arkari](https://github.com/KomiMoe/Arkari)**, moving toward an **independent branch line** with its **own obfuscation algorithms and implementation logic**.
>
> That commit restructured the documentation (README trimmed into an overview page; detailed usage split into standalone docs) and added bilingual documentation with a contributing guide.
>
> - Future releases may **diverge from upstream** in obfuscation flags, pass behavior, and binary output; **upstream sync is no longer guaranteed**;
> - Tutorials and configs written for Arkari / upstream may **no longer apply** — always refer to this repository's [Usage Manual](./USAGE_en.md) instead;
> - Existing releases remain usable; new features and algorithms will be developed only on this repository's independent branch.

---

## Introduction

This repository is based on [llvm/llvm-project](https://github.com/llvm/llvm-project) (official LLVM sources) with the [KomiMoe/Arkari](https://github.com/KomiMoe/Arkari) obfuscation engine integrated and customized for the Android NDK, ported onto the LLVM version used by **Google's official Android NDK** (currently LLVM 21).

This project uses **NDK r30 / LLVM 21** as a stable baseline and does not track upstream LLVM major releases, prioritizing long-term toolchain stability and reliability.

Obfuscation capabilities at a glance:

- **Control-flow obfuscation**: FLA (control-flow flattening), BCF (bogus control flow with opaque predicates)
- **Indirection obfuscation**: INDBR (indirect branches), ICALL (indirect calls), INDGV (indirect global variable access) — encryption loop levels 0–3
- **Data obfuscation**: CSE (string encryption), CIE (integer constant encryption), CFE (floating-point constant encryption)
- **Extra protection**: RTTI name erasure (experimental)
- **Three control interfaces**: command-line flags, per-function `annotate` attributes, JSON config file (`-oboro-cfg`)

> 📖 The full **flag reference** and **before/after obfuscation comparisons** (IDA disassembly views / Graph View) are detailed usage documentation, kept in → [**Usage Manual (USAGE_en.md)**](./USAGE_en.md)

## Quick Start

### 1. Download the prebuilt toolchain

Download the prebuilt toolchain for your platform from [Releases](https://github.com/luluovo1/Oboro/releases) and extract it to any local directory (avoid non-ASCII characters or spaces in the path).

### 2. Integrate into your Android CMake project

Add obfuscation flags via `target_compile_options` in your `CMakeLists.txt`:

```cmake
# Recommended Tier 1: global protection for regular business logic
target_compile_options(your_target PRIVATE
    -mllvm -irobf-cse
    -mllvm -irobf-icall
    -mllvm -irobf-indbr -mllvm -irobf-level=1
)
```

Or invoke clang directly:

```bash
export PATH=/path/to/ollvm-toolchain/bin:$PATH
clang -O2 -mllvm -irobf-cse -mllvm -irobf-icall foo.c -o foo
```

### 3. Verify the obfuscation took effect

- Run `strings` on the `.so` — plaintext strings should disappear once `-irobf-cse` is enabled
- Open the `.so` in IDA Pro — the disassembly views should show `JUMPOUT` or scrambled switch dispatchers

> See the [Usage Manual (USAGE_en.md)](./USAGE_en.md) for more flag combinations and effect demonstrations

## Differences from Arkari

This project builds on [Arkari](https://github.com/KomiMoe/Arkari) as its core obfuscation engine:

| Aspect | Arkari | This Project |
|:---|:---|:---|
| Target platform | Generic LLVM / iOS | NDK-tailored, Windows supported as well |
| LLVM version | Upstream LLVM branches | Google NDK official LLVM 21 |
| Control-flow flattening (FLA) | Standard implementation | Ported and adapted from Arkari |
| Indirect branches (INDBR) | Standard encrypted page table | Ported and adapted from Arkari |
| Indirect calls (ICALL) | Standard encrypted page table | Ported and adapted from Arkari |
| Bogus control flow (BCF) | Not included | **BCF v2**: 12 randomized opaque-predicate families (production: 5 rule-engine-proof families), randomized poison payloads (AArch64 SP-convergence / x86_64 JUMPOUT) |
| Anti-emulation decoy | Not included | **Opt-in**: probe-driven L1 reconverge / L3 value pollution |
| Safety floor | Not included | **Red/yellow zones**: weak symbols, C++ runtime glue, ctors/dtors/operators are never obfuscated |
| Policy system | CLI flags only | **Config-first**: JSON `deny` + class/file `patterns` with field-level cascade |
| Compatibility | Generic | Generic |

Key differences in detail:

- Added the **BCF (Bogus Control Flow)** pass. v2 picks one of 12 mathematically proven opaque predicates at random per compilation (wraparound-safe, pre-filtered against InstSimplify), randomizes the input transform / polarity / payload constants, and injects either a poison dead block or an opt-in decoy block. Production weights only use the five families with 0% rule-engine fold rate (consecutive products / popcount); MBA and bit0 families stay test-only.
- **Safety floor** enforced inside `toObfuscate()`: red zone (weak symbols incl. all STL template instances, `__cxa_`/`__gxx_` glue, static ctor/dtor list, `operator new/delete`) is never obfuscated even by annotation; yellow zone (ctors/dtors/other operators) needs an explicit per-function annotation or an exact-name config pattern
- **Config-first policy**: `-oboro-cfg=policy.json` supports a `deny` list and class/namespace/file `patterns`, with a field-level cascade (`annotation > class pattern > file pattern > CLI > config > built-in`)
- **decoy (opt-in)**: the toolchain never detects environments itself. Your app provides `__oboro_probe()`; when it returns 0 the obfuscated code silently follows decoy paths — L1 stays semantically correct (trace noise), L3 pollutes values (wrong but executable results) behind a hard def-use safety filter
- Removed the ineffective PseudoStackOffset pass
- Fixed the `CryptoUtils.h` macro pollution issue affecting MSVC compilation

## Best Practices

Based on automated benchmarks of 18 flag combinations, the following three tiers are recommended.

### Tier 1: Global protection for regular code

Suited for enabling on regular business logic across an entire project. Binary size grows by about `+3.6%` and runtime by about `+79%`, but real-world impact is near zero for low-compute business code.

```cmake
# Android CMake
target_compile_options(your_target PRIVATE
    -mllvm -irobf-cse
    -mllvm -irobf-icall
    -mllvm -irobf-indbr -mllvm -irobf-level=1
)
```

```bash
# Direct clang usage
clang -O2 -mllvm -irobf-cse -mllvm -irobf-icall -mllvm -irobf-indbr -mllvm -irobf-level=1 foo.c -o foo
```

### Tier 2: Core algorithms & crypto functions

Enable only on auth logic, license checks and crypto cores. The cost is about `+450%`, but these functions run for milliseconds at a time — imperceptible to users, while dramatically raising the reverse-engineering cost.

```c
// Annotate the function to enable strong obfuscation for it only
__attribute__((__annotate__("irobf-fla")))
__attribute__((__annotate__("irobf-bcf")))
__attribute__((__annotate__("irobf-indbr")))
int verify_license(const char* key) {
    // ... license check logic
}
```

Or enable per translation unit via compile flags:

```bash
clang -O2 -mllvm -irobf-fla -mllvm -irobf-icall -mllvm -irobf-indbr \
      -mllvm -irobf-cse -mllvm -irobf-bcf=80 \
      crypto.c -o crypto.o
```

### Tier 3: Performance-critical paths (main loops, rendering, physics)

**Do not** enable FLA, BCF or high-level indirection obfuscation here. These three completely break CPU branch prediction and data-access locality, dropping hot loops by `400%~500%` — unacceptable for games, audio/video codecs and similar workloads.

Only **data-layer** obfuscation is recommended:

```bash
# For rendering/physics and other performance-critical modules
clang -O2 -mllvm -irobf-cse -mllvm -irobf-cie -mllvm -irobf-level=1 hotpath.c -o hotpath.o
```

> For performance-sensitive modules, encrypt *data* (strings, constants) and leave *control flow* (branches, jumps) alone — the golden rule.

### About the Level flags

`-irobf-level` sets the runtime XOR decryption loop layers for every pass that has a level (INDBR / ICALL / INDGV / CIE / CFE / rename). **The higher the level, the harder to reverse — and the cost grows exponentially.** To tune one pass alone, use its config node, e.g. `"indgv": {"level": 1}`.

| Level | Extra overhead (reference) | Use case |
|:---:|:---:|:---|
| `1` | `+20% ~ +75%` | Recommended default for all scenarios |
| `2` | `+120% ~ +250%` | Core functions, non-hot paths |
| `3` | `+300% ~ +470%` | Maximum protection, non-loop code |

**Warning**: `"indgv": {"level": 3}` triggers multi-layer decryption loops on *every* global variable access — on game-state reads or render-pipeline globals this easily causes Android ANR.

## License

This project is licensed under **LLVM Apache 2.0** (see [`LICENSE.TXT`](./LICENSE.TXT)). The obfuscation engine is based on [Arkari](https://github.com/KomiMoe/Arkari).

For learning and software-protection research purposes only. Do not use for any illegal purpose; users are responsible for their own compliance.

## Contributing

Contributions of any kind are welcome! Please read the [**Contributing Guide (CONTRIBUTING.md)**](./CONTRIBUTING.md) before opening an issue or pull request.

- 🐞 **Bug reports**: include reproduction steps, toolchain version and obfuscation flags
- 💡 **Feature requests**: open an [Issue](https://github.com/luluovo1/Oboro/issues)
- 🔧 **Code contributions**: the current roadmap includes more obfuscation options and the ongoing evolution of the independent obfuscation algorithms

If you find this project useful, please give it a ⭐ Star!

## Acknowledgments

This project stands on the shoulders of the OLLVM ecosystem:

- [LLVM Project](https://github.com/llvm/llvm-project) — the compiler infrastructure this toolchain is built upon
- [OLLVM (obfuscator-llvm)](https://github.com/obfuscator-llvm/obfuscator) — original design and implementation of the classic obfuscation passes (BCF / FLA / ICALL)
- [Hikari](https://github.com/HikariObfuscator/Hikari) — the LLVM obfuscator by Naville whose `-irobf-*` pass family and design ideas deeply influenced this toolchain
- [Goron](https://github.com/amimo/goron) — the technical foundation on which Arkari was built
- [KomiMoe / Arkari](https://github.com/KomiMoe/Arkari) — the direct upstream this project was originally based on

Thanks to everyone who has filed issues, submitted pull requests, or shared feedback — your contributions keep this project moving forward.

## Star History

<a href="https://www.star-history.com/#luluovo1/Oboro&date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=luluovo1/Oboro&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=luluovo1/Oboro&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=luluovo1/Oboro&type=Date" />
 </picture>
</a>
