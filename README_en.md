# OLLVM for Android NDK (Based on LLVM 21 + Arkari)

[![Build NDK OLLVM Toolchain](https://github.com/luluovo1/ollvm-ndk30-based-on-llvm21/actions/workflows/build-ndk-ollvm.yml/badge.svg)](https://github.com/luluovo1/ollvm-ndk30-based-on-llvm21/actions/workflows/build-ndk-ollvm.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![LLVM Version](https://img.shields.io/badge/LLVM-21.0.0-red.svg)](https://llvm.org/)
[![NDK Version](https://img.shields.io/badge/NDK-r30-green.svg)](https://developer.android.com/ndk)

<p align="center">
  <a href="./README.md"><img src="https://img.shields.io/badge/README-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-c0392b?style=for-the-badge" alt="简体中文"/></a>
  <a href="./README_en.md"><img src="https://img.shields.io/badge/README-English-2980b9?style=for-the-badge" alt="English"/></a>
</p>

> [!CAUTION]
> **⚠️ Important Notice: This repository is departing from upstream**
>
> Starting with this commit, this repository will **gradually detach from LLVM upstream ([llvm/llvm-project](https://github.com/llvm/llvm-project)) and [KomiMoe/Arkari](https://github.com/KomiMoe/Arkari)**, moving toward an **independent branch line** with its **own obfuscation algorithms and implementation logic**.
>
> - Future releases may **diverge from upstream** in obfuscation flags, pass behavior, and binary output; **upstream sync is no longer guaranteed**;
> - Tutorials and configs written for Arkari / upstream may **no longer apply** — always refer to this repository's [Usage Manual](./USAGE.md) (Chinese) instead;
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
- **Three control interfaces**: command-line flags, per-function `annotate` attributes, JSON config file (`-samsara-cfg`)

> 📖 The full **flag reference** and **before/after obfuscation comparisons** (IDA screenshots) are detailed usage documentation, kept in → [**Usage Manual (USAGE.md)**](./USAGE.md) (Chinese)

## Quick Start

### 1. Download the prebuilt toolchain

Download the prebuilt toolchain for your platform from [Releases](https://github.com/luluovo1/ollvm-ndk30-based-on-llvm21/releases) and extract it to any local directory (avoid non-ASCII characters or spaces in the path).

### 2. Integrate into your Android CMake project

Add obfuscation flags via `target_compile_options` in your `CMakeLists.txt`:

```cmake
# Recommended Tier 1: global protection for regular business logic
target_compile_options(your_target PRIVATE
    -mllvm -irobf-cse
    -mllvm -irobf-icall
    -mllvm -irobf-indbr -mllvm -level-indbr=1
)
```

Or invoke clang directly:

```bash
export PATH=/path/to/ollvm-toolchain/bin:$PATH
clang -O2 -mllvm -irobf-cse -mllvm -irobf-icall foo.c -o foo
```

### 3. Verify the obfuscation took effect

- Run `strings` on the `.so` — plaintext strings should disappear once `-irobf-cse` is enabled
- Open the `.so` in IDA Pro — decompiled functions should show `JUMPOUT` or scrambled switch dispatchers

> See the [Usage Manual (USAGE.md)](./USAGE.md) for more flag combinations and effect demonstrations

## Differences from Arkari

This project builds on [Arkari](https://github.com/KomiMoe/Arkari) as its core obfuscation engine:

| Aspect | Arkari | This Project |
|:---|:---|:---|
| Target platform | Generic LLVM / iOS | NDK-tailored, Windows supported as well |
| LLVM version | Upstream LLVM branches | Google NDK official LLVM 21 |
| Control-flow flattening (FLA) | Standard implementation | Ported and adapted from Arkari |
| Indirect branches (INDBR) | Standard encrypted page table | Ported and adapted from Arkari |
| Indirect calls (ICALL) | Standard encrypted page table | Ported and adapted from Arkari |
| Bogus control flow (BCF) | Not included | Included |
| Active stack corruption | Not included | Deprecated |
| Compatibility | Generic | Generic |

Key differences in detail:

- Added the **BCF (Bogus Control Flow)** pass using opaque predicates `(x*(x+1))%2==0` to inject unreachable diamond-shaped branches, degrading IDA Hex-Rays decompilation quality
- Removed the ineffective PseudoStackOffset pass
- Fixed the `CryptoUtils.h` macro pollution issue affecting MSVC compilation

## Best Practices

Based on automated benchmarks of 18 flag combinations (`testresu/benchmark_report.md`), the following three tiers are recommended.

### Tier 1: Global protection for regular code

Suited for enabling on regular business logic across an entire project. Binary size grows by about `+3.6%` and runtime by about `+79%`, but real-world impact is near zero for low-compute business code.

```cmake
# Android CMake
target_compile_options(your_target PRIVATE
    -mllvm -irobf-cse
    -mllvm -irobf-icall
    -mllvm -irobf-indbr -mllvm -level-indbr=1
)
```

```bash
# Direct clang usage
clang -O2 -mllvm -irobf-cse -mllvm -irobf-icall -mllvm -irobf-indbr -mllvm -level-indbr=1 foo.c -o foo
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
      -mllvm -irobf-cse -mllvm -irobf-bcf -mllvm -irobf-bcf_prob=80 \
      crypto.c -o crypto.o
```

### Tier 3: Performance-critical paths (main loops, rendering, physics)

**Do not** enable FLA, BCF or high-level indirection obfuscation here. These three completely break CPU branch prediction and data-access locality, dropping hot loops by `400%~500%` — unacceptable for games, audio/video codecs and similar workloads.

Only **data-layer** obfuscation is recommended:

```bash
# For rendering/physics and other performance-critical modules
clang -O2 -mllvm -irobf-cse -mllvm -irobf-cie -mllvm -level-cie=1 hotpath.c -o hotpath.o
```

> For performance-sensitive modules, encrypt *data* (strings, constants) and leave *control flow* (branches, jumps) alone — the golden rule.

### About the Level flags

`-level-indbr`, `-level-icall` and `-level-indgv` control the number of XOR decryption loop layers at runtime. **The higher the level, the harder to reverse — and the cost grows exponentially.**

| Level | Extra overhead (reference) | Use case |
|:---:|:---:|:---|
| `1` | `+20% ~ +75%` | Recommended default for all scenarios |
| `2` | `+120% ~ +250%` | Core functions, non-hot paths |
| `3` | `+300% ~ +470%` | Maximum protection, non-loop code |

**Warning**: `-level-indgv=3` triggers multi-layer decryption loops on *every* global variable access — on game-state reads or render-pipeline globals this easily causes Android ANR.

## License

This project is licensed under **LLVM Apache 2.0** (see [`LICENSE.TXT`](./LICENSE.TXT)). The obfuscation engine is based on [Arkari](https://github.com/KomiMoe/Arkari).

For learning and software-protection research purposes only. Do not use for any illegal purpose; users are responsible for their own compliance.

## Contributing

Contributions of any kind are welcome! Please read the [**Contributing Guide (CONTRIBUTING.md)**](./CONTRIBUTING.md) before opening an issue or pull request.

- 🐞 **Bug reports**: include reproduction steps, toolchain version and obfuscation flags
- 💡 **Feature requests**: open an [Issue](https://github.com/luluovo1/ollvm-ndk30-based-on-llvm21/issues)
- 🔧 **Code contributions**: the current roadmap includes more obfuscation options and the ongoing evolution of the independent obfuscation algorithms

If you find this project useful, please give it a ⭐ Star!

## Credits

- [LLVM Foundation](https://llvm.org/) — [llvm/llvm-project](https://github.com/llvm/llvm-project) (official LLVM upstream)
- [KomiMoe / Arkari](https://github.com/KomiMoe/Arkari) (obfuscation engine upstream)
