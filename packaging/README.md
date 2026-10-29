# Oboro release packaging

Scripts that turn a local build tree into a versioned, relocatable toolchain
archive, plus the integration files that make it usable from CMake, ndk-build
and Gradle.

```
packaging/
  VERSION                                single source of truth for the version
  package.sh                             build tree -> oboro-<ver>-<host>.tar.xz
  install.sh                             install / uninstall (standalone or NDK drop-in)
  env.sh, env.bat                        put the toolchain on PATH
  cmake/oboro-android-toolchain.cmake    CMake toolchain file
  ndk-build/oboro.mk                     -mllvm flag presets for ndk-build
```

## 1. Build the archive

```bash
packaging/package.sh                       # full archive
packaging/package.sh --slim                # clang + opt + lld only (~40% smaller)
packaging/package.sh --out /tmp/out        # where to write it
packaging/package.sh --version 1.0.1       # override packaging/VERSION
```

The build tree defaults to `llvm/buildtest/Release`; override with
`--build DIR` or `$OBORO_BUILD`.

Output:

```
oboro-<version>-<host>.tar.xz
oboro-<version>-<host>.tar.xz.sha256
```

Archive layout:

```
oboro-<version>-<host>/
  bin/            clang, clang++, clang-cl, opt, ld.lld, llvm-{ar,nm,objcopy,...}
  lib/clang/21/   resource headers + Android builtins
  share/oboro/    cmake/ and ndk-build/ integration files
  docs/           README, USAGE, CHANGELOG, LICENSE
  install.sh  env.sh  env.bat
  VERSION  oboro-version.txt  MANIFEST.txt
```

`MANIFEST.txt` lists every file with its size and SHA-256, so an installed tree
can be verified without trusting the archive:

```bash
cd <prefix> && sha256sum -c <(awk '{print $1"  "$3}' MANIFEST.txt)
```

`--slim` drops `clang++`/`clang-cl` from the archive; `install.sh` recreates
them from `clang` (they are the same binary, selected by `argv[0]`).

## 2. Install

### Standalone

```bash
./install.sh --prefix ~/.oboro/1.0.0 --archive oboro-1.0.0-windows-x86_64.tar.xz
source ~/.oboro/1.0.0/env.sh
```

`install.sh` runs `clang --version` after copying and fails if the installed
compiler does not start.

### NDK drop-in

Replaces the NDK's compiler with Oboro's, so existing CMake/ndk-build/Gradle
projects pick it up with **no build-script changes**:

```bash
./install.sh --ndk /path/to/android-ndk            # clang, clang++, clang-cl
./install.sh --ndk /path/to/android-ndk --with-lld # also ld.lld/lld
./install.sh --ndk /path/to/android-ndk --uninstall
```

The original binaries are moved to `<prebuilt>/.oboro-backup/` first and are
restored by `--uninstall`. The install refuses to run if the NDK's
`lib/clang/<n>` major version differs from the package's, because clang would
then be unable to find its own headers.

## 3. CMake

```bash
cmake -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$OBORO_ROOT/share/oboro/cmake/oboro-android-toolchain.cmake \
  -DOBORO_NDK=$ANDROID_NDK_ROOT \
  -DOBORO_ABI=arm64-v8a \
  -DOBORO_API=24 \
  -DOBORO_FLAGS="-mllvm;-irobf-bcf;-mllvm;-irobf-fla;-mllvm;-irobf-cse"
```

| Variable | Meaning |
|---|---|
| `OBORO_NDK` | NDK root. Auto-detected from `ANDROID_NDK_ROOT`, `ANDROID_NDK_HOME`, `NDK_ROOT`, then the newest `$LOCALAPPDATA/Android/Sdk/ndk/*` |
| `OBORO_ABI` | `arm64-v8a` (default), `armeabi-v7a`, `x86`, `x86_64` |
| `OBORO_API` | API level; defaults to 24 for 64-bit ABIs and 21 for 32-bit |
| `OBORO_FLAGS` | semicolon list appended to the compile flags |
| `OBORO_CFG` | path to a JSON policy file, added as `-oboro-cfg=<path>` |
| `OBORO_LD` | `lld` (default), `gold`, `none` |

The toolchain file works without the NDK drop-in install: it points
`CMAKE_<LANG>_COMPILER` at the package's clang, sets
`--target=<triple><api>` and `--sysroot=<ndk>/.../sysroot`, and forwards its
inputs to `try_compile` through `CMAKE_TRY_COMPILE_PLATFORM_VARIABLES`.

For Android Gradle Plugin, pass the same arguments through
`externalNativeBuild.cmake.arguments`.

## 4. ndk-build

After the drop-in install, only the flags are needed:

```make
include $(OBORO_ROOT)/share/oboro/ndk-build/oboro.mk

LOCAL_CFLAGS   += $(OBORO_CFLAGS_STANDARD)
LOCAL_CPPFLAGS += $(OBORO_CFLAGS_STANDARD)
```

Presets: `OBORO_CFLAGS_MIN`, `OBORO_CFLAGS_STANDARD`, `OBORO_CFLAGS_HEAVY`,
and `OBORO_CFLAGS_CONFIG` (set `OBORO_CFG=<path>` on the ndk-build command
line). Every LLVM option needs its own `-mllvm` prefix; the presets already do
this.

## 5. Version policy

`packaging/VERSION` is the only place the version is written. It feeds
`oboro-version.txt` inside the archive and the archive name. Bump it and add a
`CHANGELOG.md` entry in the same change.

`oboro-version.txt` records version, LLVM major, host tag, source commit and
build timestamp, which is what support requests should quote.

## 6. Verification checklist

After changing any packaging file:

```bash
bash -n packaging/package.sh packaging/install.sh
packaging/package.sh --slim --out .tmp/pkg
./install.sh --prefix .tmp/inst --archive .tmp/pkg/oboro-*-*.tar.xz
cmake -S <small project> -B .tmp/b -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=.tmp/inst/share/oboro/cmake/oboro-android-toolchain.cmake \
  -DOBORO_NDK=$ANDROID_NDK_ROOT "-DOBORO_FLAGS=-mllvm;-irobf-bcf"
```

Then confirm on a device that the baseline and the obfuscated build print the
same output, and that the obfuscated symbols grew
(`llvm-nm -S --defined-only lib.so`).
