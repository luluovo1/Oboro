#!/usr/bin/env bash
# Install Oboro from an unpacked release tree or a .tar.xz archive.
#
#   install.sh --prefix DIR [--archive FILE | --from DIR] [--force]
#   install.sh --ndk NDK_DIR [--archive FILE | --from DIR] [--with-lld] [--force]
#   install.sh --ndk NDK_DIR --uninstall
#
#   --prefix DIR    standalone install (default: ~/.oboro/<version>)
#   --ndk NDK_DIR   drop-in replacement of the NDK's clang, so CMake and
#                   ndk-build pick it up with no build-script changes
#   --archive FILE  install from oboro-<ver>-<host>.tar.xz
#   --from DIR      install from an unpacked package tree
#   --with-lld      also replace the NDK's ld.lld/lld
#   --force         overwrite an existing install
#   --uninstall     restore the NDK's original compilers
#
# With neither --archive nor --from, the directory containing this script is
# used, which is the normal case right after unpacking a release tarball.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

PREFIX=""
NDK=""
ARCHIVE=""
SRC=""
WITH_LLD=0
FORCE=0
UNINSTALL=0

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)    PREFIX=$2;  shift 2 ;;
    --ndk)       NDK=$2;     shift 2 ;;
    --archive)   ARCHIVE=$2; shift 2 ;;
    --from)      SRC=$2;     shift 2 ;;
    --with-lld)  WITH_LLD=1; shift   ;;
    --force)     FORCE=1;    shift   ;;
    --uninstall) UNINSTALL=1; shift  ;;
    -h|--help)   sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$PREFIX" ] || [ -n "$NDK" ] || die "one of --prefix or --ndk is required"
[ -n "$PREFIX" ] && [ -n "$NDK" ] && die "--prefix and --ndk are mutually exclusive"

# ================================================================ uninstall
# Runs before any package source is resolved: restoring the stock compilers
# must work even if the release tree is gone.
if [ "$UNINSTALL" = 1 ]; then
  [ -n "$NDK" ] || die "--uninstall only applies to --ndk"
  PREBUILT=$(find "$NDK/toolchains/llvm/prebuilt" -maxdepth 1 -mindepth 1 -type d | head -1)
  [ -n "$PREBUILT" ] || die "no prebuilt toolchain under $NDK/toolchains/llvm/prebuilt"
  BK="$PREBUILT/.oboro-backup"
  [ -d "$BK" ] || die "nothing to restore: $BK does not exist"
  for f in "$BK"/*; do
    [ -e "$f" ] || continue
    mv -f "$f" "$PREBUILT/bin/$(basename "$f")"
    note "restored bin/$(basename "$f")"
  done
  rm -rf "$BK"
  rm -f "$PREBUILT/.oboro-installed"
  echo "uninstalled Oboro from $PREBUILT"
  exit 0
fi

# ------------------------------------------------------------------- source
UNPACK=""
cleanup() { [ -n "$UNPACK" ] && rm -rf "$UNPACK"; }
trap cleanup EXIT

if [ -n "$ARCHIVE" ]; then
  [ -f "$ARCHIVE" ] || die "archive not found: $ARCHIVE"
  UNPACK="$(cd "$(dirname "$ARCHIVE")" && pwd)/.oboro-unpack.$$"
  rm -rf "$UNPACK"; mkdir -p "$UNPACK"
  echo "unpacking $(basename "$ARCHIVE")"
  tar -C "$UNPACK" -xJf "$ARCHIVE"
  SRC=$(find "$UNPACK" -maxdepth 1 -mindepth 1 -type d | head -1)
elif [ -z "$SRC" ]; then
  SRC=$HERE
fi

[ -d "$SRC/bin" ] || die "not an Oboro package tree (no bin/): $SRC"
[ -f "$SRC/oboro-version.txt" ] || die "not an Oboro package tree (no oboro-version.txt): $SRC"
VERSION=$(sed -n 's/^version: //p' "$SRC/oboro-version.txt")

# ============================================================ NDK drop-in
if [ -n "$NDK" ]; then
  [ -d "$NDK/toolchains/llvm/prebuilt" ] || die "not an NDK (no toolchains/llvm/prebuilt): $NDK"
  PREBUILT=$(find "$NDK/toolchains/llvm/prebuilt" -maxdepth 1 -mindepth 1 -type d | head -1)
  [ -n "$PREBUILT" ] || die "no prebuilt toolchain under $NDK/toolchains/llvm/prebuilt"
  BIN="$PREBUILT/bin"
  BK="$PREBUILT/.oboro-backup"

  if [ -f "$PREBUILT/.oboro-installed" ] && [ "$FORCE" != 1 ]; then
    die "Oboro already installed in $PREBUILT (use --force, or --uninstall first)"
  fi

  # Resource dir version must match, otherwise clang will not find its headers.
  NDK_RES=$(ls -d "$PREBUILT"/lib/clang/*/ 2>/dev/null | sort -V | tail -1)
  OUR_RES=$(ls -d "$SRC"/lib/clang/*/ 2>/dev/null | sort -V | tail -1)
  [ -n "$NDK_RES" ] && [ -n "$OUR_RES" ] || die "missing lib/clang in the NDK or the package"
  [ "$(basename "$NDK_RES")" = "$(basename "$OUR_RES")" ] || \
    die "clang resource version mismatch: NDK has $(basename "$NDK_RES"), package has $(basename "$OUR_RES")"

  mkdir -p "$BK"
  REPLACE=(clang clang++ clang-cl)
  [ "$WITH_LLD" = 1 ] && REPLACE+=(ld.lld lld)

  for t in "${REPLACE[@]}"; do
    src="$SRC/bin/$t.exe"
    [ -f "$src" ] || src="$SRC/bin/$t"
    [ -f "$src" ] || { note "skip $t (not in package)"; continue; }
    if [ -f "$BIN/$t.exe" ] && [ ! -f "$BK/$t.exe" ]; then
      cp "$BIN/$t.exe" "$BK/$t.exe"
    fi
    cp "$src" "$BIN/$(basename "$src")"
    note "replaced bin/$(basename "$src")"
  done

  printf 'version: %s\nsource: %s\n' "$VERSION" "$SRC" >"$PREBUILT/.oboro-installed"

  echo
  echo "Oboro $VERSION installed into $PREBUILT"
  echo "Restore the stock compilers with: $0 --ndk \"$NDK\" --uninstall"
  exit 0
fi

# ============================================================ standalone
[ -n "$PREFIX" ] || PREFIX="$HOME/.oboro/$VERSION"

if [ -d "$PREFIX" ] && [ -n "$(ls -A "$PREFIX" 2>/dev/null)" ] && [ "$FORCE" != 1 ]; then
  die "target exists and is not empty: $PREFIX (use --force)"
fi

mkdir -p "$PREFIX"
echo "installing Oboro $VERSION to $PREFIX"
cp -R "$SRC"/. "$PREFIX"/

# Slim packages ship clang only; clang++/clang-cl are argv[0] personalities.
for alias in clang++ clang-cl; do
  [ -f "$PREFIX/bin/$alias.exe" ] || [ -f "$PREFIX/bin/$alias" ] && continue
  if [ -f "$PREFIX/bin/clang.exe" ]; then
    cp "$PREFIX/bin/clang.exe" "$PREFIX/bin/$alias.exe"
  elif [ -f "$PREFIX/bin/clang" ]; then
    ln -sf clang "$PREFIX/bin/$alias" 2>/dev/null || cp "$PREFIX/bin/clang" "$PREFIX/bin/$alias"
  fi
done

chmod +x "$PREFIX"/bin/* 2>/dev/null || true
chmod +x "$PREFIX/install.sh" 2>/dev/null || true

# Sanity check: the installed compiler must actually run.
CC_BIN="$PREFIX/bin/clang"
[ -f "$CC_BIN.exe" ] && CC_BIN="$CC_BIN.exe"
if VER_LINE=$("$CC_BIN" --version 2>/dev/null | head -1); then
  note "self-test: $VER_LINE"
else
  die "installed clang does not run: $CC_BIN"
fi

cat <<EOF

Installed.  Next steps:

  source "$PREFIX/env.sh"          # POSIX shells; env.bat on cmd.exe
  export OBORO_NDK=/path/to/ndk    # only for the CMake toolchain file

  CMake   : -DCMAKE_TOOLCHAIN_FILE="$PREFIX/share/oboro/cmake/oboro-android-toolchain.cmake"
  ndk-build: include "$PREFIX/share/oboro/ndk-build/oboro.mk" in Android.mk

Uninstall: rm -rf "$PREFIX"
EOF
