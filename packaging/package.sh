#!/usr/bin/env bash
# Build a relocatable Oboro release archive from an existing build tree.
#
#   packaging/package.sh [options]
#
#   --build DIR      build tree to package      (default: $OBORO_BUILD or llvm/buildtest/Release)
#   --host TAG       host tag                   (default: detected from the build tree)
#   --out DIR        output directory           (default: .tmp/pkg)
#   --version VER    override packaging/VERSION
#   --slim           ship only clang/opt/lld; install.sh materialises clang++/clang-cl
#   --strip          strip binaries (uses llvm-strip from the build; POSIX hosts only)
#
# Produces <out>/oboro-<version>-<host>.tar.xz plus a .sha256 file next to it.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

BUILD=${OBORO_BUILD:-$ROOT/llvm/buildtest/Release}
OUT=${OBORO_PKG_OUT:-$ROOT/.tmp/pkg}
VERSION=$(tr -d ' \t\r\n' <"$HERE/VERSION")
HOST=""
SLIM=0
STRIP=0

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
warn() { printf 'warning: %s\n' "$*" >&2; }
note() { printf '  %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --build)   BUILD=$2;   shift 2 ;;
    --host)    HOST=$2;    shift 2 ;;
    --out)     OUT=$2;     shift 2 ;;
    --version) VERSION=$2; shift 2 ;;
    --slim)    SLIM=1;     shift   ;;
    --strip)   STRIP=1;    shift   ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -d "$BUILD" ] || die "build tree not found: $BUILD"

# ---------------------------------------------------------------- host / exe
if [ -z "$HOST" ]; then
  if [ -f "$BUILD/bin/clang.exe" ]; then
    HOST=windows-x86_64
  elif [ -f "$BUILD/bin/clang" ]; then
    case "$(uname -s)" in
      Darwin) HOST="darwin-$(uname -m)" ;;
      *)      HOST="linux-$(uname -m)"  ;;
    esac
  else
    die "no clang binary in $BUILD/bin; pass --host and check --build"
  fi
fi

case "$HOST" in
  windows-*) EXE=.exe ;;
  *)         EXE=     ;;
esac

NAME="oboro-$VERSION-$HOST"
STAGE="$OUT/stage"
PKG="$STAGE/$NAME"

# ------------------------------------------------------------------- staging
rm -rf "$STAGE"
mkdir -p "$PKG/bin" "$PKG/share/oboro/cmake" "$PKG/share/oboro/ndk-build" "$PKG/docs"

# Tools a cross build actually needs.  Anything missing is reported, not fatal:
# build configurations differ (e.g. no lld in a clang-only build).
TOOLS=(clang clang++ opt ld.lld lld llvm-ar llvm-ranlib llvm-nm llvm-strip
       llvm-objcopy llvm-objdump llvm-readelf llvm-size llvm-as llvm-link)
[ "$EXE" = .exe ] && TOOLS+=(clang-cl)
[ "$SLIM" = 1 ] && TOOLS=(clang opt ld.lld lld llvm-ar llvm-ranlib llvm-nm
                          llvm-strip llvm-objcopy llvm-objdump llvm-readelf llvm-size)

echo "staging $NAME"
missing=0
for t in "${TOOLS[@]}"; do
  src="$BUILD/bin/$t$EXE"
  if [ ! -f "$src" ]; then
    warn "missing tool: $t$EXE"
    missing=$((missing + 1))
    continue
  fi
  cp "$src" "$PKG/bin/"
  note "bin/$t$EXE"
done
[ "$missing" -gt 0 ] || true

# ------------------------------------------------------------ clang resources
RES_SRC=$(ls -d "$BUILD"/lib/clang/*/ 2>/dev/null | sort -V | tail -1 || true)
[ -n "$RES_SRC" ] || die "no lib/clang/<version> directory in $BUILD"
RES_VER=$(basename "$RES_SRC")
mkdir -p "$PKG/lib/clang/$RES_VER"

cp -R "$RES_SRC/include" "$PKG/lib/clang/$RES_VER/"
note "lib/clang/$RES_VER/include"

# Builtins for Android targets only; the rest of lib/clang/<ver>/lib is build
# residue (static LLVM archives) and must never ship.
mkdir -p "$PKG/lib/clang/$RES_VER/lib"
for d in "$RES_SRC"lib/*-linux-android*; do
  [ -d "$d" ] || continue
  cp -R "$d" "$PKG/lib/clang/$RES_VER/lib/"
  note "lib/clang/$RES_VER/lib/$(basename "$d")"
done

# --------------------------------------------------------------- integration
cp "$HERE/cmake/oboro-android-toolchain.cmake" "$PKG/share/oboro/cmake/"
cp "$HERE/ndk-build/oboro.mk"                  "$PKG/share/oboro/ndk-build/"
cp "$HERE/install.sh"                          "$PKG/install.sh"
cp "$HERE/env.sh" "$HERE/env.bat"              "$PKG/"
cp "$HERE/VERSION"                             "$PKG/VERSION"
chmod +x "$PKG/install.sh" "$PKG/env.sh" 2>/dev/null || true

# The archive is consumed on Linux/macOS as well: never ship CRLF shell scripts
# even when this tree was checked out on Windows with core.autocrlf=true.
for f in "$PKG/install.sh" "$PKG/env.sh"; do
  sed -i 's/\r$//' "$f"
done
# cmd.exe is happiest with CRLF batch files.
sed -i 's/\r$//; s/$/\r/' "$PKG/env.bat"

# -------------------------------------------------------------------- docs
for f in LICENSE.TXT README.md README.zh-CN.md USAGE.md USAGE_en.md CHANGELOG.md; do
  [ -f "$ROOT/$f" ] && cp "$ROOT/$f" "$PKG/docs/"
done

# ------------------------------------------------------------------- strip
if [ "$STRIP" = 1 ]; then
  if [ "$EXE" = .exe ]; then
    warn "--strip ignored on windows hosts (MSVC binaries carry no ELF symbols)"
  else
    STRIPPER="$BUILD/bin/llvm-strip"
    [ -x "$STRIPPER" ] || STRIPPER=$(command -v strip || true)
    if [ -n "$STRIPPER" ]; then
      for f in "$PKG"/bin/*; do "$STRIPPER" --strip-all "$f" 2>/dev/null || true; done
      note "stripped bin/*"
    else
      warn "--strip requested but no strip tool found"
    fi
  fi
fi

# ---------------------------------------------------------------- metadata
COMMIT=$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILT=${SOURCE_DATE_EPOCH:+$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)}
[ -n "${BUILT:-}" ] || BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LLVM_VER=$(basename "$RES_VER")

cat >"$PKG/oboro-version.txt" <<EOF
name: Oboro
version: $VERSION
llvm: $LLVM_VER
host: $HOST
commit: $COMMIT
built: $BUILT
EOF

# MANIFEST: every shipped file with size and sha256, so an installed tree can be
# verified without trusting the archive itself.
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
(
  cd "$PKG"
  find . -type f ! -name MANIFEST.txt | LC_ALL=C sort | while IFS= read -r f; do
    printf '%s  %10s  %s\n' "$($SHA "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "${f#./}"
  done
) >"$PKG/MANIFEST.txt"
note "MANIFEST.txt ($(grep -c . "$PKG/MANIFEST.txt") files)"

# ------------------------------------------------------------------ archive
ARCHIVE="$OUT/$NAME.tar.xz"
rm -f "$ARCHIVE" "$ARCHIVE.sha256"
echo "compressing (xz -9) ..."
tar -C "$STAGE" \
    --sort=name --owner=0 --group=0 --numeric-owner \
    -cJf "$ARCHIVE" "$NAME"

(
  cd "$OUT"
  $SHA "$NAME.tar.xz" >"$NAME.tar.xz.sha256"
)

printf '\narchive : %s\nsize    : %s\nsha256  : %s\n' \
  "$ARCHIVE" \
  "$(du -h "$ARCHIVE" | cut -f1)" \
  "$(cut -d' ' -f1 "$ARCHIVE.sha256")"
