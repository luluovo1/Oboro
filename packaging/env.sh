#!/usr/bin/env bash
# Put the Oboro toolchain first on PATH.
#
#   source <oboro>/env.sh
#
# Optional: export OBORO_NDK=/path/to/android-ndk before sourcing to have the
# CMake toolchain file pick it up automatically.

OBORO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
case ":$PATH:" in
  *":$OBORO_ROOT/bin:"*) ;;
  *) PATH="$OBORO_ROOT/bin:$PATH" ;;
esac
export OBORO_ROOT PATH
