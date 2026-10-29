# Oboro Android toolchain for CMake.
#
#   cmake -B build -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=<oboro>/share/oboro/cmake/oboro-android-toolchain.cmake \
#     -DOBORO_NDK=/path/to/android-ndk \
#     -DOBORO_ABI=arm64-v8a \
#     -DOBORO_API=24 \
#     -DOBORO_FLAGS="-mllvm;-irobf-bcf;-mllvm;-irobf-fla"
#
# Inputs (all optional except OBORO_NDK when it cannot be auto-detected):
#   OBORO_NDK     NDK root; falls back to $ANDROID_NDK_ROOT, $ANDROID_NDK_HOME,
#                 $NDK_ROOT, then the newest SDK ndk/ directory
#   OBORO_ABI     arm64-v8a (default) | armeabi-v7a | x86 | x86_64
#   OBORO_API     Android API level (default: 24 for 64-bit, 21 for 32-bit)
#   OBORO_FLAGS   semicolon list of extra flags, e.g. "-mllvm;-irobf-bcf"
#   OBORO_CFG     path to a JSON obfuscation config, added as -oboro-cfg
#   OBORO_LD      lld (default) | gold | none

cmake_minimum_required(VERSION 3.20)

# try_compile() re-runs this file in a scratch project that does not inherit
# -D arguments, so every input has to be forwarded explicitly.
set(CMAKE_TRY_COMPILE_PLATFORM_VARIABLES
    OBORO_ROOT OBORO_NDK OBORO_ABI OBORO_API OBORO_FLAGS OBORO_CFG OBORO_LD)

if(NOT OBORO_ROOT)
  get_filename_component(OBORO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
endif()
if(NOT EXISTS "${OBORO_ROOT}/bin")
  message(FATAL_ERROR "Oboro: OBORO_ROOT does not look like a package root: ${OBORO_ROOT}")
endif()

# ------------------------------------------------------------------ NDK
if(NOT OBORO_NDK)
  foreach(_cand "$ENV{ANDROID_NDK_ROOT}" "$ENV{ANDROID_NDK_HOME}" "$ENV{NDK_ROOT}")
    if(_cand AND EXISTS "${_cand}/toolchains/llvm/prebuilt")
      set(OBORO_NDK "${_cand}")
      break()
    endif()
  endforeach()
endif()
if(NOT OBORO_NDK)
  file(GLOB _ndks "$ENV{LOCALAPPDATA}/Android/Sdk/ndk/*")
  list(SORT _ndks COMPARE NATURAL ORDER DESCENDING)
  foreach(_cand IN LISTS _ndks)
    if(EXISTS "${_cand}/toolchains/llvm/prebuilt")
      set(OBORO_NDK "${_cand}")
      break()
    endif()
  endforeach()
endif()
if(NOT OBORO_NDK OR NOT EXISTS "${OBORO_NDK}/toolchains/llvm/prebuilt")
  message(FATAL_ERROR "Oboro: set -DOBORO_NDK=/path/to/android-ndk")
endif()
set(OBORO_NDK "${OBORO_NDK}" CACHE PATH "Android NDK used by the Oboro toolchain")

file(GLOB _prebuilts "${OBORO_NDK}/toolchains/llvm/prebuilt/*")
list(GET _prebuilts 0 OBORO_PREBUILT)
if(NOT EXISTS "${OBORO_PREBUILT}/sysroot")
  message(FATAL_ERROR "Oboro: no sysroot under ${OBORO_PREBUILT}")
endif()

# ------------------------------------------------------------------ ABI
if(NOT OBORO_ABI)
  set(OBORO_ABI "arm64-v8a")
endif()
if(NOT OBORO_API)
  if(OBORO_ABI STREQUAL "arm64-v8a" OR OBORO_ABI STREQUAL "x86_64")
    set(OBORO_API 24)
  else()
    set(OBORO_API 21)
  endif()
endif()

if(OBORO_ABI STREQUAL "arm64-v8a")
  set(_triple aarch64-linux-android)
  set(_proc aarch64)
elseif(OBORO_ABI STREQUAL "armeabi-v7a")
  set(_triple armv7a-linux-androideabi)
  set(_proc armv7-a)
elseif(OBORO_ABI STREQUAL "x86")
  set(_triple i686-linux-android)
  set(_proc i686)
elseif(OBORO_ABI STREQUAL "x86_64")
  set(_triple x86_64-linux-android)
  set(_proc x86_64)
else()
  message(FATAL_ERROR "Oboro: unsupported OBORO_ABI=${OBORO_ABI}")
endif()

# ------------------------------------------------------------- compilers
set(_suffix "")
if(CMAKE_HOST_WIN32)
  set(_suffix ".exe")
endif()
set(_clang "${OBORO_ROOT}/bin/clang${_suffix}")
set(_clangxx "${OBORO_ROOT}/bin/clang++${_suffix}")
if(NOT EXISTS "${_clang}")
  message(FATAL_ERROR "Oboro: clang not found at ${_clang}")
endif()

set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION ${OBORO_API})
set(CMAKE_SYSTEM_PROCESSOR ${_proc})
set(CMAKE_ANDROID_ARCH_ABI ${OBORO_ABI})
set(CMAKE_ANDROID_API ${OBORO_API})

set(CMAKE_C_COMPILER   "${_clang}")
set(CMAKE_CXX_COMPILER "${_clangxx}")
set(CMAKE_C_COMPILER_TARGET   "${_triple}${OBORO_API}")
set(CMAKE_CXX_COMPILER_TARGET "${_triple}${OBORO_API}")

set(CMAKE_SYSROOT "${OBORO_PREBUILT}/sysroot")
set(CMAKE_FIND_ROOT_PATH "${CMAKE_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# ------------------------------------------------------------------ flags
if(NOT DEFINED OBORO_FLAGS)
  set(OBORO_FLAGS "-mllvm;-irobf-bcf")
endif()
set(_oboro_flags ${OBORO_FLAGS})
if(OBORO_CFG)
  list(APPEND _oboro_flags "-mllvm" "-oboro-cfg=${OBORO_CFG}")
endif()

if(NOT OBORO_LD)
  set(OBORO_LD "lld")
endif()
set(_oboro_ld "")
if(OBORO_LD STREQUAL "lld")
  set(_oboro_ld "-fuse-ld=lld")
elseif(OBORO_LD STREQUAL "gold")
  set(_oboro_ld "-fuse-ld=gold")
endif()

string(REPLACE ";" " " _oboro_flags_str "${_oboro_flags}")
set(CMAKE_C_FLAGS_INIT   "${_oboro_flags_str}")
set(CMAKE_CXX_FLAGS_INIT "${_oboro_flags_str}")
set(CMAKE_ASM_FLAGS_INIT "")

# The -mllvm groups are compile-time only; keep them quiet at link time.
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_oboro_ld} -Qunused-arguments")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_oboro_ld} -Qunused-arguments")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_oboro_ld} -Qunused-arguments")

# CMake includes a toolchain file more than once per configure (system
# determination, then project()); print the summary only on the first pass.
if(NOT OBORO_ANNOUNCED)
  set(OBORO_ANNOUNCED TRUE)
  message(STATUS "Oboro: ${OBORO_ROOT}")
  message(STATUS "Oboro: ${OBORO_ABI} API ${OBORO_API} via ${OBORO_PREBUILT}")
  message(STATUS "Oboro: flags ${_oboro_flags_str}")
endif()
