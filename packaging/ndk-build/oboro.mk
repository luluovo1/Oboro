# Oboro flag presets for ndk-build.
#
# ndk-build picks the obfuscating compiler up automatically once Oboro has been
# installed into the NDK (`install.sh --ndk <NDK>`); this file only supplies the
# -mllvm flag groups.
#
#   include $(OBORO_ROOT)/share/oboro/ndk-build/oboro.mk
#
#   LOCAL_CFLAGS   += $(OBORO_CFLAGS_STANDARD)
#   LOCAL_CPPFLAGS += $(OBORO_CFLAGS_STANDARD)
#   LOCAL_LDFLAGS  += $(OBORO_LDFLAGS)
#
# Note: every LLVM option needs its own -mllvm in front of it.

# Minimum: cheap call/global indirection, negligible size growth.
OBORO_CFLAGS_MIN := -mllvm -irobf-icall -mllvm -irobf-indgv

# Standard: what most apps want.  Control-flow + strings + calls.
OBORO_CFLAGS_STANDARD := \
  -mllvm -irobf-bcf \
  -mllvm -irobf-fla \
  -mllvm -irobf-cse \
  -mllvm -irobf-icall \
  -mllvm -irobf-indgv

# Heavy: adds constant encryption, indirect branches and decoy paths.
# Expect a large size increase; measure before shipping.
OBORO_CFLAGS_HEAVY := \
  $(OBORO_CFLAGS_STANDARD) \
  -mllvm -irobf-indbr=full \
  -mllvm -irobf-cie \
  -mllvm -irobf-cfe \
  -mllvm -irobf-decoy=40 \
  -mllvm -irobf-aux=wrap \
  -mllvm -irobf-level=3

# Config-file driven: the whole policy lives in JSON, flags only point at it.
#   ndk-build OBORO_CFG=$(LOCAL_PATH)/oboro.json
ifdef OBORO_CFG
OBORO_CFLAGS_CONFIG := -mllvm -irobf -mllvm -oboro-cfg=$(OBORO_CFG)
endif

# lld ships with Oboro; the NDK's own lld is used unless --with-lld was passed
# to install.sh, so no explicit -fuse-ld is needed here.
OBORO_LDFLAGS :=
