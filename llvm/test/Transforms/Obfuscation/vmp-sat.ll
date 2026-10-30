; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s --check-prefixes=CHECK,NOSAT
;
; Saturating arithmetic and llvm.abs have no opcode of their own: the
; translator emits the equivalent add/sub/xor/icmp/select sequence, so the
; intrinsic calls disappear from a virtualized function.  The shapes below
; mirror what -O2 leaves behind for zlib's longest_match (usub.sat) and
; deflateBound (llvm.abs), including the 8- and 16-bit widths whose registers
; are masked sub-word values.

declare i8 @llvm.uadd.sat.i8(i8, i8)
declare i16 @llvm.sadd.sat.i16(i16, i16)
declare i32 @llvm.usub.sat.i32(i32, i32)
declare i64 @llvm.ssub.sat.i64(i64, i64)
declare i32 @llvm.abs.i32(i32, i1)

define i8 @uadd8(i8 %a, i8 %b) {
entry:
  %r = call i8 @llvm.uadd.sat.i8(i8 %a, i8 %b)
  ret i8 %r
}

; CHECK: define {{.*}}i8 @uadd8(
; CHECK-NOT: call i8 @llvm.uadd.sat.i8
; CHECK: call i64 @
; CHECK: ret i8

define i16 @sadd16(i16 %a, i16 %b) {
entry:
  %r = call i16 @llvm.sadd.sat.i16(i16 %a, i16 %b)
  %s = add i16 %r, 1
  ret i16 %s
}

; CHECK: define {{.*}}i16 @sadd16(
; CHECK-NOT: call i16 @llvm.sadd.sat.i16
; CHECK: call i64 @
; CHECK: ret i16

define i32 @usub32(i32 %a, i32 %b) {
entry:
  %r = call i32 @llvm.usub.sat.i32(i32 %a, i32 %b)
  ret i32 %r
}

; CHECK: define {{.*}}i32 @usub32(
; CHECK-NOT: call i32 @llvm.usub.sat.i32
; CHECK: call i64 @
; CHECK: ret i32

define i64 @ssub64(i64 %a, i64 %b) {
entry:
  %r = call i64 @llvm.ssub.sat.i64(i64 %a, i64 %b)
  ret i64 %r
}

; CHECK: define {{.*}}i64 @ssub64(
; CHECK-NOT: call i64 @llvm.ssub.sat.i64
; CHECK: call i64 @
; CHECK: ret i64

define i32 @abs32(i32 %a) {
entry:
  %r = call i32 @llvm.abs.i32(i32 %a, i1 false)
  ret i32 %r
}

; CHECK: define {{.*}}i32 @abs32(
; CHECK-NOT: call i32 @llvm.abs.i32
; CHECK: call i64 @
; CHECK: ret i32

; No virtualized function may keep a saturating or abs call behind: every one
; of them is rewritten into ordinary operations.
;
; NOSAT-NOT: call i8 @llvm.uadd.sat.i8
; NOSAT-NOT: call i16 @llvm.sadd.sat.i16
; NOSAT-NOT: call i32 @llvm.usub.sat.i32
; NOSAT-NOT: call i64 @llvm.ssub.sat.i64
; NOSAT-NOT: call i32 @llvm.abs.i32
