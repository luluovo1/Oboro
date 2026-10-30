; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s
;
; llvm.fshl/fshr cover the rotate idiom, which shows up in every hash and
; checksum loop.  They must translate rather than skip the whole function.

declare i64 @llvm.fshl.i64(i64, i64, i64)
declare i32 @llvm.fshr.i32(i32, i32, i32)

define i64 @rotl(i64 %a, i64 %s) {
entry:
  %r = call i64 @llvm.fshl.i64(i64 %a, i64 %a, i64 %s)
  ret i64 %r
}

define i32 @rotr(i32 %a, i32 %s) {
entry:
  %r = call i32 @llvm.fshr.i32(i32 %a, i32 %a, i32 %s)
  ret i32 %r
}

; CHECK: define {{.*}}i64 @rotl(i64 %a, i64 %s)
; CHECK-NOT: llvm.fshl
; CHECK: call i64 @
; CHECK: ret i64
; CHECK: define {{.*}}i32 @rotr(i32 %a, i32 %s)
; CHECK-NOT: llvm.fshr
; CHECK: call i64 @
; CHECK: ret i32
; CHECK: define internal i64 @
; CHECK: switch i32
