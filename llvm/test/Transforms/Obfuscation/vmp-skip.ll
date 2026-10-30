; RUN: opt -S -passes='default<O0>' -irobf-vmp < %s -o - | FileCheck %s
;
; Dynamic allocas and vector values are not representable; the function must be
; left exactly as it was (no interpreter call).

define i32 @dyn_alloca(i32 %n) {
entry:
  %p = alloca i32, i32 %n
  store i32 7, ptr %p
  %v = load i32, ptr %p
  ret i32 %v
}

define <4 x i32> @vec(<4 x i32> %a) {
entry:
  %b = add <4 x i32> %a, <i32 1, i32 2, i32 3, i32 4>
  ret <4 x i32> %b
}

; A scalable element type has no fixed allocation size: the stride cannot be a
; constant and asking for one asserts.
define ptr @sve_gep(ptr %p, i64 %i) {
entry:
  %q = getelementptr <vscale x 4 x i32>, ptr %p, i64 %i
  ret ptr %q
}

; An alloca whose size overflows the frame arithmetic must be refused instead of
; wrapping to a tiny slot.
define i32 @huge_alloca(i64 %n) {
entry:
  %p = alloca [16 x i8], i64 1152921504606846976
  %q = getelementptr i8, ptr %p, i64 %n
  store i8 1, ptr %q
  %v = load i32, ptr %p
  ret i32 %v
}

; CHECK: define {{.*}}i32 @dyn_alloca(i32 %n)
; CHECK: alloca i32, i32 %n
; CHECK-NOT: call i64 @
; CHECK: define {{.*}}<4 x i32> @vec(<4 x i32> %a)
; CHECK: add <4 x i32>
; CHECK: define {{.*}}ptr @sve_gep(ptr %p, i64 %i)
; CHECK: getelementptr <vscale x 4 x i32>
; CHECK: define {{.*}}i32 @huge_alloca(i64 %n)
; CHECK: alloca [16 x i8], i64 1152921504606846976
