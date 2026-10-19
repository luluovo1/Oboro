; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s
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

; CHECK: define i32 @dyn_alloca(i32 %n)
; CHECK: alloca i32, i32 %n
; CHECK-NOT: call i64 @
; CHECK: define <4 x i32> @vec(<4 x i32> %a)
; CHECK: add <4 x i32>
