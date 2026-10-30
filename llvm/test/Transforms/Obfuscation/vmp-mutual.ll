; RUN: opt -S -passes='default<O0>' -irobf-vmp < %s -o - | FileCheck %s
;
; Mutual recursion forms a call cycle of two.  Neither function calls itself, so
; a direct self-call check alone would not see the cycle at all.  The cycle is
; small enough for the per-call VM budget, so both functions must still be
; virtualised: each wrapper calls an i64 interpreter.

define i32 @even(i32 %n) {
entry:
  %c = icmp sle i32 %n, 0
  br i1 %c, label %base, label %rec
base:
  ret i32 1
rec:
  %d = sub i32 %n, 1
  %t = call i32 @odd(i32 %d)
  %r = add i32 %t, %n
  ret i32 %r
}

define i32 @odd(i32 %n) {
entry:
  %c = icmp sle i32 %n, 0
  br i1 %c, label %base, label %rec
base:
  ret i32 0
rec:
  %d = sub i32 %n, 1
  %t = call i32 @even(i32 %d)
  %r = xor i32 %t, %n
  ret i32 %r
}

; CHECK: define i32 @even
; CHECK: call i64 @
; CHECK: define i32 @odd
; CHECK: call i64 @
