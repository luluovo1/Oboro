; RUN: opt -S -passes='default<O0>' -irobf-bcf=100 -irobf-debug-names < %s | FileCheck %s
;
; BCF must actually insert opaque-predicate diamonds. -irobf-bcf=100 forces
; every eligible block, and -irobf-debug-names keeps the bcf.* labels so the
; check does not depend on the random naming layer.

define i32 @f(i32 %x) {
entry:
  %a = add i32 %x, 1
  %b = mul i32 %a, 3
  %c = icmp sgt i32 %b, 10
  br i1 %c, label %t, label %e
t:
  %d = sub i32 %b, 2
  ret i32 %d
e:
  ret i32 %b
}

; CHECK: define i32 @f
; CHECK: bcf.ctr
; CHECK: bcf.bogus
; CHECK: bcf.j
