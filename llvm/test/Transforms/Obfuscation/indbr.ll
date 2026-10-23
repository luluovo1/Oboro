; RUN: opt -S -passes='default<O0>' -irobf-indbr < %s | FileCheck %s
;
; Page-table indirect branches: every conditional edge becomes an indirectbr
; whose target comes from a global table via blockaddress.

define i32 @f(i32 %x) {
entry:
  %c = icmp sgt i32 %x, 10
  br i1 %c, label %t, label %e
t:
  ret i32 1
e:
  ret i32 0
}

; CHECK: blockaddress(@f
; CHECK: define {{.*}}@f
; CHECK: indirectbr
