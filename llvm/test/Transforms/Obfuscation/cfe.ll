; RUN: opt -S -passes='default<O0>' -irobf-cfe < %s | FileCheck %s
;
; Floating-point constant encryption must remove the plaintext value.

define double @cf() {
entry:
  ret double 3.14159265358979
}

; CHECK: define double @cf
; CHECK-NOT: 3.14159265358979
