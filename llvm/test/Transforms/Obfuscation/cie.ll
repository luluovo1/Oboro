; RUN: opt -S -passes='default<O0>' -irobf-cie < %s | FileCheck %s
;
; Integer constant encryption must remove the plaintext value from the IR.

define i32 @ci() {
entry:
  ret i32 305419896
}

; CHECK: define i32 @ci
; CHECK-NOT: 305419896
