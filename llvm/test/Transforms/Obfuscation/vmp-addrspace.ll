; RUN: opt -S -passes='default<O0>' -irobf-vmp < %s -o - | FileCheck %s
;
; A datalayout that moves allocas and globals out of address space 0 cannot
; host the interpreter: the frame would be a ptr addrspace(200) passed to a
; function declared to take ptr, which is a hard type error, and the constant
; pools would live in a space the VM cannot index with i64 arithmetic.  Every
; function has to be left alone.

target datalayout = "e-m:e-p200:128:128:128:64-A200-P200-G200"

define i32 @f(i32 %x) {
entry:
  %y = add i32 %x, 5
  ret i32 %y
}

; CHECK: define {{.*}}i32 @f(i32 %x)
; CHECK: add i32 %x, 5
; CHECK-NOT: call i64 @
