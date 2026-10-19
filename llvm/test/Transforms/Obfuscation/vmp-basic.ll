; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s
;
; A virtualized function keeps its original signature and body size shrinks to
; a wrapper call; the module gains an internal interpreter with a dispatcher.

define i32 @check(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %y = mul i32 %x, 7
  %z = xor i32 %y, %a
  ret i32 %z
}

; CHECK: define i32 @check(i32 %0, i32 %1)
; CHECK-NOT: add i32
; CHECK: call i64 @
; CHECK: ret i32
; CHECK: define internal i64 @
; CHECK: switch i32
