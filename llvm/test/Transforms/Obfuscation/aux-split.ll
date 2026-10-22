; RUN: opt -S -passes='default<O0>' -irobf-split -irobf-split_num=2 < %s -o - | FileCheck %s
;
; The late split pass must add control-flow edges to a straight-line body.

define i32 @straight(i32 %a, i32 %b) {
entry:
  %x = add i32 %a, %b
  %y = mul i32 %x, 3
  %z = xor i32 %y, %a
  %w = add i32 %z, 7
  ret i32 %w
}

; CHECK: define i32 @straight
; CHECK-COUNT-2: br label
