; RUN: opt -S -passes='default<O0>' -irobf-fla -verify-each < %s -o - | FileCheck %s
;
; LowerSwitch only handles up to 64-bit switches.  A wider switch must be left
; alone rather than truncated through getSExtValue().

define i32 @f(i128 %x) {
entry:
  switch i128 %x, label %d [
    i128 0, label %a
    i128 1, label %b
  ]
a:
  ret i32 1
b:
  ret i32 2
d:
  ret i32 0
}

; CHECK: switch i128
