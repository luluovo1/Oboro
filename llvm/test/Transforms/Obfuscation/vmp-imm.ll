; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s
;
; Constants that feed a single binary operator are folded into the immediate
; form of the instruction instead of being materialised in the constant pool.
; The function must still be virtualised as a whole.

define i32 @imm(i32 %a) {
entry:
  %x = add i32 %a, 12345
  %y = shl i32 %x, 3
  %z = xor i32 %y, 7
  ret i32 %z
}

; A constant used twice cannot be folded: both uses need the same register.
define i32 @twice(i32 %a) {
entry:
  %x = mul i32 %a, 999
  %y = add i32 %x, 999
  ret i32 %y
}

; CHECK: define {{.*}}i32 @imm(i32 %a)
; CHECK-NOT: add i32
; CHECK: call i64 @
; CHECK: ret i32
; CHECK-NOT: i64 12345
; CHECK: define {{.*}}i32 @twice(i32 %a)
; CHECK-NOT: mul i32
; CHECK: call i64 @
; CHECK: ret i32
; CHECK: define internal i64 @
; CHECK: switch i32
