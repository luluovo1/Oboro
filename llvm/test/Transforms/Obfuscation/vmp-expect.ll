; RUN: opt -S -passes='default<O0>' -irobf-vmp -verify-each < %s -o /dev/null
; RUN: opt -S -passes='default<O0>' -irobf-vmp < %s -o - | FileCheck %s
;
; llvm.expect used to alias its result to the operand register.  Once the
; operand died the register was recycled and the result read a stale value.

declare i64 @llvm.expect.i64(i64, i64)
define i64 @f(i64 %a, i64 %b) {
  %x = add i64 %a, %b
  %e = call i64 @llvm.expect.i64(i64 %x, i64 1)
  %r = add i64 %e, 1
  ret i64 %r
}

; CHECK: define i64 @f
