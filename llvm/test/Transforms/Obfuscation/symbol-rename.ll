; RUN: opt -S -passes='default<O0>' -irobf-rename < %s -o - | FileCheck %s
;
; Internal symbols get opaque names; exported symbols and main keep theirs.

@internal_g = internal global i32 7
@public_g = global i32 9

define internal i32 @secret(i32 %x) {
entry:
  %r = add i32 %x, 11
  ret i32 %r
}

define i32 @public(i32 %x) {
entry:
  %r = call i32 @secret(i32 %x)
  %g = load i32, ptr @internal_g
  %s = add i32 %r, %g
  ret i32 %s
}

define i32 @main() {
entry:
  %r = call i32 @public(i32 1)
  ret i32 %r
}

; CHECK: @public_g = global
; CHECK-NOT: @secret
; CHECK-NOT: @internal_g
; CHECK: define i32 @public(
; CHECK: define i32 @main(
