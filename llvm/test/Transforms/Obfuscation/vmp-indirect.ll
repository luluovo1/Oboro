; RUN: opt -S -passes='default<O0>' -irobf-vmp < %s -o - | FileCheck %s
;
; Indirect and variadic call sites must be virtualised through a two-argument
; thunk (argument block + dynamic callee), and the thunk must keep the
; concrete argument types of the site.

@tbl = private constant [2 x ptr] [ptr @add, ptr @sub], align 8
@fmt = private constant [7 x i8] c"%d %d\0A\00"

declare i32 @printf(ptr, ...)

define i32 @add(i32 %a, i32 %b) {
entry:
  %r = add i32 %a, %b
  ret i32 %r
}

define i32 @sub(i32 %a, i32 %b) {
entry:
  %r = sub i32 %a, %b
  ret i32 %r
}

define i32 @indirect(i32 %k, i32 %a, i32 %b) {
entry:
  %i = and i32 %k, 1
  %p = getelementptr [2 x ptr], ptr @tbl, i64 0, i32 %i
  %f = load ptr, ptr %p
  %r = call i32 %f(i32 %a, i32 %b)
  %v = call i32 (ptr, ...) @printf(ptr @fmt, i32 %r, i32 %a)
  ret i32 %r
}

; CHECK: define i32 @indirect(
; CHECK: call i64 @
; CHECK: define internal i64 @
; CHECK: call i32 %{{[0-9]+}}(i32
; CHECK: call i32 (ptr, ...) @printf
