; RUN: opt -S -passes='default<O0>' -irobf-fla < %s | FileCheck %s
;
; setjmp/longjmp restores registers and stack to the setjmp point. A
; flattened state variable would roll back to its old value, so the
; dispatcher can jump to the wrong case (or loop forever). Functions that
; call a returns_twice function must be left untouched.

declare i32 @_setjmp(ptr) returns_twice

define i32 @with_setjmp(i32 %x) {
entry:
  %buf = alloca i32, align 4
  %r = call i32 @_setjmp(ptr %buf)
  %c = icmp eq i32 %r, 0
  br i1 %c, label %zero, label %nonzero
zero:
  ret i32 1
nonzero:
  ret i32 2
}

define i32 @plain(i32 %x) {
entry:
  %c = icmp eq i32 %x, 0
  br i1 %c, label %zero, label %nonzero
zero:
  ret i32 1
nonzero:
  ret i32 2
}

; The setjmp function keeps its plain conditional branch...
; CHECK-LABEL: define i32 @with_setjmp
; CHECK-NOT: switch
; CHECK: br i1 %c, label %zero, label %nonzero
; CHECK-NOT: switch
;
; ...while a function without returns_twice is still flattened.
; CHECK-LABEL: define i32 @plain
; CHECK: switch
