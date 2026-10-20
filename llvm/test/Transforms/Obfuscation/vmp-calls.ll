; RUN: opt -S -passes='default<O0>' -irobf-vmp < %s -o - | FileCheck %s
;
; A call site makes the pass emit a forwarding thunk.  The pass must not then
; virtualise that thunk (which would emit another thunk, and so on): the module
; stays at two wrappers, two interpreters and one thunk.

define i32 @callee(i32 %x) {
entry:
  %r = add i32 %x, 7
  ret i32 %r
}

define i32 @caller(i32 %x) {
entry:
  %r = call i32 @callee(i32 %x)
  %s = mul i32 %r, 3
  ret i32 %s
}

; CHECK-COUNT-5: define
; CHECK: call i64 @
