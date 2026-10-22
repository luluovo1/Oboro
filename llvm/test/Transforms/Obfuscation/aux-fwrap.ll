; RUN: opt -S -passes='default<O0>' -irobf-fwrap < %s -o - | FileCheck %s
;
; Direct calls are retargeted to an internal forwarding wrapper.

define i32 @callee(i32 %x) {
entry:
  %r = add i32 %x, 9
  ret i32 %r
}

define i32 @caller(i32 %x) {
entry:
  %r = call i32 @callee(i32 %x)
  ret i32 %r
}

; CHECK: define i32 @caller(
; CHECK: call i32 @{{.*}}(i32 %x)
; CHECK: define internal i32 @{{.*}}(i32
; CHECK: call i32 @callee
; CHECK: "oboro.wrapper"
