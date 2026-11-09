; RUN: opt -S -passes='default<O0>' -irobf-merge < %s -o - | FileCheck %s
; RUN: opt -S -passes='default<O0>' -irobf-merge -verify-each < %s -o /dev/null
;
; Members whose properties cannot survive cloning into a shared dispatcher
; must be rejected: i128 parameters would be truncated to the i64 slots, and
; noreturn would mark a dispatcher that does return.

define internal void @ok1(i32 %x) {
  ret void
}
define internal void @ok2(i32 %x) {
  ret void
}
define internal void @wide(i128 %x) {
  ret void
}
define internal void @noret(i32 %x) #0 {
  ret void
}
define void @caller(i32 %x) {
  call void @ok1(i32 %x)
  call void @ok2(i32 %x)
  call void @wide(i128 1)
  call void @noret(i32 %x)
  ret void
}
attributes #0 = { noreturn }

; CHECK: define internal void @wide(i128
; CHECK: define internal void @noret(i32
; CHECK-NOT: define internal void @ok1(
; CHECK-NOT: define internal void @ok2(
; CHECK: switch i32
