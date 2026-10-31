; RUN: opt -S -passes='default<O0>' -irobf-merge < %s -o - | FileCheck %s
; RUN: opt -S -passes='default<O0>' -irobf-merge -verify-each < %s -o /dev/null
;
; Eligible internal void functions are cloned into one dispatcher, their call
; sites are rewritten to pass an id, and the originals are erased.  Everything
; that could leave a dangling reference is skipped: address-taken functions,
; non-void functions and functions reachable from outside the module.

define internal void @a(i32 %x) {
  ret void
}

define internal void @b(i32 %x, i32 %y) {
  ret void
}

define void @caller() {
  call void @a(i32 1)
  call void @b(i32 2, i32 3)
  ret void
}

; CHECK-LABEL: define void @caller()
; The call sites now pass an id to the dispatcher instead of calling @a / @b.
; CHECK-NOT:     call void @a(
; CHECK-NOT:     call void @b(

; Address taken: never merged.
define internal void @addr_taken() {
  ret void
}
@fp = global ptr @addr_taken

; CHECK: define internal void @addr_taken()

; Non-void: never merged.
define internal i32 @returns_value() {
  ret i32 7
}

; CHECK: define internal i32 @returns_value()

; The dispatcher: one case per merged member, and a trap for any other id.
; CHECK: switch i32
; CHECK: call void @llvm.trap()
; CHECK: unreachable

; The original symbols are gone from the whole module.
; CHECK-NOT: define internal void @a(
; CHECK-NOT: define internal void @b(
