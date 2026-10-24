; RUN: opt -S -passes='default<O0>' -irobf-icall -irobf-debug-names < %s | FileCheck %s
; RUN: opt -S -passes='default<O0>' -irobf-icall < %s | FileCheck %s --check-prefix=NAMED
;
; Every direct call must become a page-table lookup plus an indirect call, and
; the callee address must never appear as a direct call target afterwards.
; -irobf-debug-names keeps the pass-generated names readable; the NAMED run
; checks the production path, where the table name is randomised.

define internal i32 @callee(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}

define i32 @f(i32 %x) {
entry:
  %a = call i32 @callee(i32 %x)
  %b = call i32 @callee(i32 %a)
  ret i32 %b
}

; CHECK: _IndirectCallee_objects
; CHECK: ptrtoint (ptr @callee to i64)
; CHECK: _IndirectCallee_page_table_0
; CHECK: inttoptr i64
; CHECK: call i32 %Call_callee(
; CHECK: call i32 %Call_callee1(

; The table exists but must not be named after the pass in production.
; NAMED-NOT: _IndirectCallee_objects
; NAMED: inttoptr i64
