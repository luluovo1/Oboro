; RUN: opt -S -passes='default<O0>' -irobf-indgv -irobf-debug-names < %s | FileCheck %s
; RUN: opt -S -passes='default<O0>' -irobf-indgv < %s | FileCheck %s --check-prefix=NAMED
;
; A global read must go through a page table: the address is materialised from
; an encrypted initializer and the load takes the resulting pointer, so the
; original "@g" never appears as a load operand.

@g = internal global i32 7

define i32 @f() {
entry:
  %b = load i32, ptr @g
  %c = add i32 %b, 1
  ret i32 %c
}

; CHECK: _IndirectGVs_objects
; CHECK: ptrtoint (ptr @g to i64)
; CHECK: inttoptr i64
; CHECK: load i32, ptr %
; CHECK-NOT: load i32, ptr @g

; NAMED-NOT: _IndirectGVs_objects
; NAMED: inttoptr i64
