; RUN: opt -S -passes='default<O2>' < %s -o - | FileCheck %s
;
; Without -irobf-vmp, only the annotated function is virtualized.

@.str = private unnamed_addr constant [5 x i8] c"+vmp\00", align 1

define i32 @protected(i32 %a) {
entry:
  %x = mul i32 %a, 3
  ret i32 %x
}

define i32 @plain(i32 %a) {
entry:
  %x = mul i32 %a, 3
  ret i32 %x
}

@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }]
  [{ ptr, ptr, ptr, i32, ptr } { ptr @protected, ptr @.str, ptr @.str, i32 0, ptr null }],
  section "llvm.metadata"

; CHECK: define i32 @protected(i32 %0)
; CHECK: call i64 @
; CHECK: define i32 @plain(i32 %a)
; CHECK: mul i32 %a, 3
