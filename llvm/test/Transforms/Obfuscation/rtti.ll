; RUN: opt -S -passes='default<O0>' -irobf-rtti < %s | FileCheck %s
;
; MSVC RTTI type descriptors keep the class name in a string constant.
; The pass must rewrite that string in place.

target triple = "x86_64-pc-windows-msvc"

%rtti.TypeDescriptor7 = type { ptr, ptr, [8 x i8] }

$"??_R0?AUA@@@8" = comdat any

@"??_7type_info@@6B@" = external constant ptr
@"??_R0?AUA@@@8" = linkonce_odr global %rtti.TypeDescriptor7 { ptr @"??_7type_info@@6B@", ptr null, [8 x i8] c".?AUA@@\00" }, comdat

define i32 @f() {
entry:
  ret i32 0
}

; CHECK: define {{.*}}@f
; CHECK-NOT: .?AUA@@
