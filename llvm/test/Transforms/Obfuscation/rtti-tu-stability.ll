; RUN: opt -S -passes='default<O0>' -irobf-rtti %p/Inputs/rtti-tu-a.ll -o - | grep -o 'c"[^"]*"' > %t.a
; RUN: opt -S -passes='default<O0>' -irobf-rtti %p/Inputs/rtti-tu-b.ll -o - | grep -o 'c"[^"]*"' > %t.b
; RUN: diff %t.a %t.b
;
; RUN: opt -S -passes='default<O0>' -irobf-rtti %p/Inputs/rtti-tu-a.ll -o - | FileCheck %s
;
; The RTTI name hash must not depend on anything per-run.  With no seed
; configured it is keyed by the type name alone, so two translation units
; describing the same type get the same mangled name and exception matching
; still works after linking.  A clock-based fallback would break this.

; CHECK-NOT: c".?AUA@@
; CHECK: c".?AU
