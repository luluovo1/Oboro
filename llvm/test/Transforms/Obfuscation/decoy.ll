; RUN: opt -S -passes='default<O0>' -irobf-decoy=100 -irobf-debug-names < %s | FileCheck %s
;
; decoy is an independent feature domain: it must work without -irobf-bcf.
; The module gets a weak probe definition and a getenv-based runtime.

define i32 @f(i32 %x) {
entry:
  %a = add i32 %x, 1
  %b = mul i32 %a, 3
  ret i32 %b
}

; CHECK-DAG: define {{.*}}@f
; CHECK-DAG: bcf.env
; CHECK-DAG: @oboro.getenv
; CHECK-DAG: define weak hidden i32 @__oboro_probe
