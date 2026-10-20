; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s
;
; Scalar floating point is carried as its bit pattern: arithmetic, comparison,
; conversions and FP constants must all translate, otherwise the function
; would be skipped.

define double @fpmath(double %a, float %b, i32 %n) {
entry:
  %x = fmul double %a, 1.500000e+00
  %y = fadd double %x, 2.250000e+00
  %z = fdiv double %y, 3.000000e+00
  %c = fcmp ogt double %z, 1.000000e+00
  %s = select i1 %c, double %z, double %x
  %f = fpext float %b to double
  %r = fadd double %s, %f
  %i = fptosi double %r to i32
  %d = sitofp i32 %i to double
  ret double %d
}

define float @fpcmp(float %a, float %b) {
entry:
  %c = fcmp ult float %a, %b
  %s = select i1 %c, float %a, float %b
  %m = frem float %s, 3.000000e+00
  ret float %m
}

; CHECK: define double @fpmath(
; CHECK: call i64 @
; CHECK: define float @fpcmp(
; CHECK: call i64 @
; CHECK: fadd double
; CHECK: fcmp ogt double
