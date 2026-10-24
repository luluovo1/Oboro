; RUN: opt -S -passes='default<O0>' -irobf-fla -irobf-bcf=100 -irobf-debug-names < %s | FileCheck %s
;
; Red-zone functions must never be rewritten: a weak definition can be replaced
; by another translation unit at link time, and global ctors/dtors run before
; the module's own initialisation. Obfuscating either changes behaviour that the
; program cannot observe from inside the pass. Both must stay untouched even
; with the strongest settings, while an ordinary function is transformed.

@g = global i32 0

define weak i32 @weakfn(i32 %a) {
entry:
  %b = add i32 %a, 1
  %c = icmp sgt i32 %b, 3
  br i1 %c, label %t, label %e
t:
  ret i32 %b
e:
  ret i32 %a
}

define internal void @_GLOBAL__sub_I_g() {
entry:
  store i32 1, ptr @g
  ret void
}

define i32 @normal(i32 %a) {
entry:
  %b = mul i32 %a, 3
  %c = icmp sgt i32 %b, 7
  br i1 %c, label %t, label %e
t:
  ret i32 %b
e:
  ret i32 %a
}

; CHECK-LABEL: define weak i32 @weakfn
; CHECK-NOT: keyHead
; CHECK-NOT: bcf.
; CHECK-LABEL: define internal void @_GLOBAL__sub_I_g
; CHECK-NOT: keyHead
; CHECK-NOT: bcf.
; CHECK-LABEL: define i32 @normal
; CHECK: keyHead
