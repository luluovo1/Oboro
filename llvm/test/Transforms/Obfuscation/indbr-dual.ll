; RUN: opt -S -passes='default<O1>' -irobf-indbr=dual < %s -o - | FileCheck %s
;
; Dual mode replaces a conditional branch with a two-target indirectbr whose
; destination is a select of two block addresses, and runs late so SimplifyCFG
; cannot turn it back into a branch.

define i32 @loop(i32 %n) {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %i.next, %body ]
  %s = phi i32 [ 0, %entry ], [ %s.next, %body ]
  %c = icmp slt i32 %i, %n
  br i1 %c, label %body, label %exit

body:
  %s.next = add i32 %s, %i
  %i.next = add i32 %i, 1
  br label %loop

exit:
  ret i32 %s
}

; CHECK: select i1
; CHECK: blockaddress(@loop
; CHECK: indirectbr ptr
