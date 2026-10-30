; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s
;
; The default edge of a switch may land on a block whose PHIs are live.  Those
; copies used to make the translator give up on the whole function; they are
; now emitted like any other edge, including the parallel-assignment case where
; two PHIs exchange values.

define i32 @swphi(i32 %n, i32 %m) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %inc, %latch ]
  %acc = phi i32 [ 1, %entry ], [ %acc.next, %latch ]
  %cmp = icmp slt i32 %i, %n
  br i1 %cmp, label %body, label %exit
body:
  switch i32 %m, label %latch [ i32 0, label %case0
                                i32 1, label %case1 ]
case0:
  %a0 = add i32 %acc, %i
  br label %latch
case1:
  %a1 = xor i32 %acc, %i
  br label %latch
latch:
  %acc.next = phi i32 [ %a0, %case0 ], [ %a1, %case1 ], [ %acc, %body ]
  %inc = add i32 %i, 1
  br label %loop
exit:
  ret i32 %acc
}

; CHECK: define {{.*}}i32 @swphi(i32 %n, i32 %m)
; CHECK-NOT: switch i32 %m
; CHECK: call i64 @
; CHECK: ret i32
; CHECK: define internal i64 @
; CHECK: switch i32
