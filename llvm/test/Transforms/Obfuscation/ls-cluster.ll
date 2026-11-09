; RUN: opt -S -passes='default<O0>' -irobf-fla -verify-each < %s -o /dev/null
;
; Clusters that share a successor, sparse ranges and an unreachable default
; all exercise the PHI edge accounting in LowerSwitch.

define i32 @multi(i32 %x) {
entry:
  switch i32 %x, label %d [
    i32 0, label %a
    i32 1, label %a
    i32 2, label %a
    i32 5, label %b
    i32 6, label %b
  ]
a:
  ret i32 1
b:
  ret i32 2
d:
  ret i32 0
}

define i32 @unreach_default(i64 %x) {
entry:
  switch i64 %x, label %u [
    i64 0, label %a
    i64 1, label %a
    i64 2, label %a
    i64 3, label %a
  ]
a:
  ret i32 1
u:
  unreachable
}

define i32 @sparse_unreach(i64 %x) {
entry:
  switch i64 %x, label %u [
    i64 0, label %a
    i64 1000000, label %a
    i64 9223372036854775807, label %a
  ]
a:
  ret i32 1
u:
  unreachable
}
