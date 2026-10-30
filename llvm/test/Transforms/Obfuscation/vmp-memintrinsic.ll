; RUN: opt -S -passes='default<O0>' -irobf-vmp < %s -o - | FileCheck %s
;
; Two memset intrinsics with different length widths used to collide on the
; synthesised `memset` declaration: the second one reused the first one's
; prototype, so the call the thunk built did not match it.  The module also
; declares memset itself, with the void-returning prototype some code uses, so
; the thunk has to convert to the declaration's real parameter types.

declare void @memset(ptr, i32, i64)
declare void @llvm.memset.p0.i32(ptr, i8, i32, i1)
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

define void @set32(ptr %p, i32 %n) {
entry:
  call void @llvm.memset.p0.i32(ptr %p, i8 0, i32 %n, i1 false)
  ret void
}

define void @set64(ptr %p, i64 %n) {
entry:
  call void @llvm.memset.p0.i64(ptr %p, i8 1, i64 %n, i1 false)
  ret void
}

; CHECK: define {{.*}}void @set32(ptr %p, i32 %n)
; CHECK: call i64 @
; CHECK: define {{.*}}void @set64(ptr %p, i64 %n)
; CHECK: call i64 @
