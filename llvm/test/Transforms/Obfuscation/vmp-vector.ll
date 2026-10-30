; RUN: opt -S -passes='default<O2>' -irobf-vmp < %s -o - | FileCheck %s
;
; SLP turns constant initialisers and struct copies into vector accesses, which
; the VM cannot represent.  Such a function is retried after the vector memory
; operations are split into one access per element, so it is still virtualized
; instead of being skipped.
;
; The element accesses must line up with the vector layout: <4 x i32> and
; <2 x ptr> both have the same size as the equivalent array.

define i32 @const_store(ptr %p) {
entry:
  store <4 x i32> <i32 0, i32 0, i32 0, i32 1>, ptr %p, align 8
  %v = load i32, ptr %p, align 4
  ret i32 %v
}

; CHECK: define {{.*}}i32 @const_store(
; CHECK-NOT: store <4 x i32>
; CHECK: call i64 @
; CHECK: ret i32

define i32 @copy_and_use(ptr %a, ptr %b) {
entry:
  %v = load <2 x ptr>, ptr %a, align 8
  store <2 x ptr> %v, ptr %b, align 8
  %e = extractelement <2 x ptr> %v, i64 0
  %c = icmp ne ptr %e, null
  %r = zext i1 %c to i32
  ret i32 %r
}

; CHECK: define {{.*}}i32 @copy_and_use(
; CHECK-NOT: load <2 x ptr>
; CHECK-NOT: extractelement
; CHECK: call i64 @
; CHECK: ret i32

; Vector arithmetic is not splittable, so a function that contains it is still
; skipped: the retry must not pessimise code it cannot virtualize anyway.

declare void @sink(<4 x i32>)

define i32 @vector_math(<4 x i32> %v) {
entry:
  %m = mul <4 x i32> %v, <i32 3, i32 3, i32 3, i32 3>
  call void @sink(<4 x i32> %m)
  ret i32 7
}

; CHECK: define {{.*}}i32 @vector_math(
; CHECK: mul <4 x i32>
; CHECK: call void @sink(<4 x i32>
; CHECK: ret i32 7

; A broadcast (insertelement + shufflevector) that is only stored is the shape
; SLP leaves behind for a duplicated field.  Splitting the store makes the whole
; chain dead, so the function still gets virtualized.

define void @broadcast_store(ptr %p, i32 %x) {
entry:
  %ins = insertelement <2 x i32> poison, i32 %x, i64 0
  %splat = shufflevector <2 x i32> %ins, <2 x i32> poison, <4 x i32> zeroinitializer
  store <4 x i32> %splat, ptr %p, align 1
  ret void
}

; CHECK: define {{.*}}void @broadcast_store(
; CHECK-NOT: store <4 x i32>
; CHECK-NOT: shufflevector
; CHECK: call i64 @
; CHECK: ret void

; The same broadcast feeding vector arithmetic is rebuilt lane by lane, so the
; chain disappears instead of keeping the function out of the virtualiser.

define void @broadcast_math(ptr %p, ptr %q, i8 %x) {
entry:
  %ins = insertelement <4 x i8> poison, i8 %x, i64 0
  %splat = shufflevector <4 x i8> %ins, <4 x i8> poison, <4 x i32> zeroinitializer
  %v = load <4 x i8>, ptr %q, align 1
  %a = and <4 x i8> %v, %splat
  store <4 x i8> %a, ptr %p, align 1
  ret void
}

; CHECK: define {{.*}}void @broadcast_math(
; CHECK-NOT: shufflevector
; CHECK-NOT: and <4 x i8>
; CHECK: call i64 @
; CHECK: ret void

; Vector arithmetic on loaded values: add, compare, select and a cast are each
; expanded into one scalar operation per lane.

define void @vec_add(ptr %p, ptr %q) {
entry:
  %a = load <4 x i32>, ptr %p, align 16
  %b = load <4 x i32>, ptr %q, align 16
  %s = add <4 x i32> %a, %b
  %m = mul <4 x i32> %s, <i32 3, i32 5, i32 7, i32 11>
  store <4 x i32> %m, ptr %p, align 16
  ret void
}

; CHECK: define {{.*}}void @vec_add(
; CHECK-NOT: add <4 x i32>
; CHECK-NOT: mul <4 x i32>
; CHECK-NOT: load <4 x i32>
; CHECK: call i64 @
; CHECK: ret void

define void @vec_cmp_sel(ptr %p, ptr %q) {
entry:
  %a = load <4 x i32>, ptr %p, align 16
  %b = load <4 x i32>, ptr %q, align 16
  %c = icmp slt <4 x i32> %a, %b
  %s = select <4 x i1> %c, <4 x i32> %a, <4 x i32> zeroinitializer
  store <4 x i32> %s, ptr %p, align 16
  ret void
}

; CHECK: define {{.*}}void @vec_cmp_sel(
; CHECK-NOT: icmp slt <4 x i32>
; CHECK-NOT: select <4 x i1>
; CHECK: call i64 @
; CHECK: ret void

define void @vec_shuffle_cast(ptr %p, ptr %q) {
entry:
  %a = load <4 x i16>, ptr %p, align 8
  %b = load <4 x i16>, ptr %q, align 8
  %x = shufflevector <4 x i16> %a, <4 x i16> %b, <4 x i32> <i32 0, i32 5, i32 2, i32 7>
  %w = sext <4 x i16> %x to <4 x i32>
  store <4 x i32> %w, ptr %p, align 16
  ret void
}

; CHECK: define {{.*}}void @vec_shuffle_cast(
; CHECK-NOT: shufflevector
; CHECK-NOT: sext <4 x i16>
; CHECK: call i64 @
; CHECK: ret void

; A bitcast has no per-lane meaning -- it reinterprets the whole register -- so
; a function holding one is still skipped.

define i32 @vec_bitcast(ptr %p, ptr %q) {
entry:
  %a = load <4 x i8>, ptr %p, align 4
  %b = load <4 x i8>, ptr %q, align 4
  %x = xor <4 x i8> %a, %b
  %v = bitcast <4 x i8> %x to i32
  ret i32 %v
}

; CHECK: define {{.*}}i32 @vec_bitcast(
; CHECK-NOT: call i64 @
; CHECK: bitcast <4 x i8>
; CHECK: ret i32

; An elementwise intrinsic means the same thing lane by lane, so it expands
; into one call to the scalar overload per lane.

declare <8 x i16> @llvm.usub.sat.v8i16(<8 x i16>, <8 x i16>)

define void @vec_sat_sub(ptr %p, ptr %q) {
entry:
  %a = load <8 x i16>, ptr %p, align 16
  %b = load <8 x i16>, ptr %q, align 16
  %s = call <8 x i16> @llvm.usub.sat.v8i16(<8 x i16> %a, <8 x i16> %b)
  store <8 x i16> %s, ptr %p, align 16
  ret void
}

; CHECK: define {{.*}}void @vec_sat_sub(
; CHECK-NOT: usub.sat.v8i16
; CHECK-NOT: load <8 x i16>
; CHECK: call i64 @
; CHECK: ret void

; A vector PHI becomes one scalar PHI per lane, and a reduction folds the lanes
; back into a scalar, so the loop body no longer holds a vector value.

declare i32 @llvm.vector.reduce.add.v4i32(<4 x i32>)

define i32 @vec_loop_reduce(ptr %p, i32 %n) {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %i.next, %loop ]
  %acc = phi <4 x i32> [ zeroinitializer, %entry ], [ %sum, %loop ]
  %v = load <4 x i32>, ptr %p, align 16
  %sum = add <4 x i32> %acc, %v
  %i.next = add i32 %i, 1
  %done = icmp eq i32 %i.next, %n
  br i1 %done, label %exit, label %loop

exit:
  %r = call i32 @llvm.vector.reduce.add.v4i32(<4 x i32> %acc)
  ret i32 %r
}

; CHECK: define {{.*}}i32 @vec_loop_reduce(
; CHECK-NOT: phi <4 x i32>
; CHECK-NOT: vector.reduce
; CHECK-NOT: add <4 x i32>
; CHECK: call i64 @
; CHECK: ret i32

; An elementwise intrinsic that also takes a scalar immediate keeps the scalar
; argument as-is, and a max-reduction folds the lanes with a compare+select.

declare <4 x i32> @llvm.ctlz.v4i32(<4 x i32>, i1 immarg)
declare i32 @llvm.vector.reduce.smax.v4i32(<4 x i32>)

define i32 @vec_ctlz_reduce(ptr %p) {
entry:
  %a = load <4 x i32>, ptr %p, align 16
  %l = call <4 x i32> @llvm.ctlz.v4i32(<4 x i32> %a, i1 false)
  %r = call i32 @llvm.vector.reduce.smax.v4i32(<4 x i32> %l)
  ret i32 %r
}

; CHECK: define {{.*}}i32 @vec_ctlz_reduce(
; CHECK-NOT: ctlz.v4i32
; CHECK-NOT: vector.reduce
; CHECK-NOT: load <4 x i32>
; CHECK: call i64 @
; CHECK: ret i32

; A very wide vector would multiply the function instead of shrinking it, so
; the rewrite refuses to touch it and the function stays as it was.

define void @vec_wide(ptr %p) {
entry:
  %a = load <128 x i32>, ptr %p, align 64
  %b = add <128 x i32> %a, %a
  store <128 x i32> %b, ptr %p, align 64
  ret void
}

; CHECK: define {{.*}}void @vec_wide(
; CHECK-NOT: call i64 @
; CHECK: store <128 x i32>
; CHECK: ret void
