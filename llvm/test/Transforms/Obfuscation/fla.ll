; RUN: opt -S -passes='default<O0>' -irobf-fla -irobf-debug-names < %s | FileCheck %s
;
; Flattening must replace the original control flow with a single dispatcher:
; every original block reaches loopEnd, loopEnd feeds keyHead, and the switch
; condition is derived from the encrypted state and the rolling key rather than
; from a stored plaintext value.

define i32 @f(i32 %x) {
entry:
  %a = add i32 %x, 1
  %c = icmp sgt i32 %a, 10
  br i1 %c, label %t, label %e
t:
  %d = mul i32 %a, 3
  ret i32 %d
e:
  %g = sub i32 %a, 2
  ret i32 %g
}

; CHECK: keyHead:
; CHECK: loopEntry:
; CHECK: switchCond = xor i64 %switchVar.enc0, %key
; The switch is lowered to a pivot tree, so the dispatcher shows up as icmp
; comparisons against the state instead of a switch instruction.
; CHECK: Pivot
; The state slot only ever receives ciphertext.
; CHECK: store volatile i64
; CHECK: loopEnd:
