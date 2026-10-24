; RUN: opt -S -passes='default<O0>' -irobf-cse -irobf-debug-names < %s | FileCheck %s
;
; A used string literal must be moved into an encrypted table and replaced by
; a call to a per-string decryptor, so the plaintext never reaches the call
; site directly. -irobf-debug-names keeps the generated names stable.

declare i32 @puts(ptr)

@s = private unnamed_addr constant [6 x i8] c"hello\00"

define i32 @f() {
entry:
  %p = call i32 @puts(ptr @s)
  ret i32 %p
}

; CHECK: @EncryptedStringTable
; CHECK: decrypt_string
; CHECK: call i32 @puts(ptr @dec0)
