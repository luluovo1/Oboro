; RUN: opt -S -passes='default<O0>' -irobf-cse -irobf-debug-names < %s | FileCheck %s
;
; RTTI type-name strings (Itanium _ZTS*) are compared directly by
; dynamic_cast and exception matching at runtime. They are referenced as
; data, so there is no use site where a decryptor could be inserted;
; encrypting them makes every dynamic_cast return null. Ordinary literals
; must still be encrypted.

@_ZTS3Foo = private unnamed_addr constant [5 x i8] c"3Foo\00", align 1
@s = private unnamed_addr constant [6 x i8] c"hello\00", align 1

declare i32 @puts(ptr)

define i32 @f() {
entry:
  %p = call i32 @puts(ptr @s)
  ret i32 %p
}

; CHECK-DAG: @_ZTS3Foo = private unnamed_addr constant [5 x i8] c"3Foo\00"
; CHECK-DAG: @EncryptedStringTable
; CHECK: call i32 @puts(ptr @dec0)
