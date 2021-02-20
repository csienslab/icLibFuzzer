; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+amx-int8 -mattr=+avx512f -verify-machineinstrs | FileCheck %s
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"

define dso_local void @test_chain(i8* %A_mem, i8* %B_mem, i8* %C_mem) local_unnamed_addr {
; CHECK-LABEL: test_chain:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    vpxord %zmm0, %zmm0, %zmm0
; CHECK-NEXT:    vmovdqu64 %zmm0, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb $1, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb $16, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw $64, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb $16, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw $64, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb $16, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw $64, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb $16, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw $64, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb $16, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw $64, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    ldtilecfg -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movl $64, %r8d
; CHECK-NEXT:    movw $64, %cx
; CHECK-NEXT:    movw $16, %ax
; CHECK-NEXT:    tileloadd (%rdi,%r8), %tmm0
; CHECK-NEXT:    addq $1024, %rdi # imm = 0x400
; CHECK-NEXT:    tileloadd (%rdi,%r8), %tmm1
; CHECK-NEXT:    tileloadd (%rdx,%r8), %tmm3
; CHECK-NEXT:    leaq 1024(%rdx), %rdi
; CHECK-NEXT:    tileloadd (%rdi,%r8), %tmm2
; CHECK-NEXT:    tileloadd (%rsi,%r8), %tmm4
; CHECK-NEXT:    tdpbssd %tmm4, %tmm0, %tmm3
; CHECK-NEXT:    tilestored %tmm3, (%rdx,%r8)
; CHECK-NEXT:    tdpbssd %tmm4, %tmm1, %tmm2
; CHECK-NEXT:    tilestored %tmm2, (%rdi,%r8)
; CHECK-NEXT:    tilerelease
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    retq
entry:
  %a1 = call <256 x i32> @llvm.x86.tileloadd64.internal(i16 16, i16 64, i8* nonnull %A_mem, i64 64)
  %addr = getelementptr inbounds i8, i8* %A_mem, i64 1024
  %a2 = call <256 x i32> @llvm.x86.tileloadd64.internal(i16 16, i16 64, i8* nonnull %addr, i64 64)
  %c1 = call <256 x i32> @llvm.x86.tileloadd64.internal(i16 16, i16 64, i8* nonnull %C_mem, i64 64)
  %caddr = getelementptr inbounds i8, i8* %C_mem, i64 1024
  %c2 = call <256 x i32> @llvm.x86.tileloadd64.internal(i16 16, i16 64, i8* nonnull %caddr, i64 64)
  br label %dotpd

dotpd:
  %b = call <256 x i32> @llvm.x86.tileloadd64.internal(i16 16, i16 64, i8* nonnull %B_mem, i64 64)
  %dp1 = call <256 x i32> @llvm.x86.tdpbssd.internal(i16 16, i16 64, i16 64, <256 x i32> %c1, <256 x i32> %a1, <256 x i32> %b)
  call void @llvm.x86.tilestored64.internal(i16 16, i16 64, i8* nonnull %C_mem, i64 64, <256 x i32> %dp1)
  %dp2 = call <256 x i32> @llvm.x86.tdpbssd.internal(i16 16, i16 64, i16 64, <256 x i32> %c2, <256 x i32> %a2, <256 x i32> %b)
  call void @llvm.x86.tilestored64.internal(i16 16, i16 64, i8* nonnull %caddr, i64 64, <256 x i32> %dp2)
  ret void
}

declare <256 x i32> @llvm.x86.tileloadd64.internal(i16, i16, i8*, i64)
declare <256 x i32> @llvm.x86.tdpbssd.internal(i16, i16, i16, <256 x i32>, <256 x i32>, <256 x i32>)
declare void @llvm.x86.tilestored64.internal(i16, i16, i8*, i64, <256 x i32>)