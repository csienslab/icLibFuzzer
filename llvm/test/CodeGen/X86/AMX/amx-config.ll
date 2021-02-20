; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -mattr=+amx-int8 -verify-machineinstrs | FileCheck %s

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@buf = dso_local global [1024 x i8] zeroinitializer, align 16
@buf2 = dso_local global [1024 x i8] zeroinitializer, align 16

; Function Attrs: nounwind uwtable
define dso_local void @test_api(i32 %0, i16 signext %1, i16 signext %2) local_unnamed_addr #2 {
; CHECK-LABEL: test_api:
; CHECK:       # %bb.0:
; CHECK-NEXT:    movsbl %sil, %eax
; CHECK-NEXT:    vpxord %zmm0, %zmm0, %zmm0
; CHECK-NEXT:    vmovdqu64 %zmm0, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb $1, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb %al, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw %si, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb %al, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw %dx, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movb %al, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    movw %dx, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    ldtilecfg -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    testl %edi, %edi
; CHECK-NEXT:    je .LBB0_2
; CHECK-NEXT:  # %bb.1:
; CHECK-NEXT:    movl $buf, %ecx
; CHECK-NEXT:    jmp .LBB0_3
; CHECK-NEXT:  .LBB0_2:
; CHECK-NEXT:    movl $buf2, %ecx
; CHECK-NEXT:  .LBB0_3:
; CHECK-NEXT:    movl $32, %edi
; CHECK-NEXT:    tileloadd (%rcx,%rdi), %tmm0
; CHECK-NEXT:    tileloadd (%rcx,%rdi), %tmm2
; CHECK-NEXT:    tileloadd (%rcx,%rdi), %tmm1
; CHECK-NEXT:    tdpbssd %tmm2, %tmm0, %tmm1
; CHECK-NEXT:    movl $buf, %ecx
; CHECK-NEXT:    movl $32, %esi
; CHECK-NEXT:    tilestored %tmm1, (%rcx,%rsi)
; CHECK-NEXT:    tilerelease
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    retq
  %4 = icmp eq i32 %0, 0
  %5 = shl i16 %1, 8
  %6 = ashr exact i16 %5, 8
  br i1 %4, label %11, label %7

7:                                                ; preds = %3
  %8 = tail call <256 x i32> @llvm.x86.tileloadd64.internal(i16 %6, i16 %1, i8* getelementptr inbounds ([1024 x i8], [1024 x i8]* @buf, i64 0, i64 0), i64 32) #3
  %9 = tail call <256 x i32> @llvm.x86.tileloadd64.internal(i16 %6, i16 %2, i8* getelementptr inbounds ([1024 x i8], [1024 x i8]* @buf, i64 0, i64 0), i64 32) #3
  %10 = tail call <256 x i32> @llvm.x86.tileloadd64.internal(i16 %6, i16 %2, i8* getelementptr inbounds ([1024 x i8], [1024 x i8]* @buf, i64 0, i64 0), i64 32) #3
  br label %15

11:                                               ; preds = %3
  %12 = tail call <256 x i32> @llvm.x86.tileloadd64.internal(i16 %6, i16 %1, i8* getelementptr inbounds ([1024 x i8], [1024 x i8]* @buf2, i64 0, i64 0), i64 32) #3
  %13 = tail call <256 x i32> @llvm.x86.tileloadd64.internal(i16 %6, i16 %2, i8* getelementptr inbounds ([1024 x i8], [1024 x i8]* @buf2, i64 0, i64 0), i64 32) #3
  %14 = tail call <256 x i32> @llvm.x86.tileloadd64.internal(i16 %6, i16 %2, i8* getelementptr inbounds ([1024 x i8], [1024 x i8]* @buf2, i64 0, i64 0), i64 32) #3
  br label %15

15:                                               ; preds = %11, %7
  %16 = phi <256 x i32> [ %12, %11 ], [ %8, %7 ]
  %17 = phi <256 x i32> [ %13, %11 ], [ %9, %7 ]
  %18 = phi <256 x i32> [ %14, %11 ], [ %10, %7 ]
  %19 = tail call <256 x i32> @llvm.x86.tdpbssd.internal(i16 %6, i16 %2, i16 %1, <256 x i32> %18, <256 x i32> %16, <256 x i32> %17) #3
  tail call void @llvm.x86.tilestored64.internal(i16 %6, i16 %2, i8* getelementptr inbounds ([1024 x i8], [1024 x i8]* @buf, i64 0, i64 0), i64 32, <256 x i32> %19) #3
  ret void
}

declare <256 x i32> @llvm.x86.tileloadd64.internal(i16, i16, i8*, i64) #3

declare <256 x i32> @llvm.x86.tdpbssd.internal(i16, i16, i16, <256 x i32>, <256 x i32>, <256 x i32>) #3

declare void @llvm.x86.tilestored64.internal(i16, i16, i8*, i64, <256 x i32>) #3

attributes #2 = { nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="8192" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+amx-int8,+amx-tile,+avx,+avx2,+avx512f,+cx8,+f16c,+fma,+fxsr,+mmx,+popcnt,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+ssse3,+x87,+xsave" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind }