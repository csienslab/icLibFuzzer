; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=riscv32 -verify-machineinstrs < %s \
; RUN:   | FileCheck %s -check-prefix=RV32I
; RUN: llc -mtriple=riscv32 -mattr=+experimental-b -verify-machineinstrs < %s \
; RUN:   | FileCheck %s -check-prefix=RV32IB
; RUN: llc -mtriple=riscv32 -mattr=+experimental-zbb -verify-machineinstrs < %s \
; RUN:   | FileCheck %s -check-prefix=RV32IBB
; RUN: llc -mtriple=riscv32 -mattr=+experimental-zbp -verify-machineinstrs < %s \
; RUN:   | FileCheck %s -check-prefix=RV32IBP

define i32 @andn_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: andn_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    not a1, a1
; RV32I-NEXT:    and a0, a1, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: andn_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    andn a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: andn_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    andn a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: andn_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    andn a0, a0, a1
; RV32IBP-NEXT:    ret
  %neg = xor i32 %b, -1
  %and = and i32 %neg, %a
  ret i32 %and
}

define i64 @andn_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: andn_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    not a3, a3
; RV32I-NEXT:    not a2, a2
; RV32I-NEXT:    and a0, a2, a0
; RV32I-NEXT:    and a1, a3, a1
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: andn_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    andn a0, a0, a2
; RV32IB-NEXT:    andn a1, a1, a3
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: andn_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    andn a0, a0, a2
; RV32IBB-NEXT:    andn a1, a1, a3
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: andn_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    andn a0, a0, a2
; RV32IBP-NEXT:    andn a1, a1, a3
; RV32IBP-NEXT:    ret
  %neg = xor i64 %b, -1
  %and = and i64 %neg, %a
  ret i64 %and
}

define i32 @orn_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: orn_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    not a1, a1
; RV32I-NEXT:    or a0, a1, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: orn_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    orn a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: orn_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    orn a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: orn_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    orn a0, a0, a1
; RV32IBP-NEXT:    ret
  %neg = xor i32 %b, -1
  %or = or i32 %neg, %a
  ret i32 %or
}

define i64 @orn_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: orn_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    not a3, a3
; RV32I-NEXT:    not a2, a2
; RV32I-NEXT:    or a0, a2, a0
; RV32I-NEXT:    or a1, a3, a1
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: orn_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    orn a0, a0, a2
; RV32IB-NEXT:    orn a1, a1, a3
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: orn_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    orn a0, a0, a2
; RV32IBB-NEXT:    orn a1, a1, a3
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: orn_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    orn a0, a0, a2
; RV32IBP-NEXT:    orn a1, a1, a3
; RV32IBP-NEXT:    ret
  %neg = xor i64 %b, -1
  %or = or i64 %neg, %a
  ret i64 %or
}

define i32 @xnor_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: xnor_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    xor a0, a0, a1
; RV32I-NEXT:    not a0, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: xnor_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    xnor a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: xnor_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    xnor a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: xnor_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    xnor a0, a0, a1
; RV32IBP-NEXT:    ret
  %neg = xor i32 %a, -1
  %xor = xor i32 %neg, %b
  ret i32 %xor
}

define i64 @xnor_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: xnor_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    xor a1, a1, a3
; RV32I-NEXT:    xor a0, a0, a2
; RV32I-NEXT:    not a0, a0
; RV32I-NEXT:    not a1, a1
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: xnor_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    xnor a0, a0, a2
; RV32IB-NEXT:    xnor a1, a1, a3
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: xnor_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    xnor a0, a0, a2
; RV32IBB-NEXT:    xnor a1, a1, a3
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: xnor_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    xnor a0, a0, a2
; RV32IBP-NEXT:    xnor a1, a1, a3
; RV32IBP-NEXT:    ret
  %neg = xor i64 %a, -1
  %xor = xor i64 %neg, %b
  ret i64 %xor
}

declare i32 @llvm.fshl.i32(i32, i32, i32)

define i32 @rol_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: rol_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    sll a2, a0, a1
; RV32I-NEXT:    neg a1, a1
; RV32I-NEXT:    srl a0, a0, a1
; RV32I-NEXT:    or a0, a2, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: rol_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    rol a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: rol_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    rol a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: rol_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    rol a0, a0, a1
; RV32IBP-NEXT:    ret
  %or = tail call i32 @llvm.fshl.i32(i32 %a, i32 %a, i32 %b)
  ret i32 %or
}

; As we are not matching directly i64 code patterns on RV32 some i64 patterns
; don't have yet any matching bit manipulation instructions on RV32.
; This test is presented here in case future expansions of the experimental-b
; extension introduce instructions suitable for this pattern.

declare i64 @llvm.fshl.i64(i64, i64, i64)

define i64 @rol_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: rol_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    andi a3, a2, 63
; RV32I-NEXT:    addi t1, a3, -32
; RV32I-NEXT:    addi a6, zero, 31
; RV32I-NEXT:    bltz t1, .LBB7_2
; RV32I-NEXT:  # %bb.1:
; RV32I-NEXT:    sll a7, a0, t1
; RV32I-NEXT:    j .LBB7_3
; RV32I-NEXT:  .LBB7_2:
; RV32I-NEXT:    sll a4, a1, a2
; RV32I-NEXT:    sub a3, a6, a3
; RV32I-NEXT:    srli a5, a0, 1
; RV32I-NEXT:    srl a3, a5, a3
; RV32I-NEXT:    or a7, a4, a3
; RV32I-NEXT:  .LBB7_3:
; RV32I-NEXT:    neg a4, a2
; RV32I-NEXT:    andi a5, a4, 63
; RV32I-NEXT:    addi a3, a5, -32
; RV32I-NEXT:    bltz a3, .LBB7_7
; RV32I-NEXT:  # %bb.4:
; RV32I-NEXT:    mv t0, zero
; RV32I-NEXT:    bgez a3, .LBB7_8
; RV32I-NEXT:  .LBB7_5:
; RV32I-NEXT:    srl a3, a0, a4
; RV32I-NEXT:    sub a4, a6, a5
; RV32I-NEXT:    slli a1, a1, 1
; RV32I-NEXT:    sll a1, a1, a4
; RV32I-NEXT:    or a4, a3, a1
; RV32I-NEXT:    or a1, a7, t0
; RV32I-NEXT:    bgez t1, .LBB7_9
; RV32I-NEXT:  .LBB7_6:
; RV32I-NEXT:    sll a0, a0, a2
; RV32I-NEXT:    or a0, a0, a4
; RV32I-NEXT:    ret
; RV32I-NEXT:  .LBB7_7:
; RV32I-NEXT:    srl t0, a1, a4
; RV32I-NEXT:    bltz a3, .LBB7_5
; RV32I-NEXT:  .LBB7_8:
; RV32I-NEXT:    srl a4, a1, a3
; RV32I-NEXT:    or a1, a7, t0
; RV32I-NEXT:    bltz t1, .LBB7_6
; RV32I-NEXT:  .LBB7_9:
; RV32I-NEXT:    or a0, zero, a4
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: rol_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    andi a3, a2, 63
; RV32IB-NEXT:    addi t1, a3, -32
; RV32IB-NEXT:    addi a6, zero, 31
; RV32IB-NEXT:    bltz t1, .LBB7_2
; RV32IB-NEXT:  # %bb.1:
; RV32IB-NEXT:    sll a7, a0, t1
; RV32IB-NEXT:    j .LBB7_3
; RV32IB-NEXT:  .LBB7_2:
; RV32IB-NEXT:    sll a4, a1, a2
; RV32IB-NEXT:    sub a3, a6, a3
; RV32IB-NEXT:    srli a5, a0, 1
; RV32IB-NEXT:    srl a3, a5, a3
; RV32IB-NEXT:    or a7, a4, a3
; RV32IB-NEXT:  .LBB7_3:
; RV32IB-NEXT:    neg a4, a2
; RV32IB-NEXT:    andi a5, a4, 63
; RV32IB-NEXT:    addi a3, a5, -32
; RV32IB-NEXT:    bltz a3, .LBB7_7
; RV32IB-NEXT:  # %bb.4:
; RV32IB-NEXT:    mv t0, zero
; RV32IB-NEXT:    bgez a3, .LBB7_8
; RV32IB-NEXT:  .LBB7_5:
; RV32IB-NEXT:    srl a3, a0, a4
; RV32IB-NEXT:    sub a4, a6, a5
; RV32IB-NEXT:    slli a1, a1, 1
; RV32IB-NEXT:    sll a1, a1, a4
; RV32IB-NEXT:    or a4, a3, a1
; RV32IB-NEXT:    or a1, a7, t0
; RV32IB-NEXT:    bgez t1, .LBB7_9
; RV32IB-NEXT:  .LBB7_6:
; RV32IB-NEXT:    sll a0, a0, a2
; RV32IB-NEXT:    or a0, a0, a4
; RV32IB-NEXT:    ret
; RV32IB-NEXT:  .LBB7_7:
; RV32IB-NEXT:    srl t0, a1, a4
; RV32IB-NEXT:    bltz a3, .LBB7_5
; RV32IB-NEXT:  .LBB7_8:
; RV32IB-NEXT:    srl a4, a1, a3
; RV32IB-NEXT:    or a1, a7, t0
; RV32IB-NEXT:    bltz t1, .LBB7_6
; RV32IB-NEXT:  .LBB7_9:
; RV32IB-NEXT:    or a0, zero, a4
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: rol_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    andi a3, a2, 63
; RV32IBB-NEXT:    addi t1, a3, -32
; RV32IBB-NEXT:    addi a6, zero, 31
; RV32IBB-NEXT:    bltz t1, .LBB7_2
; RV32IBB-NEXT:  # %bb.1:
; RV32IBB-NEXT:    sll a7, a0, t1
; RV32IBB-NEXT:    j .LBB7_3
; RV32IBB-NEXT:  .LBB7_2:
; RV32IBB-NEXT:    sll a4, a1, a2
; RV32IBB-NEXT:    sub a3, a6, a3
; RV32IBB-NEXT:    srli a5, a0, 1
; RV32IBB-NEXT:    srl a3, a5, a3
; RV32IBB-NEXT:    or a7, a4, a3
; RV32IBB-NEXT:  .LBB7_3:
; RV32IBB-NEXT:    neg a4, a2
; RV32IBB-NEXT:    andi a5, a4, 63
; RV32IBB-NEXT:    addi a3, a5, -32
; RV32IBB-NEXT:    bltz a3, .LBB7_7
; RV32IBB-NEXT:  # %bb.4:
; RV32IBB-NEXT:    mv t0, zero
; RV32IBB-NEXT:    bgez a3, .LBB7_8
; RV32IBB-NEXT:  .LBB7_5:
; RV32IBB-NEXT:    srl a3, a0, a4
; RV32IBB-NEXT:    sub a4, a6, a5
; RV32IBB-NEXT:    slli a1, a1, 1
; RV32IBB-NEXT:    sll a1, a1, a4
; RV32IBB-NEXT:    or a4, a3, a1
; RV32IBB-NEXT:    or a1, a7, t0
; RV32IBB-NEXT:    bgez t1, .LBB7_9
; RV32IBB-NEXT:  .LBB7_6:
; RV32IBB-NEXT:    sll a0, a0, a2
; RV32IBB-NEXT:    or a0, a0, a4
; RV32IBB-NEXT:    ret
; RV32IBB-NEXT:  .LBB7_7:
; RV32IBB-NEXT:    srl t0, a1, a4
; RV32IBB-NEXT:    bltz a3, .LBB7_5
; RV32IBB-NEXT:  .LBB7_8:
; RV32IBB-NEXT:    srl a4, a1, a3
; RV32IBB-NEXT:    or a1, a7, t0
; RV32IBB-NEXT:    bltz t1, .LBB7_6
; RV32IBB-NEXT:  .LBB7_9:
; RV32IBB-NEXT:    or a0, zero, a4
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: rol_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    andi a3, a2, 63
; RV32IBP-NEXT:    addi t1, a3, -32
; RV32IBP-NEXT:    addi a6, zero, 31
; RV32IBP-NEXT:    bltz t1, .LBB7_2
; RV32IBP-NEXT:  # %bb.1:
; RV32IBP-NEXT:    sll a7, a0, t1
; RV32IBP-NEXT:    j .LBB7_3
; RV32IBP-NEXT:  .LBB7_2:
; RV32IBP-NEXT:    sll a4, a1, a2
; RV32IBP-NEXT:    sub a3, a6, a3
; RV32IBP-NEXT:    srli a5, a0, 1
; RV32IBP-NEXT:    srl a3, a5, a3
; RV32IBP-NEXT:    or a7, a4, a3
; RV32IBP-NEXT:  .LBB7_3:
; RV32IBP-NEXT:    neg a4, a2
; RV32IBP-NEXT:    andi a5, a4, 63
; RV32IBP-NEXT:    addi a3, a5, -32
; RV32IBP-NEXT:    bltz a3, .LBB7_7
; RV32IBP-NEXT:  # %bb.4:
; RV32IBP-NEXT:    mv t0, zero
; RV32IBP-NEXT:    bgez a3, .LBB7_8
; RV32IBP-NEXT:  .LBB7_5:
; RV32IBP-NEXT:    srl a3, a0, a4
; RV32IBP-NEXT:    sub a4, a6, a5
; RV32IBP-NEXT:    slli a1, a1, 1
; RV32IBP-NEXT:    sll a1, a1, a4
; RV32IBP-NEXT:    or a4, a3, a1
; RV32IBP-NEXT:    or a1, a7, t0
; RV32IBP-NEXT:    bgez t1, .LBB7_9
; RV32IBP-NEXT:  .LBB7_6:
; RV32IBP-NEXT:    sll a0, a0, a2
; RV32IBP-NEXT:    or a0, a0, a4
; RV32IBP-NEXT:    ret
; RV32IBP-NEXT:  .LBB7_7:
; RV32IBP-NEXT:    srl t0, a1, a4
; RV32IBP-NEXT:    bltz a3, .LBB7_5
; RV32IBP-NEXT:  .LBB7_8:
; RV32IBP-NEXT:    srl a4, a1, a3
; RV32IBP-NEXT:    or a1, a7, t0
; RV32IBP-NEXT:    bltz t1, .LBB7_6
; RV32IBP-NEXT:  .LBB7_9:
; RV32IBP-NEXT:    or a0, zero, a4
; RV32IBP-NEXT:    ret
  %or = tail call i64 @llvm.fshl.i64(i64 %a, i64 %a, i64 %b)
  ret i64 %or
}

declare i32 @llvm.fshr.i32(i32, i32, i32)

define i32 @ror_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: ror_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    srl a2, a0, a1
; RV32I-NEXT:    neg a1, a1
; RV32I-NEXT:    sll a0, a0, a1
; RV32I-NEXT:    or a0, a2, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: ror_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    ror a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: ror_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    ror a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: ror_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    ror a0, a0, a1
; RV32IBP-NEXT:    ret
  %or = tail call i32 @llvm.fshr.i32(i32 %a, i32 %a, i32 %b)
  ret i32 %or
}

; As we are not matching directly i64 code patterns on RV32 some i64 patterns
; don't have yet any matching bit manipulation instructions on RV32.
; This test is presented here in case future expansions of the experimental-b
; extension introduce instructions suitable for this pattern.

declare i64 @llvm.fshr.i64(i64, i64, i64)

define i64 @ror_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: ror_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    andi a3, a2, 63
; RV32I-NEXT:    addi t1, a3, -32
; RV32I-NEXT:    addi a6, zero, 31
; RV32I-NEXT:    bltz t1, .LBB9_2
; RV32I-NEXT:  # %bb.1:
; RV32I-NEXT:    srl a7, a1, t1
; RV32I-NEXT:    j .LBB9_3
; RV32I-NEXT:  .LBB9_2:
; RV32I-NEXT:    srl a4, a0, a2
; RV32I-NEXT:    sub a3, a6, a3
; RV32I-NEXT:    slli a5, a1, 1
; RV32I-NEXT:    sll a3, a5, a3
; RV32I-NEXT:    or a7, a4, a3
; RV32I-NEXT:  .LBB9_3:
; RV32I-NEXT:    neg a4, a2
; RV32I-NEXT:    andi a5, a4, 63
; RV32I-NEXT:    addi a3, a5, -32
; RV32I-NEXT:    bltz a3, .LBB9_7
; RV32I-NEXT:  # %bb.4:
; RV32I-NEXT:    mv t0, zero
; RV32I-NEXT:    bgez a3, .LBB9_8
; RV32I-NEXT:  .LBB9_5:
; RV32I-NEXT:    sll a3, a1, a4
; RV32I-NEXT:    sub a4, a6, a5
; RV32I-NEXT:    srli a0, a0, 1
; RV32I-NEXT:    srl a0, a0, a4
; RV32I-NEXT:    or a4, a3, a0
; RV32I-NEXT:    or a0, a7, t0
; RV32I-NEXT:    bgez t1, .LBB9_9
; RV32I-NEXT:  .LBB9_6:
; RV32I-NEXT:    srl a1, a1, a2
; RV32I-NEXT:    or a1, a1, a4
; RV32I-NEXT:    ret
; RV32I-NEXT:  .LBB9_7:
; RV32I-NEXT:    sll t0, a0, a4
; RV32I-NEXT:    bltz a3, .LBB9_5
; RV32I-NEXT:  .LBB9_8:
; RV32I-NEXT:    sll a4, a0, a3
; RV32I-NEXT:    or a0, a7, t0
; RV32I-NEXT:    bltz t1, .LBB9_6
; RV32I-NEXT:  .LBB9_9:
; RV32I-NEXT:    or a1, zero, a4
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: ror_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    andi a3, a2, 63
; RV32IB-NEXT:    addi t1, a3, -32
; RV32IB-NEXT:    addi a6, zero, 31
; RV32IB-NEXT:    bltz t1, .LBB9_2
; RV32IB-NEXT:  # %bb.1:
; RV32IB-NEXT:    srl a7, a1, t1
; RV32IB-NEXT:    j .LBB9_3
; RV32IB-NEXT:  .LBB9_2:
; RV32IB-NEXT:    srl a4, a0, a2
; RV32IB-NEXT:    sub a3, a6, a3
; RV32IB-NEXT:    slli a5, a1, 1
; RV32IB-NEXT:    sll a3, a5, a3
; RV32IB-NEXT:    or a7, a4, a3
; RV32IB-NEXT:  .LBB9_3:
; RV32IB-NEXT:    neg a4, a2
; RV32IB-NEXT:    andi a5, a4, 63
; RV32IB-NEXT:    addi a3, a5, -32
; RV32IB-NEXT:    bltz a3, .LBB9_7
; RV32IB-NEXT:  # %bb.4:
; RV32IB-NEXT:    mv t0, zero
; RV32IB-NEXT:    bgez a3, .LBB9_8
; RV32IB-NEXT:  .LBB9_5:
; RV32IB-NEXT:    sll a3, a1, a4
; RV32IB-NEXT:    sub a4, a6, a5
; RV32IB-NEXT:    srli a0, a0, 1
; RV32IB-NEXT:    srl a0, a0, a4
; RV32IB-NEXT:    or a4, a3, a0
; RV32IB-NEXT:    or a0, a7, t0
; RV32IB-NEXT:    bgez t1, .LBB9_9
; RV32IB-NEXT:  .LBB9_6:
; RV32IB-NEXT:    srl a1, a1, a2
; RV32IB-NEXT:    or a1, a1, a4
; RV32IB-NEXT:    ret
; RV32IB-NEXT:  .LBB9_7:
; RV32IB-NEXT:    sll t0, a0, a4
; RV32IB-NEXT:    bltz a3, .LBB9_5
; RV32IB-NEXT:  .LBB9_8:
; RV32IB-NEXT:    sll a4, a0, a3
; RV32IB-NEXT:    or a0, a7, t0
; RV32IB-NEXT:    bltz t1, .LBB9_6
; RV32IB-NEXT:  .LBB9_9:
; RV32IB-NEXT:    or a1, zero, a4
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: ror_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    andi a3, a2, 63
; RV32IBB-NEXT:    addi t1, a3, -32
; RV32IBB-NEXT:    addi a6, zero, 31
; RV32IBB-NEXT:    bltz t1, .LBB9_2
; RV32IBB-NEXT:  # %bb.1:
; RV32IBB-NEXT:    srl a7, a1, t1
; RV32IBB-NEXT:    j .LBB9_3
; RV32IBB-NEXT:  .LBB9_2:
; RV32IBB-NEXT:    srl a4, a0, a2
; RV32IBB-NEXT:    sub a3, a6, a3
; RV32IBB-NEXT:    slli a5, a1, 1
; RV32IBB-NEXT:    sll a3, a5, a3
; RV32IBB-NEXT:    or a7, a4, a3
; RV32IBB-NEXT:  .LBB9_3:
; RV32IBB-NEXT:    neg a4, a2
; RV32IBB-NEXT:    andi a5, a4, 63
; RV32IBB-NEXT:    addi a3, a5, -32
; RV32IBB-NEXT:    bltz a3, .LBB9_7
; RV32IBB-NEXT:  # %bb.4:
; RV32IBB-NEXT:    mv t0, zero
; RV32IBB-NEXT:    bgez a3, .LBB9_8
; RV32IBB-NEXT:  .LBB9_5:
; RV32IBB-NEXT:    sll a3, a1, a4
; RV32IBB-NEXT:    sub a4, a6, a5
; RV32IBB-NEXT:    srli a0, a0, 1
; RV32IBB-NEXT:    srl a0, a0, a4
; RV32IBB-NEXT:    or a4, a3, a0
; RV32IBB-NEXT:    or a0, a7, t0
; RV32IBB-NEXT:    bgez t1, .LBB9_9
; RV32IBB-NEXT:  .LBB9_6:
; RV32IBB-NEXT:    srl a1, a1, a2
; RV32IBB-NEXT:    or a1, a1, a4
; RV32IBB-NEXT:    ret
; RV32IBB-NEXT:  .LBB9_7:
; RV32IBB-NEXT:    sll t0, a0, a4
; RV32IBB-NEXT:    bltz a3, .LBB9_5
; RV32IBB-NEXT:  .LBB9_8:
; RV32IBB-NEXT:    sll a4, a0, a3
; RV32IBB-NEXT:    or a0, a7, t0
; RV32IBB-NEXT:    bltz t1, .LBB9_6
; RV32IBB-NEXT:  .LBB9_9:
; RV32IBB-NEXT:    or a1, zero, a4
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: ror_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    andi a3, a2, 63
; RV32IBP-NEXT:    addi t1, a3, -32
; RV32IBP-NEXT:    addi a6, zero, 31
; RV32IBP-NEXT:    bltz t1, .LBB9_2
; RV32IBP-NEXT:  # %bb.1:
; RV32IBP-NEXT:    srl a7, a1, t1
; RV32IBP-NEXT:    j .LBB9_3
; RV32IBP-NEXT:  .LBB9_2:
; RV32IBP-NEXT:    srl a4, a0, a2
; RV32IBP-NEXT:    sub a3, a6, a3
; RV32IBP-NEXT:    slli a5, a1, 1
; RV32IBP-NEXT:    sll a3, a5, a3
; RV32IBP-NEXT:    or a7, a4, a3
; RV32IBP-NEXT:  .LBB9_3:
; RV32IBP-NEXT:    neg a4, a2
; RV32IBP-NEXT:    andi a5, a4, 63
; RV32IBP-NEXT:    addi a3, a5, -32
; RV32IBP-NEXT:    bltz a3, .LBB9_7
; RV32IBP-NEXT:  # %bb.4:
; RV32IBP-NEXT:    mv t0, zero
; RV32IBP-NEXT:    bgez a3, .LBB9_8
; RV32IBP-NEXT:  .LBB9_5:
; RV32IBP-NEXT:    sll a3, a1, a4
; RV32IBP-NEXT:    sub a4, a6, a5
; RV32IBP-NEXT:    srli a0, a0, 1
; RV32IBP-NEXT:    srl a0, a0, a4
; RV32IBP-NEXT:    or a4, a3, a0
; RV32IBP-NEXT:    or a0, a7, t0
; RV32IBP-NEXT:    bgez t1, .LBB9_9
; RV32IBP-NEXT:  .LBB9_6:
; RV32IBP-NEXT:    srl a1, a1, a2
; RV32IBP-NEXT:    or a1, a1, a4
; RV32IBP-NEXT:    ret
; RV32IBP-NEXT:  .LBB9_7:
; RV32IBP-NEXT:    sll t0, a0, a4
; RV32IBP-NEXT:    bltz a3, .LBB9_5
; RV32IBP-NEXT:  .LBB9_8:
; RV32IBP-NEXT:    sll a4, a0, a3
; RV32IBP-NEXT:    or a0, a7, t0
; RV32IBP-NEXT:    bltz t1, .LBB9_6
; RV32IBP-NEXT:  .LBB9_9:
; RV32IBP-NEXT:    or a1, zero, a4
; RV32IBP-NEXT:    ret
  %or = tail call i64 @llvm.fshr.i64(i64 %a, i64 %a, i64 %b)
  ret i64 %or
}

define i32 @rori_i32_fshl(i32 %a) nounwind {
; RV32I-LABEL: rori_i32_fshl:
; RV32I:       # %bb.0:
; RV32I-NEXT:    srli a1, a0, 1
; RV32I-NEXT:    slli a0, a0, 31
; RV32I-NEXT:    or a0, a0, a1
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: rori_i32_fshl:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    rori a0, a0, 1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: rori_i32_fshl:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    rori a0, a0, 1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: rori_i32_fshl:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    rori a0, a0, 1
; RV32IBP-NEXT:    ret
  %1 = tail call i32 @llvm.fshl.i32(i32 %a, i32 %a, i32 31)
  ret i32 %1
}

define i32 @rori_i32_fshr(i32 %a) nounwind {
; RV32I-LABEL: rori_i32_fshr:
; RV32I:       # %bb.0:
; RV32I-NEXT:    slli a1, a0, 1
; RV32I-NEXT:    srli a0, a0, 31
; RV32I-NEXT:    or a0, a0, a1
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: rori_i32_fshr:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    rori a0, a0, 31
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: rori_i32_fshr:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    rori a0, a0, 31
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: rori_i32_fshr:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    rori a0, a0, 31
; RV32IBP-NEXT:    ret
  %1 = tail call i32 @llvm.fshr.i32(i32 %a, i32 %a, i32 31)
  ret i32 %1
}

define i64 @rori_i64(i64 %a) nounwind {
; RV32I-LABEL: rori_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    slli a2, a1, 31
; RV32I-NEXT:    srli a3, a0, 1
; RV32I-NEXT:    or a2, a3, a2
; RV32I-NEXT:    srli a1, a1, 1
; RV32I-NEXT:    slli a0, a0, 31
; RV32I-NEXT:    or a1, a0, a1
; RV32I-NEXT:    mv a0, a2
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: rori_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    fsri a2, a0, a1, 1
; RV32IB-NEXT:    fsri a1, a1, a0, 1
; RV32IB-NEXT:    mv a0, a2
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: rori_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    slli a2, a1, 31
; RV32IBB-NEXT:    srli a3, a0, 1
; RV32IBB-NEXT:    or a2, a3, a2
; RV32IBB-NEXT:    srli a1, a1, 1
; RV32IBB-NEXT:    slli a0, a0, 31
; RV32IBB-NEXT:    or a1, a0, a1
; RV32IBB-NEXT:    mv a0, a2
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: rori_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    slli a2, a1, 31
; RV32IBP-NEXT:    srli a3, a0, 1
; RV32IBP-NEXT:    or a2, a3, a2
; RV32IBP-NEXT:    srli a1, a1, 1
; RV32IBP-NEXT:    slli a0, a0, 31
; RV32IBP-NEXT:    or a1, a0, a1
; RV32IBP-NEXT:    mv a0, a2
; RV32IBP-NEXT:    ret
  %1 = tail call i64 @llvm.fshl.i64(i64 %a, i64 %a, i64 63)
  ret i64 %1
}

define i64 @rori_i64_fshr(i64 %a) nounwind {
; RV32I-LABEL: rori_i64_fshr:
; RV32I:       # %bb.0:
; RV32I-NEXT:    slli a2, a0, 1
; RV32I-NEXT:    srli a3, a1, 31
; RV32I-NEXT:    or a2, a3, a2
; RV32I-NEXT:    srli a0, a0, 31
; RV32I-NEXT:    slli a1, a1, 1
; RV32I-NEXT:    or a1, a1, a0
; RV32I-NEXT:    mv a0, a2
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: rori_i64_fshr:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    fsri a2, a1, a0, 31
; RV32IB-NEXT:    fsri a1, a0, a1, 31
; RV32IB-NEXT:    mv a0, a2
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: rori_i64_fshr:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    slli a2, a0, 1
; RV32IBB-NEXT:    srli a3, a1, 31
; RV32IBB-NEXT:    or a2, a3, a2
; RV32IBB-NEXT:    srli a0, a0, 31
; RV32IBB-NEXT:    slli a1, a1, 1
; RV32IBB-NEXT:    or a1, a1, a0
; RV32IBB-NEXT:    mv a0, a2
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: rori_i64_fshr:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    slli a2, a0, 1
; RV32IBP-NEXT:    srli a3, a1, 31
; RV32IBP-NEXT:    or a2, a3, a2
; RV32IBP-NEXT:    srli a0, a0, 31
; RV32IBP-NEXT:    slli a1, a1, 1
; RV32IBP-NEXT:    or a1, a1, a0
; RV32IBP-NEXT:    mv a0, a2
; RV32IBP-NEXT:    ret
  %1 = tail call i64 @llvm.fshr.i64(i64 %a, i64 %a, i64 63)
  ret i64 %1
}

define i32 @pack_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: pack_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    lui a2, 16
; RV32I-NEXT:    addi a2, a2, -1
; RV32I-NEXT:    and a0, a0, a2
; RV32I-NEXT:    slli a1, a1, 16
; RV32I-NEXT:    or a0, a1, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: pack_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    pack a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: pack_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    pack a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: pack_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    pack a0, a0, a1
; RV32IBP-NEXT:    ret
  %shl = and i32 %a, 65535
  %shl1 = shl i32 %b, 16
  %or = or i32 %shl1, %shl
  ret i32 %or
}

; As we are not matching directly i64 code patterns on RV32 some i64 patterns
; don't have yet any matching bit manipulation instructions on RV32.
; This test is presented here in case future expansions of the experimental-b
; extension introduce instructions suitable for this pattern.

define i64 @pack_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: pack_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    mv a1, a2
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: pack_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    mv a1, a2
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: pack_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    mv a1, a2
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: pack_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    mv a1, a2
; RV32IBP-NEXT:    ret
  %shl = and i64 %a, 4294967295
  %shl1 = shl i64 %b, 32
  %or = or i64 %shl1, %shl
  ret i64 %or
}

define i32 @packu_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: packu_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    srli a0, a0, 16
; RV32I-NEXT:    lui a2, 1048560
; RV32I-NEXT:    and a1, a1, a2
; RV32I-NEXT:    or a0, a1, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: packu_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    packu a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: packu_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    packu a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: packu_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    packu a0, a0, a1
; RV32IBP-NEXT:    ret
  %shr = lshr i32 %a, 16
  %shr1 = and i32 %b, -65536
  %or = or i32 %shr1, %shr
  ret i32 %or
}

; As we are not matching directly i64 code patterns on RV32 some i64 patterns
; don't have yet any matching bit manipulation instructions on RV32.
; This test is presented here in case future expansions of the experimental-b
; extension introduce instructions suitable for this pattern.

define i64 @packu_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: packu_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    mv a0, a1
; RV32I-NEXT:    mv a1, a3
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: packu_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    mv a0, a1
; RV32IB-NEXT:    mv a1, a3
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: packu_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    mv a0, a1
; RV32IBB-NEXT:    mv a1, a3
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: packu_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    mv a0, a1
; RV32IBP-NEXT:    mv a1, a3
; RV32IBP-NEXT:    ret
  %shr = lshr i64 %a, 32
  %shr1 = and i64 %b, -4294967296
  %or = or i64 %shr1, %shr
  ret i64 %or
}

define i32 @packh_i32(i32 %a, i32 %b) nounwind {
; RV32I-LABEL: packh_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    zext.b a0, a0
; RV32I-NEXT:    slli a1, a1, 8
; RV32I-NEXT:    lui a2, 16
; RV32I-NEXT:    addi a2, a2, -256
; RV32I-NEXT:    and a1, a1, a2
; RV32I-NEXT:    or a0, a1, a0
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: packh_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    packh a0, a0, a1
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: packh_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    packh a0, a0, a1
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: packh_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    packh a0, a0, a1
; RV32IBP-NEXT:    ret
  %and = and i32 %a, 255
  %and1 = shl i32 %b, 8
  %shl = and i32 %and1, 65280
  %or = or i32 %shl, %and
  ret i32 %or
}

define i64 @packh_i64(i64 %a, i64 %b) nounwind {
; RV32I-LABEL: packh_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    zext.b a0, a0
; RV32I-NEXT:    slli a1, a2, 8
; RV32I-NEXT:    lui a2, 16
; RV32I-NEXT:    addi a2, a2, -256
; RV32I-NEXT:    and a1, a1, a2
; RV32I-NEXT:    or a0, a1, a0
; RV32I-NEXT:    mv a1, zero
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: packh_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    packh a0, a0, a2
; RV32IB-NEXT:    mv a1, zero
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: packh_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    packh a0, a0, a2
; RV32IBB-NEXT:    mv a1, zero
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: packh_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    packh a0, a0, a2
; RV32IBP-NEXT:    mv a1, zero
; RV32IBP-NEXT:    ret
  %and = and i64 %a, 255
  %and1 = shl i64 %b, 8
  %shl = and i64 %and1, 65280
  %or = or i64 %shl, %and
  ret i64 %or
}

define i32 @zexth_i32(i32 %a) nounwind {
; RV32I-LABEL: zexth_i32:
; RV32I:       # %bb.0:
; RV32I-NEXT:    lui a1, 16
; RV32I-NEXT:    addi a1, a1, -1
; RV32I-NEXT:    and a0, a0, a1
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: zexth_i32:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    zext.h a0, a0
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: zexth_i32:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    zext.h a0, a0
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: zexth_i32:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    pack a0, a0, zero
; RV32IBP-NEXT:    ret
  %and = and i32 %a, 65535
  ret i32 %and
}

define i64 @zexth_i64(i64 %a) nounwind {
; RV32I-LABEL: zexth_i64:
; RV32I:       # %bb.0:
; RV32I-NEXT:    lui a1, 16
; RV32I-NEXT:    addi a1, a1, -1
; RV32I-NEXT:    and a0, a0, a1
; RV32I-NEXT:    mv a1, zero
; RV32I-NEXT:    ret
;
; RV32IB-LABEL: zexth_i64:
; RV32IB:       # %bb.0:
; RV32IB-NEXT:    zext.h a0, a0
; RV32IB-NEXT:    mv a1, zero
; RV32IB-NEXT:    ret
;
; RV32IBB-LABEL: zexth_i64:
; RV32IBB:       # %bb.0:
; RV32IBB-NEXT:    zext.h a0, a0
; RV32IBB-NEXT:    mv a1, zero
; RV32IBB-NEXT:    ret
;
; RV32IBP-LABEL: zexth_i64:
; RV32IBP:       # %bb.0:
; RV32IBP-NEXT:    pack a0, a0, zero
; RV32IBP-NEXT:    mv a1, zero
; RV32IBP-NEXT:    ret
  %and = and i64 %a, 65535
  ret i64 %and
}
