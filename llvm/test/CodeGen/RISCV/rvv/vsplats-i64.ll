; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=riscv32 -mattr=+experimental-v -verify-machineinstrs < %s \
; RUN:   | FileCheck %s --check-prefix=RV32V
; RUN: llc -mtriple=riscv64 -mattr=+experimental-v -verify-machineinstrs < %s \
; RUN:   | FileCheck %s --check-prefix=RV64V

define <vscale x 8 x i64> @vsplat_nxv8i64_1() {
; RV32V-LABEL: vsplat_nxv8i64_1:
; RV32V:       # %bb.0:
; RV32V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.i v16, -1
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vsplat_nxv8i64_1:
; RV64V:       # %bb.0:
; RV64V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV64V-NEXT:    vmv.v.i v16, -1
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 -1, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  ret <vscale x 8 x i64> %splat
}

define <vscale x 8 x i64> @vsplat_nxv8i64_2() {
; RV32V-LABEL: vsplat_nxv8i64_2:
; RV32V:       # %bb.0:
; RV32V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.i v16, 4
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vsplat_nxv8i64_2:
; RV64V:       # %bb.0:
; RV64V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV64V-NEXT:    vmv.v.i v16, 4
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 4, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  ret <vscale x 8 x i64> %splat
}

define <vscale x 8 x i64> @vsplat_nxv8i64_3() {
; RV32V-LABEL: vsplat_nxv8i64_3:
; RV32V:       # %bb.0:
; RV32V-NEXT:    addi a0, zero, 255
; RV32V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.x v16, a0
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vsplat_nxv8i64_3:
; RV64V:       # %bb.0:
; RV64V-NEXT:    addi a0, zero, 255
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vmv.v.x v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 255, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  ret <vscale x 8 x i64> %splat
}

define <vscale x 8 x i64> @vsplat_nxv8i64_4() {
; RV32V-LABEL: vsplat_nxv8i64_4:
; RV32V:       # %bb.0:
; RV32V-NEXT:    lui a0, 1028096
; RV32V-NEXT:    addi a0, a0, -1281
; RV32V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.x v8, a0
; RV32V-NEXT:    addi a0, zero, 32
; RV32V-NEXT:    vsll.vx v8, v8, a0
; RV32V-NEXT:    vsrl.vx v16, v8, a0
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vsplat_nxv8i64_4:
; RV64V:       # %bb.0:
; RV64V-NEXT:    addi a0, zero, 251
; RV64V-NEXT:    slli a0, a0, 24
; RV64V-NEXT:    addi a0, a0, -1281
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vmv.v.x v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 4211079935, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  ret <vscale x 8 x i64> %splat
}

define <vscale x 8 x i64> @vsplat_nxv8i64_5(i64 %a) {
; RV32V-LABEL: vsplat_nxv8i64_5:
; RV32V:       # %bb.0:
; RV32V-NEXT:    vsetvli a2, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.x v8, a1
; RV32V-NEXT:    addi a1, zero, 32
; RV32V-NEXT:    vsll.vx v8, v8, a1
; RV32V-NEXT:    vmv.v.x v16, a0
; RV32V-NEXT:    vsll.vx v16, v16, a1
; RV32V-NEXT:    vsrl.vx v16, v16, a1
; RV32V-NEXT:    vor.vv v16, v16, v8
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vsplat_nxv8i64_5:
; RV64V:       # %bb.0:
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vmv.v.x v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 %a, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  ret <vscale x 8 x i64> %splat
}

define <vscale x 8 x i64> @vadd_vx_nxv8i64_6(<vscale x 8 x i64> %v) {
; RV32V-LABEL: vadd_vx_nxv8i64_6:
; RV32V:       # %bb.0:
; RV32V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV32V-NEXT:    vadd.vi v16, v16, 2
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vadd_vx_nxv8i64_6:
; RV64V:       # %bb.0:
; RV64V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV64V-NEXT:    vadd.vi v16, v16, 2
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 2, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  %vret = add <vscale x 8 x i64> %v, %splat
  ret <vscale x 8 x i64> %vret
}

define <vscale x 8 x i64> @vadd_vx_nxv8i64_7(<vscale x 8 x i64> %v) {
; RV32V-LABEL: vadd_vx_nxv8i64_7:
; RV32V:       # %bb.0:
; RV32V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV32V-NEXT:    vadd.vi v16, v16, -1
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vadd_vx_nxv8i64_7:
; RV64V:       # %bb.0:
; RV64V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV64V-NEXT:    vadd.vi v16, v16, -1
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 -1, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  %vret = add <vscale x 8 x i64> %v, %splat
  ret <vscale x 8 x i64> %vret
}

define <vscale x 8 x i64> @vadd_vx_nxv8i64_8(<vscale x 8 x i64> %v) {
; RV32V-LABEL: vadd_vx_nxv8i64_8:
; RV32V:       # %bb.0:
; RV32V-NEXT:    addi a0, zero, 255
; RV32V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV32V-NEXT:    vadd.vx v16, v16, a0
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vadd_vx_nxv8i64_8:
; RV64V:       # %bb.0:
; RV64V-NEXT:    addi a0, zero, 255
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vadd.vx v16, v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 255, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  %vret = add <vscale x 8 x i64> %v, %splat
  ret <vscale x 8 x i64> %vret
}

define <vscale x 8 x i64> @vadd_vx_nxv8i64_9(<vscale x 8 x i64> %v) {
; RV32V-LABEL: vadd_vx_nxv8i64_9:
; RV32V:       # %bb.0:
; RV32V-NEXT:    lui a0, 503808
; RV32V-NEXT:    addi a0, a0, -1281
; RV32V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV32V-NEXT:    vadd.vx v16, v16, a0
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vadd_vx_nxv8i64_9:
; RV64V:       # %bb.0:
; RV64V-NEXT:    lui a0, 503808
; RV64V-NEXT:    addiw a0, a0, -1281
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vadd.vx v16, v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 2063596287, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  %vret = add <vscale x 8 x i64> %v, %splat
  ret <vscale x 8 x i64> %vret
}

define <vscale x 8 x i64> @vadd_vx_nxv8i64_10(<vscale x 8 x i64> %v) {
; RV32V-LABEL: vadd_vx_nxv8i64_10:
; RV32V:       # %bb.0:
; RV32V-NEXT:    lui a0, 1028096
; RV32V-NEXT:    addi a0, a0, -1281
; RV32V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.x v8, a0
; RV32V-NEXT:    addi a0, zero, 32
; RV32V-NEXT:    vsll.vx v8, v8, a0
; RV32V-NEXT:    vsrl.vx v8, v8, a0
; RV32V-NEXT:    vadd.vv v16, v16, v8
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vadd_vx_nxv8i64_10:
; RV64V:       # %bb.0:
; RV64V-NEXT:    addi a0, zero, 251
; RV64V-NEXT:    slli a0, a0, 24
; RV64V-NEXT:    addi a0, a0, -1281
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vadd.vx v16, v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 4211079935, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  %vret = add <vscale x 8 x i64> %v, %splat
  ret <vscale x 8 x i64> %vret
}

define <vscale x 8 x i64> @vadd_vx_nxv8i64_11(<vscale x 8 x i64> %v) {
; RV32V-LABEL: vadd_vx_nxv8i64_11:
; RV32V:       # %bb.0:
; RV32V-NEXT:    vsetvli a0, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.i v8, 1
; RV32V-NEXT:    addi a0, zero, 32
; RV32V-NEXT:    vsll.vx v8, v8, a0
; RV32V-NEXT:    lui a1, 1028096
; RV32V-NEXT:    addi a1, a1, -1281
; RV32V-NEXT:    vmv.v.x v24, a1
; RV32V-NEXT:    vsll.vx v24, v24, a0
; RV32V-NEXT:    vsrl.vx v24, v24, a0
; RV32V-NEXT:    vor.vv v8, v24, v8
; RV32V-NEXT:    vadd.vv v16, v16, v8
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vadd_vx_nxv8i64_11:
; RV64V:       # %bb.0:
; RV64V-NEXT:    addi a0, zero, 507
; RV64V-NEXT:    slli a0, a0, 24
; RV64V-NEXT:    addi a0, a0, -1281
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vadd.vx v16, v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 8506047231, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  %vret = add <vscale x 8 x i64> %v, %splat
  ret <vscale x 8 x i64> %vret
}

define <vscale x 8 x i64> @vadd_vx_nxv8i64_12(<vscale x 8 x i64> %v, i64 %a) {
; RV32V-LABEL: vadd_vx_nxv8i64_12:
; RV32V:       # %bb.0:
; RV32V-NEXT:    vsetvli a2, zero, e64,m8,ta,mu
; RV32V-NEXT:    vmv.v.x v8, a1
; RV32V-NEXT:    addi a1, zero, 32
; RV32V-NEXT:    vsll.vx v8, v8, a1
; RV32V-NEXT:    vmv.v.x v24, a0
; RV32V-NEXT:    vsll.vx v24, v24, a1
; RV32V-NEXT:    vsrl.vx v24, v24, a1
; RV32V-NEXT:    vor.vv v8, v24, v8
; RV32V-NEXT:    vadd.vv v16, v16, v8
; RV32V-NEXT:    ret
;
; RV64V-LABEL: vadd_vx_nxv8i64_12:
; RV64V:       # %bb.0:
; RV64V-NEXT:    vsetvli a1, zero, e64,m8,ta,mu
; RV64V-NEXT:    vadd.vx v16, v16, a0
; RV64V-NEXT:    ret
  %head = insertelement <vscale x 8 x i64> undef, i64 %a, i32 0
  %splat = shufflevector <vscale x 8 x i64> %head, <vscale x 8 x i64> undef, <vscale x 8 x i32> zeroinitializer
  %vret = add <vscale x 8 x i64> %v, %splat
  ret <vscale x 8 x i64> %vret
}
