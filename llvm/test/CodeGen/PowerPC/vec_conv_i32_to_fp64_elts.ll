; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -verify-machineinstrs -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:     -mcpu=pwr8 -ppc-asm-full-reg-names -ppc-vsr-nums-as-vr < %s | \
; RUN: FileCheck %s --check-prefix=CHECK-P8
; RUN: llc -verify-machineinstrs -mtriple=powerpc64le-unknown-linux-gnu \
; RUN:     -mcpu=pwr9 -ppc-asm-full-reg-names -ppc-vsr-nums-as-vr < %s | \
; RUN: FileCheck %s --check-prefix=CHECK-P9
; RUN: llc -verify-machineinstrs -mtriple=powerpc64-unknown-linux-gnu \
; RUN:     -mcpu=pwr9 -ppc-asm-full-reg-names -ppc-vsr-nums-as-vr < %s | \
; RUN: FileCheck %s --check-prefix=CHECK-BE

define <2 x double> @test2elt(i64 %a.coerce) local_unnamed_addr #0 {
; CHECK-P8-LABEL: test2elt:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    mtfprd f0, r3
; CHECK-P8-NEXT:    xxswapd v2, vs0
; CHECK-P8-NEXT:    xxmrglw v2, v2, v2
; CHECK-P8-NEXT:    xvcvuxwdp v2, v2
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test2elt:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    mtfprd f0, r3
; CHECK-P9-NEXT:    xxswapd v2, vs0
; CHECK-P9-NEXT:    xxmrglw v2, v2, v2
; CHECK-P9-NEXT:    xvcvuxwdp v2, v2
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test2elt:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    mtfprd f0, r3
; CHECK-BE-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvuxwdp v2, v2
; CHECK-BE-NEXT:    blr
entry:
  %0 = bitcast i64 %a.coerce to <2 x i32>
  %1 = uitofp <2 x i32> %0 to <2 x double>
  ret <2 x double> %1
}

define void @test4elt(<4 x double>* noalias nocapture sret(<4 x double>) %agg.result, <4 x i32> %a) local_unnamed_addr #1 {
; CHECK-P8-LABEL: test4elt:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    xxmrglw v3, v2, v2
; CHECK-P8-NEXT:    xxmrghw v2, v2, v2
; CHECK-P8-NEXT:    li r4, 16
; CHECK-P8-NEXT:    xvcvuxwdp vs0, v3
; CHECK-P8-NEXT:    xvcvuxwdp vs1, v2
; CHECK-P8-NEXT:    xxswapd vs0, vs0
; CHECK-P8-NEXT:    xxswapd vs1, vs1
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r4
; CHECK-P8-NEXT:    stxvd2x vs0, 0, r3
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test4elt:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    xxmrglw v3, v2, v2
; CHECK-P9-NEXT:    xxmrghw v2, v2, v2
; CHECK-P9-NEXT:    xvcvuxwdp vs0, v3
; CHECK-P9-NEXT:    xvcvuxwdp vs1, v2
; CHECK-P9-NEXT:    stxv vs1, 16(r3)
; CHECK-P9-NEXT:    stxv vs0, 0(r3)
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test4elt:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    xxmrghw v3, v2, v2
; CHECK-BE-NEXT:    xxmrglw v2, v2, v2
; CHECK-BE-NEXT:    xvcvuxwdp vs0, v3
; CHECK-BE-NEXT:    xvcvuxwdp vs1, v2
; CHECK-BE-NEXT:    stxv vs1, 16(r3)
; CHECK-BE-NEXT:    stxv vs0, 0(r3)
; CHECK-BE-NEXT:    blr
entry:
  %0 = uitofp <4 x i32> %a to <4 x double>
  store <4 x double> %0, <4 x double>* %agg.result, align 32
  ret void
}

define void @test8elt(<8 x double>* noalias nocapture sret(<8 x double>) %agg.result, <8 x i32>* nocapture readonly) local_unnamed_addr #2 {
; CHECK-P8-LABEL: test8elt:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    li r5, 16
; CHECK-P8-NEXT:    lvx v3, 0, r4
; CHECK-P8-NEXT:    li r6, 32
; CHECK-P8-NEXT:    lvx v2, r4, r5
; CHECK-P8-NEXT:    li r4, 48
; CHECK-P8-NEXT:    xxmrglw v5, v3, v3
; CHECK-P8-NEXT:    xxmrghw v3, v3, v3
; CHECK-P8-NEXT:    xxmrglw v4, v2, v2
; CHECK-P8-NEXT:    xxmrghw v2, v2, v2
; CHECK-P8-NEXT:    xvcvuxwdp vs2, v5
; CHECK-P8-NEXT:    xvcvuxwdp vs0, v4
; CHECK-P8-NEXT:    xvcvuxwdp vs1, v2
; CHECK-P8-NEXT:    xvcvuxwdp vs3, v3
; CHECK-P8-NEXT:    xxswapd vs2, vs2
; CHECK-P8-NEXT:    xxswapd vs0, vs0
; CHECK-P8-NEXT:    xxswapd vs1, vs1
; CHECK-P8-NEXT:    xxswapd vs3, vs3
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r4
; CHECK-P8-NEXT:    stxvd2x vs0, r3, r6
; CHECK-P8-NEXT:    stxvd2x vs3, r3, r5
; CHECK-P8-NEXT:    stxvd2x vs2, 0, r3
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test8elt:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    lxv vs1, 0(r4)
; CHECK-P9-NEXT:    lxv vs0, 16(r4)
; CHECK-P9-NEXT:    xxmrglw v2, vs1, vs1
; CHECK-P9-NEXT:    xvcvuxwdp vs2, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs1, vs1
; CHECK-P9-NEXT:    xvcvuxwdp vs1, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-P9-NEXT:    xvcvuxwdp vs3, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-P9-NEXT:    stxv vs2, 0(r3)
; CHECK-P9-NEXT:    xvcvuxwdp vs0, v2
; CHECK-P9-NEXT:    stxv vs1, 16(r3)
; CHECK-P9-NEXT:    stxv vs3, 32(r3)
; CHECK-P9-NEXT:    stxv vs0, 48(r3)
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test8elt:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    lxv vs1, 0(r4)
; CHECK-BE-NEXT:    lxv vs0, 16(r4)
; CHECK-BE-NEXT:    xxmrghw v2, vs1, vs1
; CHECK-BE-NEXT:    xvcvuxwdp vs2, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs1, vs1
; CHECK-BE-NEXT:    xvcvuxwdp vs1, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvuxwdp vs3, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-BE-NEXT:    stxv vs2, 0(r3)
; CHECK-BE-NEXT:    xvcvuxwdp vs0, v2
; CHECK-BE-NEXT:    stxv vs1, 16(r3)
; CHECK-BE-NEXT:    stxv vs3, 32(r3)
; CHECK-BE-NEXT:    stxv vs0, 48(r3)
; CHECK-BE-NEXT:    blr
entry:
  %a = load <8 x i32>, <8 x i32>* %0, align 32
  %1 = uitofp <8 x i32> %a to <8 x double>
  store <8 x double> %1, <8 x double>* %agg.result, align 64
  ret void
}

define void @test16elt(<16 x double>* noalias nocapture sret(<16 x double>) %agg.result, <16 x i32>* nocapture readonly) local_unnamed_addr #2 {
; CHECK-P8-LABEL: test16elt:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    li r5, 16
; CHECK-P8-NEXT:    li r6, 48
; CHECK-P8-NEXT:    li r7, 32
; CHECK-P8-NEXT:    li r8, 64
; CHECK-P8-NEXT:    lvx v2, r4, r5
; CHECK-P8-NEXT:    lvx v3, r4, r6
; CHECK-P8-NEXT:    lvx v0, r4, r7
; CHECK-P8-NEXT:    xxmrglw v4, v2, v2
; CHECK-P8-NEXT:    xxmrghw v5, v3, v3
; CHECK-P8-NEXT:    xxmrghw v2, v2, v2
; CHECK-P8-NEXT:    xxmrglw v3, v3, v3
; CHECK-P8-NEXT:    xvcvuxwdp vs0, v4
; CHECK-P8-NEXT:    lvx v4, 0, r4
; CHECK-P8-NEXT:    li r4, 112
; CHECK-P8-NEXT:    xvcvuxwdp vs1, v5
; CHECK-P8-NEXT:    xxmrghw v5, v0, v0
; CHECK-P8-NEXT:    xxmrglw v0, v0, v0
; CHECK-P8-NEXT:    xvcvuxwdp vs2, v2
; CHECK-P8-NEXT:    xxmrglw v2, v4, v4
; CHECK-P8-NEXT:    xvcvuxwdp vs3, v3
; CHECK-P8-NEXT:    xxmrghw v3, v4, v4
; CHECK-P8-NEXT:    xvcvuxwdp vs4, v5
; CHECK-P8-NEXT:    xvcvuxwdp vs5, v0
; CHECK-P8-NEXT:    xvcvuxwdp vs6, v2
; CHECK-P8-NEXT:    xxswapd vs0, vs0
; CHECK-P8-NEXT:    xvcvuxwdp vs7, v3
; CHECK-P8-NEXT:    xxswapd vs1, vs1
; CHECK-P8-NEXT:    xxswapd vs2, vs2
; CHECK-P8-NEXT:    xxswapd vs3, vs3
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r4
; CHECK-P8-NEXT:    li r4, 96
; CHECK-P8-NEXT:    xxswapd vs4, vs4
; CHECK-P8-NEXT:    xxswapd vs1, vs5
; CHECK-P8-NEXT:    stxvd2x vs3, r3, r4
; CHECK-P8-NEXT:    xxswapd vs5, vs6
; CHECK-P8-NEXT:    li r4, 80
; CHECK-P8-NEXT:    xxswapd vs3, vs7
; CHECK-P8-NEXT:    stxvd2x vs4, r3, r4
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r8
; CHECK-P8-NEXT:    stxvd2x vs2, r3, r6
; CHECK-P8-NEXT:    stxvd2x vs0, r3, r7
; CHECK-P8-NEXT:    stxvd2x vs3, r3, r5
; CHECK-P8-NEXT:    stxvd2x vs5, 0, r3
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test16elt:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    lxv vs0, 0(r4)
; CHECK-P9-NEXT:    lxv vs2, 16(r4)
; CHECK-P9-NEXT:    lxv vs5, 32(r4)
; CHECK-P9-NEXT:    lxv vs4, 48(r4)
; CHECK-P9-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-P9-NEXT:    xvcvuxwdp vs1, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-P9-NEXT:    xvcvuxwdp vs0, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs2, vs2
; CHECK-P9-NEXT:    xvcvuxwdp vs3, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs2, vs2
; CHECK-P9-NEXT:    stxv vs1, 0(r3)
; CHECK-P9-NEXT:    stxv vs0, 16(r3)
; CHECK-P9-NEXT:    xvcvuxwdp vs2, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs5, vs5
; CHECK-P9-NEXT:    xvcvuxwdp vs6, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs5, vs5
; CHECK-P9-NEXT:    stxv vs3, 32(r3)
; CHECK-P9-NEXT:    stxv vs2, 48(r3)
; CHECK-P9-NEXT:    xvcvuxwdp vs5, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs4, vs4
; CHECK-P9-NEXT:    xvcvuxwdp vs7, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs4, vs4
; CHECK-P9-NEXT:    stxv vs6, 64(r3)
; CHECK-P9-NEXT:    stxv vs5, 80(r3)
; CHECK-P9-NEXT:    xvcvuxwdp vs4, v2
; CHECK-P9-NEXT:    stxv vs7, 96(r3)
; CHECK-P9-NEXT:    stxv vs4, 112(r3)
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test16elt:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    lxv vs0, 0(r4)
; CHECK-BE-NEXT:    lxv vs2, 16(r4)
; CHECK-BE-NEXT:    lxv vs5, 32(r4)
; CHECK-BE-NEXT:    lxv vs4, 48(r4)
; CHECK-BE-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvuxwdp vs1, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvuxwdp vs0, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs2, vs2
; CHECK-BE-NEXT:    xvcvuxwdp vs3, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs2, vs2
; CHECK-BE-NEXT:    stxv vs1, 0(r3)
; CHECK-BE-NEXT:    stxv vs0, 16(r3)
; CHECK-BE-NEXT:    xvcvuxwdp vs2, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs5, vs5
; CHECK-BE-NEXT:    xvcvuxwdp vs6, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs5, vs5
; CHECK-BE-NEXT:    stxv vs3, 32(r3)
; CHECK-BE-NEXT:    stxv vs2, 48(r3)
; CHECK-BE-NEXT:    xvcvuxwdp vs5, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs4, vs4
; CHECK-BE-NEXT:    xvcvuxwdp vs7, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs4, vs4
; CHECK-BE-NEXT:    stxv vs6, 64(r3)
; CHECK-BE-NEXT:    stxv vs5, 80(r3)
; CHECK-BE-NEXT:    xvcvuxwdp vs4, v2
; CHECK-BE-NEXT:    stxv vs7, 96(r3)
; CHECK-BE-NEXT:    stxv vs4, 112(r3)
; CHECK-BE-NEXT:    blr
entry:
  %a = load <16 x i32>, <16 x i32>* %0, align 64
  %1 = uitofp <16 x i32> %a to <16 x double>
  store <16 x double> %1, <16 x double>* %agg.result, align 128
  ret void
}

define <2 x double> @test2elt_signed(i64 %a.coerce) local_unnamed_addr #0 {
; CHECK-P8-LABEL: test2elt_signed:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    mtfprd f0, r3
; CHECK-P8-NEXT:    xxswapd v2, vs0
; CHECK-P8-NEXT:    xxmrglw v2, v2, v2
; CHECK-P8-NEXT:    xvcvsxwdp v2, v2
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test2elt_signed:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    mtfprd f0, r3
; CHECK-P9-NEXT:    xxswapd v2, vs0
; CHECK-P9-NEXT:    xxmrglw v2, v2, v2
; CHECK-P9-NEXT:    xvcvsxwdp v2, v2
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test2elt_signed:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    mtfprd f0, r3
; CHECK-BE-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvsxwdp v2, v2
; CHECK-BE-NEXT:    blr
entry:
  %0 = bitcast i64 %a.coerce to <2 x i32>
  %1 = sitofp <2 x i32> %0 to <2 x double>
  ret <2 x double> %1
}

define void @test4elt_signed(<4 x double>* noalias nocapture sret(<4 x double>) %agg.result, <4 x i32> %a) local_unnamed_addr #1 {
; CHECK-P8-LABEL: test4elt_signed:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    xxmrglw v3, v2, v2
; CHECK-P8-NEXT:    xxmrghw v2, v2, v2
; CHECK-P8-NEXT:    li r4, 16
; CHECK-P8-NEXT:    xvcvsxwdp vs0, v3
; CHECK-P8-NEXT:    xvcvsxwdp vs1, v2
; CHECK-P8-NEXT:    xxswapd vs0, vs0
; CHECK-P8-NEXT:    xxswapd vs1, vs1
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r4
; CHECK-P8-NEXT:    stxvd2x vs0, 0, r3
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test4elt_signed:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    xxmrglw v3, v2, v2
; CHECK-P9-NEXT:    xxmrghw v2, v2, v2
; CHECK-P9-NEXT:    xvcvsxwdp vs0, v3
; CHECK-P9-NEXT:    xvcvsxwdp vs1, v2
; CHECK-P9-NEXT:    stxv vs1, 16(r3)
; CHECK-P9-NEXT:    stxv vs0, 0(r3)
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test4elt_signed:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    xxmrghw v3, v2, v2
; CHECK-BE-NEXT:    xxmrglw v2, v2, v2
; CHECK-BE-NEXT:    xvcvsxwdp vs0, v3
; CHECK-BE-NEXT:    xvcvsxwdp vs1, v2
; CHECK-BE-NEXT:    stxv vs1, 16(r3)
; CHECK-BE-NEXT:    stxv vs0, 0(r3)
; CHECK-BE-NEXT:    blr
entry:
  %0 = sitofp <4 x i32> %a to <4 x double>
  store <4 x double> %0, <4 x double>* %agg.result, align 32
  ret void
}

define void @test8elt_signed(<8 x double>* noalias nocapture sret(<8 x double>) %agg.result, <8 x i32>* nocapture readonly) local_unnamed_addr #2 {
; CHECK-P8-LABEL: test8elt_signed:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    li r5, 16
; CHECK-P8-NEXT:    lvx v3, 0, r4
; CHECK-P8-NEXT:    li r6, 32
; CHECK-P8-NEXT:    lvx v2, r4, r5
; CHECK-P8-NEXT:    li r4, 48
; CHECK-P8-NEXT:    xxmrglw v5, v3, v3
; CHECK-P8-NEXT:    xxmrghw v3, v3, v3
; CHECK-P8-NEXT:    xxmrglw v4, v2, v2
; CHECK-P8-NEXT:    xxmrghw v2, v2, v2
; CHECK-P8-NEXT:    xvcvsxwdp vs2, v5
; CHECK-P8-NEXT:    xvcvsxwdp vs0, v4
; CHECK-P8-NEXT:    xvcvsxwdp vs1, v2
; CHECK-P8-NEXT:    xvcvsxwdp vs3, v3
; CHECK-P8-NEXT:    xxswapd vs2, vs2
; CHECK-P8-NEXT:    xxswapd vs0, vs0
; CHECK-P8-NEXT:    xxswapd vs1, vs1
; CHECK-P8-NEXT:    xxswapd vs3, vs3
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r4
; CHECK-P8-NEXT:    stxvd2x vs0, r3, r6
; CHECK-P8-NEXT:    stxvd2x vs3, r3, r5
; CHECK-P8-NEXT:    stxvd2x vs2, 0, r3
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test8elt_signed:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    lxv vs1, 0(r4)
; CHECK-P9-NEXT:    lxv vs0, 16(r4)
; CHECK-P9-NEXT:    xxmrglw v2, vs1, vs1
; CHECK-P9-NEXT:    xvcvsxwdp vs2, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs1, vs1
; CHECK-P9-NEXT:    xvcvsxwdp vs1, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-P9-NEXT:    xvcvsxwdp vs3, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-P9-NEXT:    stxv vs2, 0(r3)
; CHECK-P9-NEXT:    xvcvsxwdp vs0, v2
; CHECK-P9-NEXT:    stxv vs1, 16(r3)
; CHECK-P9-NEXT:    stxv vs3, 32(r3)
; CHECK-P9-NEXT:    stxv vs0, 48(r3)
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test8elt_signed:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    lxv vs1, 0(r4)
; CHECK-BE-NEXT:    lxv vs0, 16(r4)
; CHECK-BE-NEXT:    xxmrghw v2, vs1, vs1
; CHECK-BE-NEXT:    xvcvsxwdp vs2, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs1, vs1
; CHECK-BE-NEXT:    xvcvsxwdp vs1, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvsxwdp vs3, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-BE-NEXT:    stxv vs2, 0(r3)
; CHECK-BE-NEXT:    xvcvsxwdp vs0, v2
; CHECK-BE-NEXT:    stxv vs1, 16(r3)
; CHECK-BE-NEXT:    stxv vs3, 32(r3)
; CHECK-BE-NEXT:    stxv vs0, 48(r3)
; CHECK-BE-NEXT:    blr
entry:
  %a = load <8 x i32>, <8 x i32>* %0, align 32
  %1 = sitofp <8 x i32> %a to <8 x double>
  store <8 x double> %1, <8 x double>* %agg.result, align 64
  ret void
}

define void @test16elt_signed(<16 x double>* noalias nocapture sret(<16 x double>) %agg.result, <16 x i32>* nocapture readonly) local_unnamed_addr #2 {
; CHECK-P8-LABEL: test16elt_signed:
; CHECK-P8:       # %bb.0: # %entry
; CHECK-P8-NEXT:    li r5, 16
; CHECK-P8-NEXT:    li r6, 48
; CHECK-P8-NEXT:    li r7, 32
; CHECK-P8-NEXT:    li r8, 64
; CHECK-P8-NEXT:    lvx v2, r4, r5
; CHECK-P8-NEXT:    lvx v3, r4, r6
; CHECK-P8-NEXT:    lvx v0, r4, r7
; CHECK-P8-NEXT:    xxmrglw v4, v2, v2
; CHECK-P8-NEXT:    xxmrghw v5, v3, v3
; CHECK-P8-NEXT:    xxmrghw v2, v2, v2
; CHECK-P8-NEXT:    xxmrglw v3, v3, v3
; CHECK-P8-NEXT:    xvcvsxwdp vs0, v4
; CHECK-P8-NEXT:    lvx v4, 0, r4
; CHECK-P8-NEXT:    li r4, 112
; CHECK-P8-NEXT:    xvcvsxwdp vs1, v5
; CHECK-P8-NEXT:    xxmrghw v5, v0, v0
; CHECK-P8-NEXT:    xxmrglw v0, v0, v0
; CHECK-P8-NEXT:    xvcvsxwdp vs2, v2
; CHECK-P8-NEXT:    xxmrglw v2, v4, v4
; CHECK-P8-NEXT:    xvcvsxwdp vs3, v3
; CHECK-P8-NEXT:    xxmrghw v3, v4, v4
; CHECK-P8-NEXT:    xvcvsxwdp vs4, v5
; CHECK-P8-NEXT:    xvcvsxwdp vs5, v0
; CHECK-P8-NEXT:    xvcvsxwdp vs6, v2
; CHECK-P8-NEXT:    xxswapd vs0, vs0
; CHECK-P8-NEXT:    xvcvsxwdp vs7, v3
; CHECK-P8-NEXT:    xxswapd vs1, vs1
; CHECK-P8-NEXT:    xxswapd vs2, vs2
; CHECK-P8-NEXT:    xxswapd vs3, vs3
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r4
; CHECK-P8-NEXT:    li r4, 96
; CHECK-P8-NEXT:    xxswapd vs4, vs4
; CHECK-P8-NEXT:    xxswapd vs1, vs5
; CHECK-P8-NEXT:    stxvd2x vs3, r3, r4
; CHECK-P8-NEXT:    xxswapd vs5, vs6
; CHECK-P8-NEXT:    li r4, 80
; CHECK-P8-NEXT:    xxswapd vs3, vs7
; CHECK-P8-NEXT:    stxvd2x vs4, r3, r4
; CHECK-P8-NEXT:    stxvd2x vs1, r3, r8
; CHECK-P8-NEXT:    stxvd2x vs2, r3, r6
; CHECK-P8-NEXT:    stxvd2x vs0, r3, r7
; CHECK-P8-NEXT:    stxvd2x vs3, r3, r5
; CHECK-P8-NEXT:    stxvd2x vs5, 0, r3
; CHECK-P8-NEXT:    blr
;
; CHECK-P9-LABEL: test16elt_signed:
; CHECK-P9:       # %bb.0: # %entry
; CHECK-P9-NEXT:    lxv vs0, 0(r4)
; CHECK-P9-NEXT:    lxv vs2, 16(r4)
; CHECK-P9-NEXT:    lxv vs5, 32(r4)
; CHECK-P9-NEXT:    lxv vs4, 48(r4)
; CHECK-P9-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-P9-NEXT:    xvcvsxwdp vs1, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-P9-NEXT:    xvcvsxwdp vs0, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs2, vs2
; CHECK-P9-NEXT:    xvcvsxwdp vs3, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs2, vs2
; CHECK-P9-NEXT:    stxv vs1, 0(r3)
; CHECK-P9-NEXT:    stxv vs0, 16(r3)
; CHECK-P9-NEXT:    xvcvsxwdp vs2, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs5, vs5
; CHECK-P9-NEXT:    xvcvsxwdp vs6, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs5, vs5
; CHECK-P9-NEXT:    stxv vs3, 32(r3)
; CHECK-P9-NEXT:    stxv vs2, 48(r3)
; CHECK-P9-NEXT:    xvcvsxwdp vs5, v2
; CHECK-P9-NEXT:    xxmrglw v2, vs4, vs4
; CHECK-P9-NEXT:    xvcvsxwdp vs7, v2
; CHECK-P9-NEXT:    xxmrghw v2, vs4, vs4
; CHECK-P9-NEXT:    stxv vs6, 64(r3)
; CHECK-P9-NEXT:    stxv vs5, 80(r3)
; CHECK-P9-NEXT:    xvcvsxwdp vs4, v2
; CHECK-P9-NEXT:    stxv vs7, 96(r3)
; CHECK-P9-NEXT:    stxv vs4, 112(r3)
; CHECK-P9-NEXT:    blr
;
; CHECK-BE-LABEL: test16elt_signed:
; CHECK-BE:       # %bb.0: # %entry
; CHECK-BE-NEXT:    lxv vs0, 0(r4)
; CHECK-BE-NEXT:    lxv vs2, 16(r4)
; CHECK-BE-NEXT:    lxv vs5, 32(r4)
; CHECK-BE-NEXT:    lxv vs4, 48(r4)
; CHECK-BE-NEXT:    xxmrghw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvsxwdp vs1, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs0, vs0
; CHECK-BE-NEXT:    xvcvsxwdp vs0, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs2, vs2
; CHECK-BE-NEXT:    xvcvsxwdp vs3, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs2, vs2
; CHECK-BE-NEXT:    stxv vs1, 0(r3)
; CHECK-BE-NEXT:    stxv vs0, 16(r3)
; CHECK-BE-NEXT:    xvcvsxwdp vs2, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs5, vs5
; CHECK-BE-NEXT:    xvcvsxwdp vs6, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs5, vs5
; CHECK-BE-NEXT:    stxv vs3, 32(r3)
; CHECK-BE-NEXT:    stxv vs2, 48(r3)
; CHECK-BE-NEXT:    xvcvsxwdp vs5, v2
; CHECK-BE-NEXT:    xxmrghw v2, vs4, vs4
; CHECK-BE-NEXT:    xvcvsxwdp vs7, v2
; CHECK-BE-NEXT:    xxmrglw v2, vs4, vs4
; CHECK-BE-NEXT:    stxv vs6, 64(r3)
; CHECK-BE-NEXT:    stxv vs5, 80(r3)
; CHECK-BE-NEXT:    xvcvsxwdp vs4, v2
; CHECK-BE-NEXT:    stxv vs7, 96(r3)
; CHECK-BE-NEXT:    stxv vs4, 112(r3)
; CHECK-BE-NEXT:    blr
entry:
  %a = load <16 x i32>, <16 x i32>* %0, align 64
  %1 = sitofp <16 x i32> %a to <16 x double>
  store <16 x double> %1, <16 x double>* %agg.result, align 128
  ret void
}
