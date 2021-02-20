; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --check-attributes
; RUN: opt -attributor -enable-new-pm=0 -attributor-manifest-internal  -attributor-max-iterations-verify -attributor-annotate-decl-cs -attributor-max-iterations=1 -S < %s | FileCheck %s --check-prefixes=CHECK,NOT_CGSCC_NPM,NOT_CGSCC_OPM,NOT_TUNIT_NPM,IS__TUNIT____,IS________OPM,IS__TUNIT_OPM
; RUN: opt -aa-pipeline=basic-aa -passes=attributor -attributor-manifest-internal  -attributor-max-iterations-verify -attributor-annotate-decl-cs -attributor-max-iterations=1 -S < %s | FileCheck %s --check-prefixes=CHECK,NOT_CGSCC_OPM,NOT_CGSCC_NPM,NOT_TUNIT_OPM,IS__TUNIT____,IS________NPM,IS__TUNIT_NPM
; RUN: opt -attributor-cgscc -enable-new-pm=0 -attributor-manifest-internal  -attributor-annotate-decl-cs -S < %s | FileCheck %s --check-prefixes=CHECK,NOT_TUNIT_NPM,NOT_TUNIT_OPM,NOT_CGSCC_NPM,IS__CGSCC____,IS________OPM,IS__CGSCC_OPM
; RUN: opt -aa-pipeline=basic-aa -passes=attributor-cgscc -attributor-manifest-internal  -attributor-annotate-decl-cs -S < %s | FileCheck %s --check-prefixes=CHECK,NOT_TUNIT_NPM,NOT_TUNIT_OPM,NOT_CGSCC_OPM,IS__CGSCC____,IS________NPM,IS__CGSCC_NPM

; Make sure we need a single iteration to determine the chains are dead/alive.

declare i32 @source() nounwind readonly

define i32 @chain_dead(i32 %arg) {
; IS__TUNIT____: Function Attrs: nofree nosync nounwind readnone willreturn
; IS__TUNIT____-LABEL: define {{[^@]+}}@chain_dead
; IS__TUNIT____-SAME: (i32 [[ARG:%.*]]) [[ATTR1:#.*]] {
; IS__TUNIT____-NEXT:    ret i32 0
;
; IS__CGSCC____: Function Attrs: nofree norecurse nosync nounwind readnone willreturn
; IS__CGSCC____-LABEL: define {{[^@]+}}@chain_dead
; IS__CGSCC____-SAME: (i32 [[ARG:%.*]]) [[ATTR1:#.*]] {
; IS__CGSCC____-NEXT:    ret i32 0
;
  %init = call i32 @source()
  %v0 = add i32 %arg, %init
  %v1 = add i32 %init, %v0
  %v2 = add i32 %v0, %v1
  %v3 = add i32 %v1, %v2
  %v4 = add i32 %v2, %v3
  %v5 = add i32 %v3, %v4
  %v6 = add i32 %v4, %v5
  %v7 = add i32 %v5, %v6
  %v8 = add i32 %v6, %v7
  %v9 = add i32 %v7, %v8
  ret i32 0
}

define i32 @chain_alive(i32 %arg) {
; CHECK: Function Attrs: nounwind readonly
; CHECK-LABEL: define {{[^@]+}}@chain_alive
; CHECK-SAME: (i32 [[ARG:%.*]]) [[ATTR0:#.*]] {
; CHECK-NEXT:    [[INIT:%.*]] = call i32 @source() [[ATTR2:#.*]]
; CHECK-NEXT:    [[V0:%.*]] = add i32 [[ARG]], [[INIT]]
; CHECK-NEXT:    [[V1:%.*]] = add i32 [[INIT]], [[V0]]
; CHECK-NEXT:    [[V2:%.*]] = add i32 [[V0]], [[V1]]
; CHECK-NEXT:    [[V3:%.*]] = add i32 [[V1]], [[V2]]
; CHECK-NEXT:    [[V4:%.*]] = add i32 [[V2]], [[V3]]
; CHECK-NEXT:    [[V5:%.*]] = add i32 [[V3]], [[V4]]
; CHECK-NEXT:    [[V6:%.*]] = add i32 [[V4]], [[V5]]
; CHECK-NEXT:    [[V7:%.*]] = add i32 [[V5]], [[V6]]
; CHECK-NEXT:    [[V8:%.*]] = add i32 [[V6]], [[V7]]
; CHECK-NEXT:    [[V9:%.*]] = add i32 [[V7]], [[V8]]
; CHECK-NEXT:    ret i32 [[V9]]
;
  %init = call i32 @source()
  %v0 = add i32 %arg, %init
  %v1 = add i32 %init, %v0
  %v2 = add i32 %v0, %v1
  %v3 = add i32 %v1, %v2
  %v4 = add i32 %v2, %v3
  %v5 = add i32 %v3, %v4
  %v6 = add i32 %v4, %v5
  %v7 = add i32 %v5, %v6
  %v8 = add i32 %v6, %v7
  %v9 = add i32 %v7, %v8
  ret i32 %v9
}
