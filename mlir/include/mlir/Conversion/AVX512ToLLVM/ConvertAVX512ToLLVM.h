//===- ConvertAVX512ToLLVM.h - Conversion Patterns from AVX512 to LLVM ----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef MLIR_CONVERSION_AVX512TOLLVM_CONVERTAVX512TOLLVM_H_
#define MLIR_CONVERSION_AVX512TOLLVM_CONVERTAVX512TOLLVM_H_

namespace mlir {

class LLVMTypeConverter;
class OwningRewritePatternList;

/// Collect a set of patterns to convert from the AVX512 dialect to LLVM.
void populateAVX512ToLLVMConversionPatterns(LLVMTypeConverter &converter,
                                            OwningRewritePatternList &patterns);

} // namespace mlir

#endif // MLIR_CONVERSION_AVX512TOLLVM_CONVERTAVX512TOLLVM_H_
