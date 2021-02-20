//===- FuzzerUtil.h - Internal header for the Fuzzer Utils ------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Util functions.
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_UTIL_H
#define LLVM_FUZZER_UTIL_H

#include "Builtins.h"
#include "BuiltinsMsvc.h"
#include "Defs.h"

inline size_t PageSize() { return 4096; }
inline uint8_t *RoundUpByPage(uint8_t *P) {
  uintptr_t X = reinterpret_cast<uintptr_t>(P);
  size_t Mask = PageSize() - 1;
  X = (X + Mask) & ~Mask;
  return reinterpret_cast<uint8_t *>(X);
}
inline uint8_t *RoundDownByPage(uint8_t *P) {
  uintptr_t X = reinterpret_cast<uintptr_t>(P);
  size_t Mask = PageSize() - 1;
  X = X & ~Mask;
  return reinterpret_cast<uint8_t *>(X);
}


#endif  // LLVM_FUZZER_UTIL_H
