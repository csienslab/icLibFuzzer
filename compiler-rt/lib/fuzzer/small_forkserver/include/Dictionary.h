//===- Dictionary.h - Internal header for the  ------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// fuzzer::Dictionary
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_DICTIONARY_H
#define LLVM_FUZZER_DICTIONARY_H

#include "Defs.h"

#include <stdlib.h>
#include <string.h>

// A simple POD sized array of bytes.
template <size_t kMaxSizeT> class FixedWord {
public:
  static const size_t kMaxSize = kMaxSizeT;
  FixedWord() {}
  FixedWord(const uint8_t *B, uint8_t S) { Set(B, S); }

  void init(uint8_t *Pointer) {
    Data = Pointer;
    Size = Pointer + kMaxSize * sizeof(uint8_t);
  }

  void Set(const uint8_t *B, uint8_t S) {
    assert(S <= kMaxSize);
    memcpy(Data, B, S);
    *Size = S;
  }

  static size_t GetMaxSize() { return kMaxSize; }

private:
  uint8_t *Size;
  uint8_t *Data;
};
typedef FixedWord<64> Word;

#endif  // LLVM_FUZZER_DICTIONARY_H
