//===- TracePC.cpp - PC tracing--------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Trace PCs.
// This module implements __sanitizer_cov_trace_pc_guard[_init],
// the callback required for -fsanitize-coverage=trace-pc-guard instrumentation.
//
//===----------------------------------------------------------------------===//

#include <unistd.h>
#include "TracePC.h"
#include "Defs.h"
#include "Dictionary.h"
#include "Util.h"

TracePC TPC;

size_t SimpleFastHash(const uint8_t *Data, size_t Size) {
  size_t Res = 0;
  for (size_t i = 0; i < Size; i++)
    Res = Res * 11 + Data[i];
  return Res;
}


void TracePC::HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop) {
  if (Start == Stop) return;
  if (NumModules &&
      Modules[NumModules - 1].Start() == Start)
    return;
  assert(NumModules <
         sizeof(Modules) / sizeof(Modules[0]));
  auto &M = Modules[NumModules++];
  uint8_t *AlignedStart = RoundUpByPage(Start);
  uint8_t *AlignedStop  = RoundDownByPage(Stop);
  size_t NumFullPages = AlignedStop > AlignedStart ?
                        (AlignedStop - AlignedStart) / PageSize() : 0;
  bool NeedFirst = Start < AlignedStart || !NumFullPages;
  bool NeedLast  = Stop > AlignedStop && AlignedStop >= AlignedStart;
  M.NumRegions = NumFullPages + NeedFirst + NeedLast;;
  assert(M.NumRegions > 0);
  M.Regions = (Module::Region*) calloc(M.NumRegions, sizeof(Module::Region));
  assert(M.Regions);
  size_t R = 0;
  if (NeedFirst)
    M.Regions[R++] = {Start, std::min(Stop, AlignedStart), true, false};
  for (uint8_t *P = AlignedStart; P < AlignedStop; P += PageSize())
    M.Regions[R++] = {P, P + PageSize(), true, true};
  if (NeedLast)
    M.Regions[R++] = {AlignedStop, Stop, true, false};
  assert(R == M.NumRegions);
  assert(M.Size() == (size_t)(Stop - Start));
  assert(M.Stop() == Stop);
  assert(M.Start() == Start);
  NumInline8bitCounters += M.Size();
}

void TracePC::HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop) {
  const PCTableEntry *B = reinterpret_cast<const PCTableEntry *>(Start);
  const PCTableEntry *E = reinterpret_cast<const PCTableEntry *>(Stop);
  if (NumPCTables && ModulePCTable[NumPCTables - 1].Start == B) return;
  assert(NumPCTables < sizeof(ModulePCTable) / sizeof(ModulePCTable[0]));
  ModulePCTable[NumPCTables++] = {B, E};
  NumPCsInPCTables += E - B;
}


ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::HandleCallerCallee(uintptr_t Caller, uintptr_t Callee) {
  if (!Initialized) return;
  const uintptr_t kBits = 12;
  const uintptr_t kMask = (1 << kBits) - 1;
  uintptr_t Idx = (Caller & kMask) | ((Callee & kMask) << kBits);
  ValueProfileMap.AddValueModPrime(Idx);
}


// Value profile.
// We keep track of various values that affect control flow.
// These values are inserted into a bit-set-based hash map.
// Every new bit in the map is treated as a new coverage.
//
// For memcmp/strcmp/etc the interesting value is the length of the common
// prefix of the parameters.
// For cmp instructions the interesting value is a XOR of the parameters.
// The interesting value is mixed up with the PC and is then added to the map.

ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                                size_t n, bool StopAtZero) {
  if (!Initialized) return;
  if (!n) return;
  size_t Len = std::min(n, Word::GetMaxSize());
  const uint8_t *A1 = reinterpret_cast<const uint8_t *>(s1);
  const uint8_t *A2 = reinterpret_cast<const uint8_t *>(s2);
  uint8_t B1[Word::kMaxSize];
  uint8_t B2[Word::kMaxSize];
  // Copy the data into locals in this non-msan-instrumented function
  // to avoid msan complaining further.
  size_t Hash = 0;  // Compute some simple hash of both strings.
  for (size_t i = 0; i < Len; i++) {
    B1[i] = A1[i];
    B2[i] = A2[i];
    size_t T = B1[i];
    Hash ^= (T << 8) | B2[i];
  }
  size_t I = 0;
  uint8_t HammingDistance = 0;
  for (; I < Len; I++) {
    if (B1[I] != B2[I] || (StopAtZero && B1[I] == 0)) {
      HammingDistance = Popcountll(B1[I] ^ B2[I]);
      break;
    }
  }
  size_t PC = reinterpret_cast<size_t>(caller_pc);
  size_t Idx = (PC & 4095) | (I << 12);
  Idx += HammingDistance;
  ValueProfileMap.AddValue(Idx);
  TORCW.Insert(Idx ^ Hash, B1, B2, Len);
}

template <class T>
ATTRIBUTE_TARGET_POPCNT ALWAYS_INLINE
ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::HandleCmp(uintptr_t PC, T Arg1, T Arg2) {
  if (!Initialized) return;
  uint64_t ArgXor = Arg1 ^ Arg2;
  if (sizeof(T) == 4)
      TORC4.Insert(ArgXor, Arg1, Arg2);
  else if (sizeof(T) == 8)
      TORC8.Insert(ArgXor, Arg1, Arg2);
  uint64_t HammingDistance = Popcountll(ArgXor);  // [0,64]
  uint64_t AbsoluteDistance = (Arg1 == Arg2 ? 0 : Clzll(Arg1 - Arg2) + 1);
  ValueProfileMap.AddValue(PC * 128 + HammingDistance);
  ValueProfileMap.AddValue(PC * 128 + 64 + AbsoluteDistance);
}

static size_t InternalStrnlen(const char *S, size_t MaxLen) {
  size_t Len = 0;
  for (; Len < MaxLen && S[Len]; Len++) {}
  return Len;
}

// Finds min of (strlen(S1), strlen(S2)).
// Needed bacause one of these strings may actually be non-zero terminated.
static size_t InternalStrnlen2(const char *S1, const char *S2) {
  size_t Len = 0;
  for (; S1[Len] && S2[Len]; Len++)  {}
  return Len;
}

ATTRIBUTE_TARGET_POPCNT ALWAYS_INLINE
ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::TraceInline8bitCounters(uintptr_t p) {
    for (unsigned int i = 0; i < NumModules; ++i) {
        if (p >= reinterpret_cast<uintptr_t>(Modules[i].Start()) && p <= reinterpret_cast<uintptr_t>(Modules[i].Stop())) {
            uint8_t *ActualPointer = reinterpret_cast<uint8_t*>(Modules[i].SharedStart + (p - reinterpret_cast<uintptr_t>(Modules[i].Start()))); 
            (*ActualPointer)++;
            return;
        }
    }
}

extern "C" {

// Best-effort support for -fsanitize-coverage=trace-pc, which is available
// in both Clang and GCC.
ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc() {
  ;
}

ATTRIBUTE_INTERFACE
void __sanitizer_cov_trace_pc_guard_init(uint32_t *Start, uint32_t *Stop) {
  ;
}

ATTRIBUTE_INTERFACE
void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop) {
  TPC.HandleInline8bitCountersInit(Start, Stop);
}

ATTRIBUTE_INTERFACE
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end) {
  TPC.HandlePCsInit(pcs_beg, pcs_end);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc_indir(uintptr_t Callee) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCallerCallee(PC, Callee);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
// Now the __sanitizer_cov_trace_const_cmp[1248] callbacks just mimic
// the behaviour of __sanitizer_cov_trace_cmp[1248] ones. This, however,
// should be changed later to make full use of instrumentation.
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases) {
  uint64_t N = Cases[0];
  uint64_t ValSizeInBits = Cases[1];
  uint64_t *Vals = Cases + 2;
  // Skip the most common and the most boring case: all switch values are small.
  // We may want to skip this at compile-time, but it will make the
  // instrumentation less general.
  if (Vals[N - 1]  < 256)
    return;
  // Also skip small inputs values, they won't give good signal.
  if (Val < 256)
    return;
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  size_t i;
  uint64_t Smaller = 0;
  uint64_t Larger = ~(uint64_t)0;
  // Find two switch values such that Smaller < Val < Larger.
  // Use 0 and 0xfff..f as the defaults.
  for (i = 0; i < N; i++) {
    if (Val < Vals[i]) {
      Larger = Vals[i];
      break;
    }
    if (Val > Vals[i]) Smaller = Vals[i];
  }

  // Apply HandleCmp to {Val,Smaller} and {Val, Larger},
  // use i as the PC modifier for HandleCmp.
  if (ValSizeInBits == 16) {
    TPC.HandleCmp(PC + 2 * i, static_cast<uint16_t>(Val),
                          (uint16_t)(Smaller));
    TPC.HandleCmp(PC + 2 * i + 1, static_cast<uint16_t>(Val),
                          (uint16_t)(Larger));
  } else if (ValSizeInBits == 32) {
    TPC.HandleCmp(PC + 2 * i, static_cast<uint32_t>(Val),
                          (uint32_t)(Smaller));
    TPC.HandleCmp(PC + 2 * i + 1, static_cast<uint32_t>(Val),
                          (uint32_t)(Larger));
  } else {
    TPC.HandleCmp(PC + 2*i, Val, Smaller);
    TPC.HandleCmp(PC + 2*i + 1, Val, Larger);
  }
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_div4(uint32_t Val) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Val, (uint32_t)0);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_div8(uint64_t Val) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Val, (uint64_t)0);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_gep(uintptr_t Idx) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(GET_CALLER_PC());
  TPC.HandleCmp(PC, Idx, (uintptr_t)0);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *s1,
                                  const void *s2, size_t n, int result) {
  if (result == 0) return;  // No reason to mutate.
  if (n <= 1) return;  // Not interesting.
  TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/false);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strncmp(void *caller_pc, const char *s1,
                                   const char *s2, size_t n, int result) {
  if (result == 0) return;  // No reason to mutate.
  size_t Len1 = InternalStrnlen(s1, n);
  size_t Len2 = InternalStrnlen(s2, n);
  n = std::min(n, Len1);
  n = std::min(n, Len2);
  if (n <= 1) return;  // Not interesting.
  TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/true);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1,
                                   const char *s2, int result) {
  if (result == 0) return;  // No reason to mutate.
  size_t N = InternalStrnlen2(s1, s2);
  if (N <= 1) return;  // Not interesting.
  TPC.AddValueForMemcmp(caller_pc, s1, s2, N, /*StopAtZero*/true);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strncasecmp(void *called_pc, const char *s1,
                                       const char *s2, size_t n, int result) {
  return __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcasecmp(void *called_pc, const char *s1,
                                      const char *s2, int result) {
  return __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strstr(void *called_pc, const char *s1,
                                  const char *s2, char *result) {
  TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcasestr(void *called_pc, const char *s1,
                                      const char *s2, char *result) {
  TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_memmem(void *called_pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result) {
  TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), len2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT ALWAYS_INLINE
void __sanitizer_cov_trace_inline_8bit_counters(uint8_t* ptr) {
    uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
    TPC.TraceInline8bitCounters(p);
}


}  // extern "C"



