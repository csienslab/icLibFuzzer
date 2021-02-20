//===- FuzzerTracePC.h - Internal header for the Fuzzer ---------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// fuzzer::TracePC
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_TRACE_PC
#define LLVM_FUZZER_TRACE_PC

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerValueBitMap.h"

#include <set>
#include <unordered_map>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/types.h>

extern int __libfuzzer_argc;
extern uint8_t __FUZZ_COUNTERS_START;
extern uint8_t __FUZZ_COUNTERS_END;
namespace fuzzer {

// TableOfRecentCompares (TORC) remembers the most recently performed
// comparisons of type T.
// We record the arguments of CMP instructions in this table unconditionally
// because it seems cheaper this way than to compute some expensive
// conditions inside __sanitizer_cov_trace_cmp*.
// After the unit has been executed we may decide to use the contents of
// this table to populate a Dictionary.
template<class T, size_t kSizeT>
struct TableOfRecentCompares {
  static const size_t kSize = kSizeT;
  struct Pair {
    T A, B;
  };

  size_t NeededSize() {
      return kSize * sizeof(Pair) + 1;
  }
  size_t AllocShareMemory(uint8_t *MmapTable) {
    fprintf(stderr, "[TORC] mmap start from %p\n", MmapTable);
    Table = (Pair *) MmapTable;
    return kSize * sizeof(Pair) + 1;
  }


  ATTRIBUTE_NO_SANITIZE_ALL
  void Insert(size_t Idx, const T &Arg1, const T &Arg2) {
    Idx = Idx % kSize;
    Table[Idx].A = Arg1;
    Table[Idx].B = Arg2;
  }

  Pair Get(size_t I) { return Table[I % kSize]; }

  Pair *Table;
  // Pair Table[kSizeT];
};


template<size_t kSizeT>
struct TableOfRecentComparesWord {
  struct Pair {
    Word A, B;
  };

  size_t NeededSize() {
    // Get each size
    const size_t kMaxSingleSize = Table[0].A.GetMaxSize() * sizeof(uint8_t) + /*space for uint8_t Size*/1;
    return kMaxSingleSize * kSize * 2;
  }
  size_t AllocShareMemory(uint8_t *MmapTable) {
    fprintf(stderr, "[TORCW] mmap start from %p\n", MmapTable);
    const size_t kMaxSingleSize = Table[0].A.GetMaxSize() * sizeof(uint8_t) + /*space for uint8_t Size*/1;
    for (unsigned int i = 0; i < kSize; ++i) {
      Table[i].A.init(/*Pointer=*/MmapTable + 2 * i * kMaxSingleSize);
      Table[i].B.init(/*Pointer=*/MmapTable + (2 * i + 1) * kMaxSingleSize);
    }
    return kMaxSingleSize * kSize * 2;
  }
  static const size_t kSize = kSizeT;

  ATTRIBUTE_NO_SANITIZE_ALL
  void Insert(size_t Idx, const uint8_t *Arg1, const uint8_t *Arg2, size_t Len) {
    Idx = Idx % kSize;
    Table[Idx].A.Set(Arg1, Len);
    Table[Idx].B.Set(Arg2, Len);
  }

  Pair Get(size_t I) { return Table[I % kSize]; }
  Pair Table[kSize];
};

template <size_t kSizeT>
struct MemMemTable {

  size_t NeededSize() {
    // Get each size
    const size_t kMaxSingleSize = MemMemWords[0].GetMaxSize() * sizeof(uint8_t) + /*for uint8_t Size*/1;
    return kMaxSingleSize * kSize;
  }
  size_t AllocShareMemory(uint8_t *MmapTable) {
    fprintf(stderr, "[MMT] mmap start from %p\n", MmapTable);
    const size_t kMaxSingleSize = MemMemWords[0].GetMaxSize() * sizeof(uint8_t) + /*for uint8_t Size*/1;
    for (unsigned int i = 0; i < kSize; ++i) {
      MemMemWords[i].init(/*Pointer=*/MmapTable + kMaxSingleSize * i);
    }
    return kMaxSingleSize * kSize;
  }

  static const size_t kSize = kSizeT;
  Word MemMemWords[kSize];
  Word EmptyWord;

  void Add(const uint8_t *Data, size_t Size) {
    if (Size <= 2) return;
    Size = std::min(Size, Word::GetMaxSize());
    size_t Idx = SimpleFastHash(Data, Size) % kSize;
    MemMemWords[Idx].Set(Data, Size);
  }
  const Word &Get(size_t Idx) {
    for (size_t i = 0; i < kSize; i++) {
      const Word &W = MemMemWords[(Idx + i) % kSize];
      if (W.size()) return W;
    }
    EmptyWord.Set(nullptr, 0);
    return EmptyWord;
  }
};

class TracePC {
 public:
  void HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop);
  void HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop);
  void HandleCallerCallee(uintptr_t Caller, uintptr_t Callee);
  template <class T> void HandleCmp(uintptr_t PC, T Arg1, T Arg2);
  size_t GetTotalPCCoverage();
  void SetUseCounters(bool UC) { UseCounters = UC; }
  void SetUseValueProfileMask(uint32_t VPMask) { UseValueProfileMask = VPMask; }
  void TraceInline8bitCounters(uintptr_t p);  
  void SetPrintNewPCs(bool P) { DoPrintNewPCs = P; }
  void SetPrintNewFuncs(size_t P) { NumPrintNewFuncs = P; }
  void UpdateObservedPCs();
  template <class Callback> void CollectFeatures(Callback CB) const;

  void ResetMaps() {
    ValueProfileMap.Reset();
    ClearExtraCounters();
    ClearInlineCounters();
  }

  void ClearInlineCounters();

  void UpdateFeatureSet(size_t CurrentElementIdx, size_t CurrentElementSize);
  void PrintFeatureSet();

  void PrintModuleInfo();

  void PrintCoverage();

  template<class CallBack>
  void IterateCoveredFunctions(CallBack CB);

  void AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                         size_t n, bool StopAtZero);

  TableOfRecentCompares<uint32_t, 32> TORC4;
  TableOfRecentCompares<uint64_t, 32> TORC8;
  TableOfRecentComparesWord<32> TORCW;
  MemMemTable<1024> MMT;

  void RecordInitialStack();
  uintptr_t GetMaxStackOffset() const;

  template<class CallBack>
  void ForEachObservedPC(CallBack CB) {
    for (auto PC : ObservedPCs)
      CB(PC);
  }

  void SetFocusFunction(const std::string &FuncName);
  bool ObservedFocusFunction();

  struct PCTableEntry {
    uintptr_t PC, PCFlags;
  };

  uintptr_t PCTableEntryIdx(const PCTableEntry *TE);
  const PCTableEntry *PCTableEntryByIdx(uintptr_t Idx);
  static uintptr_t GetNextInstructionPc(uintptr_t PC);
  bool PcIsFuncEntry(const PCTableEntry *TE) { return TE->PCFlags & 1; }


  ATTRIBUTE_NO_SANITIZE_ADDRESS 
  void Initialize() {
    Initialized = true;
    size_t TotalSize = 0;
    size_t CurrentSize = 0;
    // Modules
    // FIXME:
    //    we now map &__FUZZ_COUNTERS_START to &__FUZZ_COUNTERS_END to shared memory directly
    //    should check if this work when there are multiple modules
    MapModulesToSharedMemory();
    fprintf(stderr, "[DEBUG] NumModules: %lu\n", NumModules);
    for (unsigned int i = 0; i < NumModules; ++i) {
      /* 
      fprintf(stderr, "[DEBUG] NumRegions: %lu\n", Modules[i].NumRegions);
      char FileName[0x100];
      int Res = snprintf(FileName, 0xff, "/dev/shm/libfuzzer_%d_modules_%d", FuzzingNumber, i);
      assert(Res > 0);
      int fd = open(FileName, O_CREAT | O_RDWR, 0666);
      Res = ftruncate(fd, (uint64_t)Modules[i].Size() + 1);
      assert(Res == 0 && "change size of Modules' share file");
      ModuleCountersBackup[i] = (char *) mmap(0, (uint64_t)Modules[i].Size() + 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      close(fd);
      memset(ModuleCountersBackup[i], 0, (uint64_t)Modules[i].Size() + 1);
      */
      // FIXME:
      // Reallocate Regions in Modules since we read Region size from forkserver
      // This should be further refactored
      /*
      uint8_t *RegionStart = (uint8_t *) ModuleCountersBackup[i];
      for (unsigned int j = 0; j < Modules[i].NumRegions; ++j) {
        fprintf(stderr, "[PARENT] [%lu] Start: %p\n", j, Modules[i].Regions[j].Start);
        fprintf(stderr, "[PARENT] [%lu] Stop: %p\n", j, Modules[i].Regions[j].Stop);
        size_t size = Modules[i].Regions[j].Stop - Modules[i].Regions[j].Start;
        Modules[i].Regions[j].Start = RegionStart;
        RegionStart += size;
        Modules[i].Regions[j].Stop = RegionStart;
        fprintf(stderr, "[PARENT] [%lu] After: Start: %p\n", j, Modules[i].Regions[j].Start);
        fprintf(stderr, "[PARENT] [%lu] After: Stop: %p\n", j, Modules[i].Regions[j].Stop);

        if ((uintptr_t)(Modules[i].Regions[j].Start) % 0x1000 == 0 &&
                (uintptr_t)(Modules[i].Regions[j].Stop) % 0x1000 == 0) {
            Modules[i].Regions[j].OneFullPage = true;
        }
        else {
            Modules[i].Regions[j].OneFullPage = false;
        }
      }
      */
      // TotalSize += Modules[i].Size();
    }
    
    // Get total needed size and map only once
    TotalSize += ValueProfileMap.NeededSize();
    TotalSize += TORC4.NeededSize();
    TotalSize += TORC8.NeededSize();
    TotalSize += TORCW.NeededSize();
    TotalSize += MMT.NeededSize();

    // map first
    char FuzzingName[0x100];
    int Res = snprintf(FuzzingName, 0xff, "/libfuzzer_%d", FuzzingNumber);
    assert(Res > 0 && "create share file name");
    int fd = shm_open(FuzzingName, O_CREAT | O_RDWR, 0666);
    Res = ftruncate(fd, TotalSize);
    assert(Res == 0 && "change file size of share file");
    uint8_t *MmapTable = (uint8_t *) mmap(0, TotalSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    memset(MmapTable, 0, TotalSize);

    fprintf(stderr, "[mmap] start from %p, end at %p\n", MmapTable, MmapTable + TotalSize);
    // split the mmaped space to each data structure
    /*SharedStart = MmapTable;
    for (unsigned int i = 0; i < NumModules; ++i) { 
        Modules[i].SharedStart = MmapTable + CurrentSize;
        uint8_t* ModuleStart = Modules[i].Start();
        for (unsigned int j = 0; j < Modules[i].NumRegions; ++j) {
            Modules[i].Regions[j].Start += (Modules[i].SharedStart - ModuleStart);
            Modules[i].Regions[j].Stop += (Modules[i].SharedStart - ModuleStart);
        }
        fprintf(stderr, "[DEBUG] %p, %p, %p\n", MmapTable + CurrentSize, Modules[i].Start(), Modules[i].Stop());
        CurrentSize += Modules[i].Size();
    }
    SharedSize = CurrentSize;
    */
    fprintf(stderr, "[PARENT] ValueProfileMap start from %p\n", MmapTable + CurrentSize);
    CurrentSize += ValueProfileMap.AllocShareMemory(MmapTable + CurrentSize);
    fprintf(stderr, "[PARENT] TORC4 start from %p\n", MmapTable + CurrentSize);
    CurrentSize += TORC4.AllocShareMemory(MmapTable + CurrentSize);
    fprintf(stderr, "[PARENT] TORC8 start from %p\n", MmapTable + CurrentSize);
    CurrentSize += TORC8.AllocShareMemory(MmapTable + CurrentSize);
    fprintf(stderr, "[PARENT] TORCW start from %p\n", MmapTable + CurrentSize);
    CurrentSize += TORCW.AllocShareMemory(MmapTable + CurrentSize);
    fprintf(stderr, "[PARENT] MMT start from %p\n", MmapTable + CurrentSize);
    CurrentSize += MMT.AllocShareMemory(MmapTable + CurrentSize);
    fprintf(stderr, "[PARENT] Total size %zi\n", CurrentSize);
    assert(CurrentSize == TotalSize && "TotalSize not equal to needed size, should not happen");
  }
  
  ATTRIBUTE_NO_SANITIZE_ADDRESS 
  void MapModulesToSharedMemory() {
      char FileName[0x100];
      int Res = snprintf(FileName, 0xff, "/libfuzzer_%d_modules", FuzzingNumber);
      assert(Res > 0);
      int fd = shm_open(FileName, O_CREAT | O_RDWR, 0666);
      Res = ftruncate(fd, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);
      assert(Res == 0 && "change size of Modules' share file");
      void *SharedModules = (char *) mmap(0, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      memcpy(SharedModules, &__FUZZ_COUNTERS_START, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);
      munmap(SharedModules, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);
      SharedModules = (char *) mmap(&__FUZZ_COUNTERS_START, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
      close(fd);
  }
  
  void CopyModuleCountersToFile() {
    return;
    for (unsigned int i = 0; i < NumModules; ++i)
        memcpy(ModuleCountersBackup[i], Modules[i].Start(), Modules[i].Size());
  }

  void CopyFileToModuleCounters() {
    return;
    for (unsigned int i = 0; i < NumModules; ++i)
        memcpy(Modules[i].Start(), ModuleCountersBackup[i], Modules[i].Size());
  }

  void CheckSameSizeToForkserver(int WriteStartToForkServerFD) {
    for (unsigned int i = 0; i < NumModules; ++i) {
      size_t size;
      size = Modules[i].Size();
      assert(write(WriteStartToForkServerFD, &size, sizeof(size_t)) == sizeof(size_t));  
    }

    for (unsigned int i = 0; i < NumPCTables; ++i) {
      size_t size = ModulePCTable[i].Stop->PC - ModulePCTable[i].Start->PC;
      assert(write(WriteStartToForkServerFD, &size, sizeof(size_t)) == sizeof(size_t));
    }
  }

  void CheckSameSizeToParent(int ReadStartFromParentFD) {
    for (unsigned int i = 0; i < NumModules; ++i) {
      size_t size;
      size = Modules[i].Size();
      assert(read(ReadStartFromParentFD, &size, sizeof(size_t)) == sizeof(size_t));  
      assert(size == Modules[i].Size());
    }

    for (unsigned int i = 0; i < NumPCTables; ++i) {
      size_t size;
      assert(read(ReadStartFromParentFD, &size, sizeof(size_t)) == sizeof(size_t));
      assert(size==ModulePCTable[i].Stop->PC - ModulePCTable[i].Start->PC);
    }
  }

  void ReadModulesFromForkserver(int ReadStatusFromForkserverFD) {
      // Back up original NumModules first
      size_t OldNumModules = NumModules;

      assert(read(ReadStatusFromForkserverFD, &NumModules, sizeof(size_t)) == sizeof(size_t));
      fprintf(stderr, "[PARENT] get NumModules: %lu\n", NumModules);
      for (size_t i = 0; i < NumModules; ++i) {
          assert(read(ReadStatusFromForkserverFD, &(Modules[i].NumRegions), sizeof(size_t)) == sizeof(size_t));
          fprintf(stderr, "[PARENT] get Modules[%lu].NumRegions: %lu\n", i, Modules[i].NumRegions);
          Modules[i].Regions = new Module::Region[Modules[i].NumRegions];
          for (size_t j = 0; j < Modules[i].NumRegions; ++j) {
              assert(read(ReadStatusFromForkserverFD, &(Modules[i].Regions[j].Start), sizeof(uint8_t*)) == sizeof(uint8_t*));
              assert(read(ReadStatusFromForkserverFD, &(Modules[i].Regions[j].Stop), sizeof(uint8_t*)) == sizeof(uint8_t*));
              Modules[i].Regions[j].Enabled = true;
          }
      }
      assert(read(ReadStatusFromForkserverFD, &NumInline8bitCounters, sizeof(size_t)) == sizeof(size_t));
      
      // Now discard all Modules between NumModules ~ OldNumModules
      for (size_t i = NumModules; i < OldNumModules; ++i) {
          for (size_t j = 0; j < Modules[i].NumRegions; ++j) {
              Modules[i].Regions[j].Enabled = false;
	  }
      }
  }  

  /*
  void ReadModulePCTableFromForkserver(int ReadStatusFromForkserverFD) {
      // First we mmap a space to copy all PCs in forkserver
      size_t Size, CopySize;
      int Ret;
      uint8_t *PC;
      uintptr_t PCStart;
      int NeedRereadPC = 0;

      assert(read(ReadStatusFromForkserverFD, &NumPCTables, sizeof(size_t)) == sizeof(size_t));
      fprintf(stderr, "[PARENT] get NumPCTables: %lu\n", NumPCTables);
      for (size_t i = 0; i < NumPCTables; ++i) {
          // We check if we need to re-read the PC section from forkserver again
	  assert(read(ReadStatusFromForkserverFD, &NeedRereadPC, sizeof(int)) == sizeof(int));
	  if (NeedRereadPC) {
	      assert(read(ReadStatusFromForkserverFD, &Size, sizeof(size_t)) == sizeof(size_t));
	      fprintf(stderr, "[PARENT] get total PC size %lu\n", Size);
	      assert(read(ReadStatusFromForkserverFD, &(PCStart), sizeof(uintptr_t)) == sizeof(uintptr_t));
	      fprintf(stderr, "[PARENT] get total PC start %llx\n", PCStart);
	      PC = (uint8_t*) mmap(0, Size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	      if ((void*)PC == (void*)-1) {
		  fprintf(stderr, "[PARENT] mmap for PC table fail %d\n", errno);
		  exit(255);
	      }

	      // Now copy all PC
	      CopySize = 0;
	      while (CopySize != Size) {
		  Ret = read(ReadStatusFromForkserverFD, (PC+CopySize), Size-CopySize);
		  if (Ret < 0) {
		      fprintf(stderr, "[PARENT] reading PCs from forkserver fail %d\n", errno);
		      exit(255);
		  }
		  CopySize += Ret;
	      }
	
	  }

	  size_t N;
	  assert(read(ReadStatusFromForkserverFD, &N, sizeof(size_t)) == sizeof(size_t));
          fprintf(stderr, "[PARENT] get #PC: %lu\n", N);
          
	  void *TmpPointer = calloc(N, sizeof(struct PCTableEntry));
	  ModulePCTable[i].Start = reinterpret_cast<PCTableEntry *>(TmpPointer);
	  ModulePCTable[i].Stop = ModulePCTable[i].Start + N;

	  for (size_t j = 0; j < N; ++j) {
              assert(read(ReadStatusFromForkserverFD, &(ModulePCTable[i].Start[j].PC), sizeof(uintptr_t)) == sizeof(uintptr_t));
              fprintf(stderr, "[PARENT] get ModulePCTable[%lu].Start[%lu].PC: %lx\n", i, j, ModulePCTable[i].Start[j].PC);
              ModulePCTable[i].Start[j].PC += (reinterpret_cast<uintptr_t>(PC)-PCStart);
              fprintf(stderr, "[PARENT] now ModulePCTable[%lu].Start[%lu].PC: %lx\n", i, j, ModulePCTable[i].Start[j].PC);

              assert(read(ReadStatusFromForkserverFD, &(ModulePCTable[i].Start[j].PCFlags), sizeof(uintptr_t)) == sizeof(uintptr_t));
	  }
      }
      assert(read(ReadStatusFromForkserverFD, &NumPCsInPCTables, sizeof(size_t)) == sizeof(size_t));
  }
  */

  void SetFuzzingNumber(int _FuzzingNumber) {
      FuzzingNumber = _FuzzingNumber;
  }

  int GetFuzzingNumber() {
      return FuzzingNumber;
  }

private:
  bool Initialized = false;
  int FuzzingNumber;
  char *ModuleCountersBackup[4096];
  uint8_t *SharedStart;
  size_t SharedSize;

  bool UseCounters = false;
  uint32_t UseValueProfileMask = false;
  bool DoPrintNewPCs = false;
  size_t NumPrintNewFuncs = 0;

  // Module represents the array of 8-bit counters split into regions
  // such that every region, except maybe the first and the last one, is one
  // full page.
  struct Module {
    struct Region {
      uint8_t *Start, *Stop;
      bool Enabled;
      bool OneFullPage;
    };
    Region *Regions;
    size_t NumRegions;
    uint8_t *SharedStart;
    uint8_t *Start() { return Regions[0].Start; }
    uint8_t *Stop()  { return Regions[NumRegions - 1].Stop; }
    size_t Size()   { return Stop() - Start(); }
    size_t  Idx(uint8_t *P) {
      assert(P >= Start() && P < Stop());
      return P - Start();
    }
  };

  Module Modules[4096];
  size_t NumModules;  // linker-initialized.
  size_t NumInline8bitCounters;

  template <class Callback>
  void IterateCounterRegions(Callback CB) {
    for (size_t m = 0; m < NumModules; m++)
      for (size_t r = 0; r < Modules[m].NumRegions; r++)
        CB(Modules[m].Regions[r]);
  }

  struct { const PCTableEntry *Start, *Stop; } ModulePCTable[4096];
  size_t NumPCTables;
  size_t NumPCsInPCTables;

  Set<const PCTableEntry*> ObservedPCs;
  std::unordered_map<uintptr_t, uintptr_t> ObservedFuncs;  // PC => Counter.

  uint8_t *FocusFunctionCounterPtr = nullptr;

  ValueBitMap ValueProfileMap;
  uintptr_t InitialStack;
};

template <class Callback>
// void Callback(size_t FirstFeature, size_t Idx, uint8_t Value);
ATTRIBUTE_NO_SANITIZE_ALL
size_t ForEachNonZeroByte(const uint8_t *Begin, const uint8_t *End,
                        size_t FirstFeature, Callback Handle8bitCounter) {
  typedef uintptr_t LargeType;
  const size_t Step = sizeof(LargeType) / sizeof(uint8_t);
  const size_t StepMask = Step - 1;
  auto P = Begin;
  // Iterate by 1 byte until either the alignment boundary or the end.
  for (; reinterpret_cast<uintptr_t>(P) & StepMask && P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature, P - Begin, V);

  // Iterate by Step bytes at a time.
  for (; P < End; P += Step)
    if (LargeType Bundle = *reinterpret_cast<const LargeType *>(P))
      for (size_t I = 0; I < Step; I++, Bundle >>= 8)
        if (uint8_t V = Bundle & 0xff)
          Handle8bitCounter(FirstFeature, P - Begin + I, V);

  // Iterate by 1 byte until the end.
  for (; P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature, P - Begin, V);
  return End - Begin;
}

// Given a non-zero Counter returns a number in the range [0,7].
template<class T>
unsigned CounterToFeature(T Counter) {
    // Returns a feature number by placing Counters into buckets as illustrated
    // below.
    //
    // Counter bucket: [1] [2] [3] [4-7] [8-15] [16-31] [32-127] [128+]
    // Feature number:  0   1   2    3     4       5       6       7
    //
    // This is a heuristic taken from AFL (see
    // http://lcamtuf.coredump.cx/afl/technical_details.txt).
    //
    // This implementation may change in the future so clients should
    // not rely on it.
    assert(Counter);
    unsigned Bit = 0;
    /**/ if (Counter >= 128) Bit = 7;
    else if (Counter >= 32) Bit = 6;
    else if (Counter >= 16) Bit = 5;
    else if (Counter >= 8) Bit = 4;
    else if (Counter >= 4) Bit = 3;
    else if (Counter >= 3) Bit = 2;
    else if (Counter >= 2) Bit = 1;
    return Bit;
}

template <class Callback>  // void Callback(size_t Feature)
ATTRIBUTE_NO_SANITIZE_ADDRESS
ATTRIBUTE_NOINLINE
void TracePC::CollectFeatures(Callback HandleFeature) const {
  auto Handle8bitCounter = [&](size_t FirstFeature,
                               size_t Idx, uint8_t Counter) {
    if (UseCounters)
      HandleFeature(FirstFeature + Idx * 8 + CounterToFeature(Counter));
    else
      HandleFeature(FirstFeature + Idx);
  };

  size_t FirstFeature = 0;

  for (size_t i = 0; i < NumModules; i++) {
    for (size_t r = 0; r < Modules[i].NumRegions; r++) {
      if (!Modules[i].Regions[r].Enabled) continue;
      FirstFeature += 8 * ForEachNonZeroByte(Modules[i].Regions[r].Start,
                                             Modules[i].Regions[r].Stop,
                                             FirstFeature, Handle8bitCounter);
    }
  }

  FirstFeature +=
      8 * ForEachNonZeroByte(ExtraCountersBegin(), ExtraCountersEnd(),
                             FirstFeature, Handle8bitCounter);

  if (UseValueProfileMask) {
    ValueProfileMap.ForEach([&](size_t Idx) {
      HandleFeature(FirstFeature + Idx);
    });
    FirstFeature += ValueProfileMap.SizeInBits();
  }

  // Step function, grows similar to 8 * Log_2(A).
  auto StackDepthStepFunction = [](uint32_t A) -> uint32_t {
    if (!A) return A;
    uint32_t Log2 = Log(A);
    if (Log2 < 3) return A;
    Log2 -= 3;
    return (Log2 + 1) * 8 + ((A >> Log2) & 7);
  };
  assert(StackDepthStepFunction(1024) == 64);
  assert(StackDepthStepFunction(1024 * 4) == 80);
  assert(StackDepthStepFunction(1024 * 1024) == 144);

  if (auto MaxStackOffset = GetMaxStackOffset())
    HandleFeature(FirstFeature + StackDepthStepFunction(MaxStackOffset / 8));
}

extern TracePC TPC;

}  // namespace fuzzer

#endif  // LLVM_FUZZER_TRACE_PC
