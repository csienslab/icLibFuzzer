//===- TracePC.h - Internal header for the  ---------*- C++ -* ===//
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

#include "Defs.h"
#include "Dictionary.h"
#include "ValueBitMap.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/mman.h>

extern uint8_t __FUZZ_COUNTERS_START;
extern uint8_t __FUZZ_COUNTERS_END;

size_t SimpleFastHash(const uint8_t *Data, size_t Size);

// TableOfRecentCompares (TORC) remembers the most recently performed
// comparisons of type T.
// We record the arguments of CMP instructions in this table unconditionally
// because it seems cheaper this way than to compute some expensive
// conditions inside __sanitizer_cov_trace_cmp*.
// After the unit has been executed we may decide to use the contents of
// this table to populate a Dictionary.
template<class T, size_t kSizeT>
struct TableOfRecentCompares {
    struct Pair {
        T A, B;
    };

    size_t NeededSize() {
        return kSize * sizeof(Pair) + 1;
    }
    size_t AllocShareMemory(uint8_t *MmapTable) {
        Table = (Pair *) MmapTable;
        return kSize * sizeof(Pair) + 1;
    }

    static const size_t kSize = kSizeT;

    ATTRIBUTE_NO_SANITIZE_ALL
        void Insert(size_t Idx, const T &Arg1, const T &Arg2) {
            Idx = Idx % kSize;
            Table[Idx].A = Arg1;
            Table[Idx].B = Arg2;
        }

    Pair *Table;
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
        const size_t kMaxSingleSize = MemMemWords[0].GetMaxSize() * sizeof(uint8_t) + /*for uint8_t Size*/1;
        for (unsigned int i = 0; i < kSize; ++i) {
            MemMemWords[i].init(/*Pointer=*/MmapTable + kMaxSingleSize * i);
        }
        return kMaxSingleSize * kSize;
    }

    static const size_t kSize = kSizeT;
    Word MemMemWords[kSize];

    void Add(const uint8_t *Data, size_t Size) {
        if (Size <= 2) return;
        Size = std::min(Size, Word::GetMaxSize());
        size_t Idx = SimpleFastHash(Data, Size) % kSize;
        MemMemWords[Idx].Set(Data, Size);
    }
};

class TracePC {
    public:
        void HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop);
        void HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop);
        void HandleCallerCallee(uintptr_t Caller, uintptr_t Callee);
        template <class T> void HandleCmp(uintptr_t PC, T Arg1, T Arg2);

        void AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                size_t n, bool StopAtZero);
        void TraceInline8bitCounters(uintptr_t p);  

        TableOfRecentCompares<uint32_t, 32> TORC4;
        TableOfRecentCompares<uint64_t, 32> TORC8;
        TableOfRecentComparesWord<32> TORCW;
        MemMemTable<1024> MMT;

        uintptr_t GetMaxStackOffset() const;

        struct PCTableEntry {
            uintptr_t PC, PCFlags;
        };

        ATTRIBUTE_NO_SANITIZE_ADDRESS 
            void Initialize() {
                Initialized = true;
                size_t TotalSize = 0;
                size_t CurrentSize = 0;
                // Modules
                MapModulesToSharedMemory();
                for (unsigned int i = 0; i < NumModules; ++i) {
                    /*
                    char FileName[0x100];
                    int Res = snprintf(FileName, 0xff, "/dev/shm/libfuzzer_%d_modules_%d", FuzzingNumber, i);
                    assert(Res > 0);
                    int fd = open(FileName, O_CREAT | O_RDWR, 0600);
                    Res = ftruncate(fd, (uint64_t)Modules[i].Size() + 1);
                    assert(Res == 0 && "change size of Modules' share file");
                    ModuleCountersBackup[i] = (char *) mmap(0, (uint64_t)Modules[i].Size() + 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                    close(fd);
                    memset(ModuleCountersBackup[i], 0, (uint64_t)Modules[i].Size() + 1);
                    fprintf(stderr, "[FORKSERVER] Modules backup size 0x%lx\n", Modules[i].Size());
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

                // split the mmaped space to each data structure
                // for (unsigned int i = 0; i < NumModules; ++i) {
                //     Modules[i].SharedStart = MmapTable + CurrentSize;
                //     CurrentSize += Modules[i].Size();
                // }
                fprintf(stderr, "[FORKSERVER] ValueProfileMap start from %p\n", MmapTable + CurrentSize);
                CurrentSize += ValueProfileMap.AllocShareMemory(MmapTable + CurrentSize);
                fprintf(stderr, "[FORKSERVER] TORC4 start from %p\n", MmapTable + CurrentSize);
                CurrentSize += TORC4.AllocShareMemory(MmapTable + CurrentSize);
                fprintf(stderr, "[FORKSERVER] TORC8 start from %p\n", MmapTable + CurrentSize);
                CurrentSize += TORC8.AllocShareMemory(MmapTable + CurrentSize);
                fprintf(stderr, "[FORKSERVER] TORCW start from %p\n", MmapTable + CurrentSize);
                CurrentSize += TORCW.AllocShareMemory(MmapTable + CurrentSize);
                fprintf(stderr, "[FORKSERVER] MMT start from %p\n", MmapTable + CurrentSize);
                CurrentSize += MMT.AllocShareMemory(MmapTable + CurrentSize);
                fprintf(stderr, "[FORKSERVER] Total size %zi\n", CurrentSize);
                assert(CurrentSize == TotalSize && "TotalSize not equal to needed size, should not happen");

                fprintf(stderr, "[FORKSERVER] NumInline8bitCounters: %lu\n", NumInline8bitCounters);
                fprintf(stderr, "[FORKSERVER] NumPCTables: %lu\n", NumPCTables);
                fprintf(stderr, "[FORKSERVER] NumPCsInPCTables: %lu\n", NumPCsInPCTables);
            }

        ATTRIBUTE_NO_SANITIZE_ADDRESS 
        void MapModulesToSharedMemory() {
            char FileName[0x100];
            int Res = snprintf(FileName, 0xff, "/libfuzzer_%d_modules", FuzzingNumber);
            assert(Res > 0);
            int fd = shm_open(FileName, O_CREAT | O_RDWR, 0666);
            void *SharedModules = (char *) mmap(0, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(SharedModules, &__FUZZ_COUNTERS_START, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);
            munmap(SharedModules, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START);
            SharedModules = (char *) mmap(&__FUZZ_COUNTERS_START, &__FUZZ_COUNTERS_END - &__FUZZ_COUNTERS_START, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
            close(fd);
        }

        void TellParentAboutModules(int WriteStatusToParentFD) {
            assert(write(WriteStatusToParentFD, &NumModules, sizeof(size_t)) == sizeof(size_t));
            fprintf(stderr, "[FORKSERVER] Sending NumModules: %lu\n", NumModules);
            for (size_t i = 0; i < NumModules; ++i) {
                assert(write(WriteStatusToParentFD, &(Modules[i].NumRegions), sizeof(size_t)) == sizeof(size_t));
                fprintf(stderr, "[FORKSERVER] Sending NumRegions: %lu\n", Modules[i].NumRegions);
                for (size_t j = 0; j < Modules[i].NumRegions; ++j) {
                    fprintf(stderr, "[FORKSERVER] Sending Start and Stop %lu\n", j);
                    assert(write(WriteStatusToParentFD, &(Modules[i].Regions[j].Start), sizeof(uint8_t*)) == sizeof(uint8_t*));
                    assert(write(WriteStatusToParentFD, &(Modules[i].Regions[j].Stop), sizeof(uint8_t*)) == sizeof(uint8_t*));
                }
            }
            assert(write(WriteStatusToParentFD, &NumInline8bitCounters, sizeof(size_t)) == sizeof(size_t));
        }

        void TellParentAboutModulePCTable(int WriteStatusToParentFD) {
            // FIXME:
            // We first read memory map from /proc/self/maps to get PCStart and 
            // This only works on linux.
            uintptr_t SectionStart[4096], SectionStop[4096];
            char *Buf = NULL;
            uint8_t *PCStart;
            size_t BufSize = 0;
            int NumSection = 0;
            int Ret;
            FILE *fp = fopen("/proc/self/maps", "r");
            if (!fp) {
                fprintf(stderr, "[FORKSERVER] open /proc/self/maps fail\n");
                exit(255);
            }

            // We get all section with "x" enable, i.e. executable section
            Ret = getline(&Buf, &BufSize, fp);
            while (Ret >= 0) {
                // example of the file format
                // 7f3b6c7f1000-7f3b6c7f4000 r-xp 00000000 08:01 8136718                    /lib/x86_64-linux-gnu/libdl-2.27.s

                // Find first ' '
                char *Pitch = strchr(Buf, ' ');
                if (Pitch) {
                    if (*(Pitch+3) == 'x') {
                        Pitch = strchr(Buf, '-');
                        assert(Pitch);
                        ++Pitch;

                        SectionStart[NumSection] = strtoull(Buf, NULL, 16);
                        SectionStop[NumSection] = strtoull(Pitch, NULL, 16);
                        ++NumSection;
                    }
                }

                Ret = getline(&Buf, &BufSize, fp);
            }
            fclose(fp);

            // Sanity check
            if (!NumSection) {
                fprintf(stderr, "[FORKSERVER] cannot find any executable sections\n");
                exit(255);
            }


            int PreviousSection = -1;
            fprintf(stderr, "[FORKSERVER] sending NumPCTables %lu\n", NumPCTables);
            assert(write(WriteStatusToParentFD, &NumPCTables, sizeof(size_t)) == sizeof(size_t));
            for (size_t i = 0; i < NumPCTables; ++i) {
                // We first check if we need to send PC section again
                // To do this, we first check which section we are sending
                uintptr_t ComparedPC = ModulePCTable[i].Start[0].PC;
                int TargetSection = -1;
                for (int j = 0; j < NumSection; ++j) {
                    if (SectionStart[j] <= ComparedPC && ComparedPC <= SectionStop[j]) {
                        TargetSection = j;
                        break;
                    }
                }
                if (TargetSection == -1) {
                    fprintf(stderr, "[FORKSERVER] cannot find executable section containing this PC %lu\n", ComparedPC);
                    exit(255);
                }

                // Sanity check. All other PC in this table should fall into this section
                size_t N = ModulePCTable[i].Stop - ModulePCTable[i].Start;
                for (size_t j = 0; j < N; ++j) {
                    assert(SectionStart[TargetSection] <= ModulePCTable[i].Start[j].PC &&
                            ModulePCTable[i].Start[j].PC <= SectionStop[TargetSection]);
                }

                if (TargetSection != PreviousSection) {
                    int dummy = 1;
                    size_t Size = SectionStop[TargetSection] - SectionStart[TargetSection];
                    assert(write(WriteStatusToParentFD, &dummy, sizeof(int)) == sizeof(int));
                    assert(write(WriteStatusToParentFD, &Size, sizeof(size_t)) == sizeof(size_t));
                    assert(write(WriteStatusToParentFD, &(SectionStart[TargetSection]), sizeof(uintptr_t)) == sizeof(uintptr_t));
                    assert(write(WriteStatusToParentFD, (uint8_t*)SectionStart[TargetSection], Size) == Size);

                }
                PreviousSection = TargetSection;

                fprintf(stderr, "[FORKSERVER] sending N %lu\n", N);
                assert(write(WriteStatusToParentFD, &N, sizeof(size_t)) == sizeof(size_t));
                for (size_t j = 0; j < N; ++j) {
                    // fprintf(stderr, "[FORKSERVER] sending ModulePCTable[%lu].Start[%lu].PC %lx\n", i, j, ModulePCTable[i].Start[j].PC);
                    assert(write(WriteStatusToParentFD, &(ModulePCTable[i].Start[j].PC), sizeof(uintptr_t)) == sizeof(uintptr_t));
                    // fprintf(stderr, "[FORKSERVER] sending ModulePCTable[%lu].Start[%lu].PCFlags %lx\n", i, j, ModulePCTable[i].Start[j].PCFlags);
                    assert(write(WriteStatusToParentFD, &(ModulePCTable[i].Start[j].PCFlags), sizeof(uintptr_t)) == sizeof(uintptr_t));

                }
            }
            assert(write(WriteStatusToParentFD, &NumPCsInPCTables, sizeof(size_t)) == sizeof(size_t));
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

        unsigned int Checksum() {
            unsigned int ret = 0;
            for (unsigned int i = 0; i < NumModules; ++i) {
                for (uint8_t *ptr = Modules[i].Start(); ptr != Modules[i].Stop(); ++ptr) {
                    ret += (*ptr);
                }
            }
            return ret;
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
                if (size != ModulePCTable[i].Stop->PC - ModulePCTable[i].Start->PC) {
                    fprintf(stderr, "[FORKSERVER] get %lu, should be %lu\n", size, ModulePCTable[i].Stop->PC - ModulePCTable[i].Start->PC);
                }
            }
        }

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

        struct { const PCTableEntry *Start, *Stop; } ModulePCTable[4096];
        size_t NumPCTables;
        size_t NumPCsInPCTables;

        ValueBitMap ValueProfileMap;
};


extern TracePC TPC;


#endif  // LLVM_FUZZER_TRACE_PC
