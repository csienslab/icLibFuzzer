//===- FuzzerLoop.cpp - Fuzzer's main loop --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Fuzzer's main loop.
//===----------------------------------------------------------------------===//

#include "FuzzerCorpus.h"
#include "FuzzerIO.h"
#include "FuzzerInternal.h"
#include "FuzzerMutate.h"
#include "FuzzerPlatform.h"
#include "FuzzerRandom.h"
#include "FuzzerTracePC.h"
#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
std::set<size_t> hashSet;
extern char **__libfuzzer_argv;
extern int __libfuzzer_argc;
extern int FORKSERVER_FD;


#if defined(__has_include)
#if __has_include(<sanitizer / lsan_interface.h>)
#include <sanitizer/lsan_interface.h>
#endif
#endif

#define NO_SANITIZE_MEMORY
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#undef NO_SANITIZE_MEMORY
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize_memory))
#endif
#endif

namespace fuzzer {
static void CustomInterruptCallback(int _, siginfo_t *__, void *___) {
    Fuzzer::StaticInterruptCallback();
}

static const size_t kMaxUnitSizeToPrint = 256;

thread_local bool Fuzzer::IsMyThread;

bool RunningUserCallback = false;

// Only one Fuzzer per process.
static Fuzzer *F;

// Leak detection is expensive, so we first check if there were more mallocs
// than frees (using the sanitizer malloc hooks) and only then try to call lsan.
struct MallocFreeTracer {
  void Start(int TraceLevel) {
    this->TraceLevel = TraceLevel;
    if (TraceLevel)
      Printf("MallocFreeTracer: START\n");
    Mallocs = 0;
    Frees = 0;
  }
  // Returns true if there were more mallocs than frees.
  bool Stop() {
    if (TraceLevel)
      Printf("MallocFreeTracer: STOP %zd %zd (%s)\n", Mallocs.load(),
             Frees.load(), Mallocs == Frees ? "same" : "DIFFERENT");
    bool Result = Mallocs > Frees;
    Mallocs = 0;
    Frees = 0;
    TraceLevel = 0;
    return Result;
  }
  std::atomic<size_t> Mallocs;
  std::atomic<size_t> Frees;
  int TraceLevel = 0;

  std::recursive_mutex TraceMutex;
  bool TraceDisabled = false;
};

static MallocFreeTracer AllocTracer;

// Locks printing and avoids nested hooks triggered from mallocs/frees in
// sanitizer.
class TraceLock {
public:
  TraceLock() : Lock(AllocTracer.TraceMutex) {
    AllocTracer.TraceDisabled = !AllocTracer.TraceDisabled;
  }
  ~TraceLock() { AllocTracer.TraceDisabled = !AllocTracer.TraceDisabled; }

  bool IsDisabled() const {
    // This is already inverted value.
    return !AllocTracer.TraceDisabled;
  }

private:
  std::lock_guard<std::recursive_mutex> Lock;
};

ATTRIBUTE_NO_SANITIZE_MEMORY
void MallocHook(const volatile void *ptr, size_t size) {
  size_t N = AllocTracer.Mallocs++;
  F->HandleMalloc(size);
  if (int TraceLevel = AllocTracer.TraceLevel) {
    TraceLock Lock;
    if (Lock.IsDisabled())
      return;
    Printf("MALLOC[%zd] %p %zd\n", N, ptr, size);
    if (TraceLevel >= 2 && EF)
      PrintStackTrace();
  }
}

ATTRIBUTE_NO_SANITIZE_MEMORY
void FreeHook(const volatile void *ptr) {
  size_t N = AllocTracer.Frees++;
  if (int TraceLevel = AllocTracer.TraceLevel) {
    TraceLock Lock;
    if (Lock.IsDisabled())
      return;
    Printf("FREE[%zd]   %p\n", N, ptr);
    if (TraceLevel >= 2 && EF)
      PrintStackTrace();
  }
}

// Crash on a single malloc that exceeds the rss limit.
void Fuzzer::HandleMalloc(size_t Size) {
  if (!Options.MallocLimitMb || (Size >> 20) < (size_t)Options.MallocLimitMb)
    return;
  Printf("==%d== ERROR: libFuzzer: out-of-memory (malloc(%zd))\n", GetPid(),
         Size);
  Printf("   To change the out-of-memory limit use -rss_limit_mb=<N>\n\n");
  PrintStackTrace();
  DumpCurrentUnit("oom-");
  Printf("SUMMARY: libFuzzer: out-of-memory\n");
  PrintFinalStats();
  _Exit(Options.OOMExitCode); // Stop right now.
}

void Fuzzer::InstallInterruptCallback(int signum) {
    struct sigaction sigact = {};
    sigact.sa_flags = SA_SIGINFO;
    sigact.sa_sigaction = CustomInterruptCallback;
    if (sigaction(signum, &sigact, 0)) {
      Printf("libFuzzer: sigaction failed with %d\n", errno);
      exit(1);
    }
}

Fuzzer::Fuzzer(UserCallback CB, InputCorpus &Corpus, MutationDispatcher &MD,
               FuzzingOptions Options)
    : CB(CB), Corpus(Corpus), MD(MD), Options(Options) {
  if (EF->__sanitizer_set_death_callback)
    EF->__sanitizer_set_death_callback(StaticDeathCallback);
  assert(!F);
  F = this;

  // Check if target binary use input from file
  for (int i = 0; i < __libfuzzer_argc; ++i) {
    if (!strncmp(__libfuzzer_argv[i], "@@", 2)) {
      UseFile = true;     
      snprintf(FuzzingFileName, 0xff, "/dev/shm/libfuzzer_core_%d", Options.FuzzingNumber);
      __libfuzzer_argv[i] = FuzzingFileName;
      break;
    }
  }
  // Check if target binary read input from file
  if (!UseFile && Options.FileNameLength) {
    UseFile = true;
    assert(snprintf(FuzzingFileName, 0xff, "%s", Options.FileName) == Options.FileNameLength);
  }
  TPC.SetFuzzingNumber(Options.FuzzingNumber);
  fprintf(stderr, "[INFO] using cpu core #%d\n", Options.FuzzingNumber);
  IsMyThread = true;
  if (Options.DetectLeaks && EF->__sanitizer_install_malloc_and_free_hooks)
    EF->__sanitizer_install_malloc_and_free_hooks(MallocHook, FreeHook);
  TPC.SetUseCounters(Options.UseCounters);
  TPC.SetUseValueProfileMask(Options.UseValueProfile);

  if (Options.Verbosity)
    TPC.PrintModuleInfo();
  if (!Options.OutputCorpus.empty() && Options.ReloadIntervalSec)
    EpochOfLastReadOfOutputCorpus = GetEpoch(Options.OutputCorpus);
  MaxInputLen = MaxMutationLen = Options.MaxLen;
  TmpMaxMutationLen = 0;  // Will be set once we load the corpus.
  AllocateCurrentUnitData();
  CurrentUnitSize = 0;
  memset(BaseSha1, 0, sizeof(BaseSha1));
}

Fuzzer::~Fuzzer() {}

void Fuzzer::AllocateCurrentUnitData() {
  if (CurrentUnitData || MaxInputLen == 0)
    return;
  CurrentUnitData = new uint8_t[MaxInputLen];
}

void Fuzzer::StaticDeathCallback() {
  assert(F);
  F->DeathCallback();
}

void Fuzzer::DumpCurrentUnit(const char *Prefix) {
  if (!CurrentUnitData)
    return; // Happens when running individual inputs.
  char Buf[0x1000];
  sprintf(Buf, "%02d-%d", TPC.GetFuzzingNumber(), duration_cast<seconds>(system_clock::now() - StartFuzzingTime).count());
  strcat(Buf, Prefix);
  ScopedDisableMsanInterceptorChecks S;
  MD.PrintMutationSequence();
  Printf("; base unit: %s\n", Sha1ToString(BaseSha1).c_str());
  size_t UnitSize = CurrentUnitSize;
  if (UnitSize <= kMaxUnitSizeToPrint) {
    PrintHexArray(CurrentUnitData, UnitSize, "\n");
    PrintASCII(CurrentUnitData, UnitSize, "\n");
  }
  WriteUnitToFileWithPrefix({CurrentUnitData, CurrentUnitData + UnitSize},
                            Buf);
}

NO_SANITIZE_MEMORY
void Fuzzer::DeathCallback() {
  DumpCurrentUnit("crash-");
  PrintFinalStats();
}

void Fuzzer::StaticAlarmCallback() {
  assert(F);
  F->AlarmCallback();
}

void Fuzzer::StaticCrashSignalCallback() {
  assert(F);
  F->CrashCallback();
}

void Fuzzer::StaticExitCallback() {
  assert(F);
  F->ExitCallback();
}

void Fuzzer::StaticInterruptCallback() {
  assert(F);
  F->InterruptCallback();
}

void Fuzzer::StaticGracefulExitCallback() {
  assert(F);
  F->GracefulExitRequested = true;
  Printf("INFO: signal received, trying to exit gracefully\n");
}

void Fuzzer::StaticFileSizeExceedCallback() {
  Printf("==%lu== ERROR: libFuzzer: file size exceeded\n", GetPid());
  exit(1);
}

void Fuzzer::CrashCallback() {
  Printf("==%lu== ERROR: libFuzzer: deadly signal\n", GetPid());
  PrintStackTrace();
  Printf("NOTE: libFuzzer has rudimentary signal handlers.\n"
         "      Combine libFuzzer with AddressSanitizer or similar for better "
         "crash reports.\n");
  Printf("SUMMARY: libFuzzer: deadly signal\n");
  DumpCurrentUnit("crash-");
  PrintFinalStats();
  fprintf(stderr, "[total run] %d\n", TotalNumberOfRuns);
}

void Fuzzer::ExitCallback() {
  kill(ForkServerPid, SIGKILL);
  _Exit(255);
}

void Fuzzer::MaybeExitGracefully() {
  if (!F->GracefulExitRequested) return;
  Printf("==%lu== INFO: libFuzzer: exiting as requested\n", GetPid());
  RmDirRecursive(TempPath("FuzzWithFork", ".dir"));
  F->PrintFinalStats();
  _Exit(0);
}

void Fuzzer::InterruptCallback() {
  PrintStackTrace();
  Printf("==%lu== libFuzzer: run interrupted; exiting\n", GetPid());
  PrintFinalStats();
  fprintf(stderr, "[total run] %d\n", TotalNumberOfRuns);
  RmDirRecursive(TempPath("FuzzWithFork", ".dir"));
  // Stop right now, don't perform any at-exit actions.
  kill(ForkServerPid, SIGKILL);
  _Exit(Options.InterruptExitCode);
}

NO_SANITIZE_MEMORY
void Fuzzer::AlarmCallback() {
  return;
}

void Fuzzer::RssLimitCallback() {
  if (EF->__sanitizer_acquire_crash_state &&
      !EF->__sanitizer_acquire_crash_state())
    return;
  Printf(
      "==%lu== ERROR: libFuzzer: out-of-memory (used: %zdMb; limit: %zdMb)\n",
      GetPid(), GetPeakRSSMb(), Options.RssLimitMb);
  Printf("   To change the out-of-memory limit use -rss_limit_mb=<N>\n\n");
  PrintMemoryProfile();
  DumpCurrentUnit("oom-");
  Printf("SUMMARY: libFuzzer: out-of-memory\n");
  PrintFinalStats();
  kill(ForkServerPid, SIGKILL);
  _Exit(Options.OOMExitCode); // Stop right now.
}

void Fuzzer::PrintStats(const char *Where, const char *End, size_t Units,
                        size_t Features) {
  size_t ExecPerSec = execPerSec();
  if (!Options.Verbosity)
    return;
  Printf("#%zd\t%s", TotalNumberOfRuns, Where);
  if (size_t N = TPC.GetTotalPCCoverage())
    Printf(" cov: %zd", N);
  if (size_t N = Features ? Features : Corpus.NumFeatures())
    Printf(" ft: %zd", N);
  if (!Corpus.empty()) {
    Printf(" corp: %zd", Corpus.NumActiveUnits());
    if (size_t N = Corpus.SizeInBytes()) {
      if (N < (1 << 14))
        Printf("/%zdb", N);
      else if (N < (1 << 24))
        Printf("/%zdKb", N >> 10);
      else
        Printf("/%zdMb", N >> 20);
    }
    if (size_t FF = Corpus.NumInputsThatTouchFocusFunction())
      Printf(" focus: %zd", FF);
  }
  if (TmpMaxMutationLen)
    Printf(" lim: %zd", TmpMaxMutationLen);
  if (Units)
    Printf(" units: %zd", Units);

  Printf(" exec/s: %zd", ExecPerSec);
  Printf(" rss: %zdMb", GetPeakRSSMb());
  Printf("%s", End);
}

void Fuzzer::PrintFinalStats() {
  if (Options.PrintCoverage)
    TPC.PrintCoverage();
  if (Options.PrintCorpusStats)
    Corpus.PrintStats();
  if (!Options.PrintFinalStats)
    return;
  size_t ExecPerSec = execPerSec();
  Printf("stat::number_of_executed_units: %zd\n", TotalNumberOfRuns);
  Printf("stat::average_exec_per_sec:     %zd\n", ExecPerSec);
  Printf("stat::new_units_added:          %zd\n", NumberOfNewUnitsAdded);
  Printf("stat::slowest_unit_time_sec:    %zd\n", TimeOfLongestUnitInSeconds);
  Printf("stat::peak_rss_mb:              %zd\n", GetPeakRSSMb());
}

void Fuzzer::SetMaxInputLen(size_t MaxInputLen) {
  assert(this->MaxInputLen == 0); // Can only reset MaxInputLen from 0 to non-0.
  assert(MaxInputLen);
  this->MaxInputLen = MaxInputLen;
  this->MaxMutationLen = MaxInputLen;
  AllocateCurrentUnitData();
  Printf("INFO: -max_len is not provided; "
         "libFuzzer will not generate inputs larger than %zd bytes\n",
         MaxInputLen);
}

void Fuzzer::SetMaxMutationLen(size_t MaxMutationLen) {
  assert(MaxMutationLen && MaxMutationLen <= MaxInputLen);
  this->MaxMutationLen = MaxMutationLen;
}

void Fuzzer::CheckExitOnSrcPosOrItem() {
  if (!Options.ExitOnSrcPos.empty()) {
    static auto *PCsSet = new Set<uintptr_t>;
    auto HandlePC = [&](const TracePC::PCTableEntry *TE) {
      if (!PCsSet->insert(TE->PC).second)
        return;
      std::string Descr = DescribePC("%F %L", TE->PC + 1);
      if (Descr.find(Options.ExitOnSrcPos) != std::string::npos) {
        Printf("INFO: found line matching '%s', exiting.\n",
               Options.ExitOnSrcPos.c_str());
        _Exit(0);
      }
    };
    TPC.ForEachObservedPC(HandlePC);
  }
  if (!Options.ExitOnItem.empty()) {
    if (Corpus.HasUnit(Options.ExitOnItem)) {
      Printf("INFO: found item with checksum '%s', exiting.\n",
             Options.ExitOnItem.c_str());
      _Exit(0);
    }
  }
}

void Fuzzer::RereadOutputCorpus(size_t MaxSize) {
  if (Options.OutputCorpus.empty() || !Options.ReloadIntervalSec)
    return;
  Vector<Unit> AdditionalCorpus;
  ReadDirToVectorOfUnits(Options.OutputCorpus.c_str(), &AdditionalCorpus,
                         &EpochOfLastReadOfOutputCorpus, MaxSize,
                         /*ExitOnError*/ false);
  if (Options.Verbosity >= 2)
    Printf("Reload: read %zd new units.\n", AdditionalCorpus.size());
  bool Reloaded = false;
  for (auto &U : AdditionalCorpus) {
    if (U.size() > MaxSize)
      U.resize(MaxSize);
    if (!Corpus.HasUnit(U)) {
      if (RunOne(U.data(), U.size())) {
        CheckExitOnSrcPosOrItem();
        Reloaded = true;
      }
    }
  }
  if (Reloaded)
    PrintStats("RELOAD");
}

void Fuzzer::PrintPulseAndReportSlowInput(const uint8_t *Data, size_t Size) {
  auto TimeOfUnit =
      duration_cast<seconds>(UnitStopTime - UnitStartTime).count();
  if (!(TotalNumberOfRuns & (TotalNumberOfRuns - 1)) &&
      secondsSinceProcessStartUp() >= 2)
    PrintStats("pulse ");
  if (TimeOfUnit > TimeOfLongestUnitInSeconds * 1.1 &&
      TimeOfUnit >= Options.ReportSlowUnits) {
    TimeOfLongestUnitInSeconds = TimeOfUnit;
    Printf("Slowest unit: %zd s:\n", TimeOfLongestUnitInSeconds);
    WriteUnitToFileWithPrefix({Data, Data + Size}, "slow-unit-");
  }
}

static void WriteFeatureSetToFile(const std::string &FeaturesDir,
                                  const std::string &FileName,
                                  const Vector<uint32_t> &FeatureSet) {
  if (FeaturesDir.empty() || FeatureSet.empty()) return;
  WriteToFile(reinterpret_cast<const uint8_t *>(FeatureSet.data()),
              FeatureSet.size() * sizeof(FeatureSet[0]),
              DirPlusFile(FeaturesDir, FileName));
}

static void RenameFeatureSetFile(const std::string &FeaturesDir,
                                 const std::string &OldFile,
                                 const std::string &NewFile) {
  if (FeaturesDir.empty()) return;
  RenameFile(DirPlusFile(FeaturesDir, OldFile),
             DirPlusFile(FeaturesDir, NewFile));
}

bool Fuzzer::RunOne(const uint8_t *Data, size_t Size, bool MayDeleteFile,
                    InputInfo *II, bool *FoundUniqFeatures) {
  if (!Size)
    return false;

  ExecuteCallback(Data, Size);

  UniqFeatureSetTmp.clear();
  size_t FoundUniqFeaturesOfII = 0;
  size_t NumUpdatesBefore = Corpus.NumFeatureUpdates();
  TPC.CollectFeatures([&](size_t Feature) {
    if (Corpus.AddFeature(Feature, Size, Options.Shrink))
      UniqFeatureSetTmp.push_back(Feature);
    if (Options.Entropic)
      Corpus.UpdateFeatureFrequency(II, Feature);
    if (Options.ReduceInputs && II)
      if (std::binary_search(II->UniqFeatureSet.begin(),
                             II->UniqFeatureSet.end(), Feature))
        FoundUniqFeaturesOfII++;
  });
  if (FoundUniqFeatures)
    *FoundUniqFeatures = FoundUniqFeaturesOfII;
  PrintPulseAndReportSlowInput(Data, Size);
  size_t NumNewFeatures = Corpus.NumFeatureUpdates() - NumUpdatesBefore;
  if (NumNewFeatures) {
    TPC.UpdateObservedPCs();
    auto NewII = Corpus.AddToCorpus({Data, Data + Size}, NumNewFeatures,
                                    MayDeleteFile, TPC.ObservedFocusFunction(),
                                    UniqFeatureSetTmp, DFT, II);
    WriteFeatureSetToFile(Options.FeaturesDir, Sha1ToString(NewII->Sha1),
                          NewII->UniqFeatureSet);
    return true;
  }
  if (II && FoundUniqFeaturesOfII &&
      II->DataFlowTraceForFocusFunction.empty() &&
      FoundUniqFeaturesOfII == II->UniqFeatureSet.size() &&
      II->U.size() > Size) {
    auto OldFeaturesFile = Sha1ToString(II->Sha1);
    Corpus.Replace(II, {Data, Data + Size});
    RenameFeatureSetFile(Options.FeaturesDir, OldFeaturesFile,
                         Sha1ToString(II->Sha1));
    return true;
  }
  return false;
}

size_t Fuzzer::GetCurrentUnitInFuzzingThead(const uint8_t **Data) const {
  assert(InFuzzingThread());
  *Data = CurrentUnitData;
  return CurrentUnitSize;
}

void Fuzzer::CrashOnOverwrittenData() {
  Printf("==%d== ERROR: libFuzzer: fuzz target overwrites its const input\n",
         GetPid());
  PrintStackTrace();
  Printf("SUMMARY: libFuzzer: overwrites-const-input\n");
  DumpCurrentUnit("crash-");
  PrintFinalStats();
  _Exit(Options.ErrorExitCode); // Stop right now.
}

// Compare two arrays, but not all bytes if the arrays are large.
static bool LooseMemeq(const uint8_t *A, const uint8_t *B, size_t Size) {
  const size_t Limit = 64;
  if (Size <= 64)
    return !memcmp(A, B, Size);
  // Compare first and last Limit/2 bytes.
  return !memcmp(A, B, Limit / 2) &&
         !memcmp(A + Size - Limit / 2, B + Size - Limit / 2, Limit / 2);
}

void Fuzzer::ExecuteCallback(const uint8_t *Data, size_t Size) {
  // TPC.RecordInitialStack();
  TotalNumberOfRuns++;
  assert(InFuzzingThread());
  uint8_t ExitState;
  size_t hash;
  Timeout = false;
  if (CurrentUnitData && CurrentUnitData != Data)
    memcpy(CurrentUnitData, Data, Size);
  CurrentUnitSize = Size;
  {
    UnitStartTime = system_clock::now();
    TPC.ResetMaps();
    RunningUserCallback = true;
    if (UseFile) {
        unlink(FuzzingFileName);
        int FD = open(FuzzingFileName, O_WRONLY | O_CREAT, 0600);
        assert(write(FD, Data, Size) == (int)Size);
        close(FD);
    } 
    else {
        lseek(FuzzingStdioFileFD, 0, SEEK_SET);
        assert(write(FuzzingStdioFileFD, Data, Size) == (int)Size);
        if (ftruncate(FuzzingStdioFileFD, Size)) {
            fprintf(stderr, "[PARENT ERROR] ftruncate....\n");
            exit(255);
        }
        lseek(FuzzingStdioFileFD, 0, SEEK_SET);
    }
    int ret;
    ret = write(WriteStartToForkServerFD, "a", 1);
    if (ret != 1) {
        fprintf(stderr, "[ERROR] writing to forkserver error, %d, %d\n", ret, errno);
    }
    int TotalLen = 0;
    while (TotalLen < 1) {
        ret = read(ReadStatusFromForkServerFD, (char *)(&ExitState) + TotalLen, 1 - TotalLen);
        TotalLen += ret;
    }
    if (TotalLen != 1) {
        fprintf(stderr, "[PARENT] reading from Forkserver error, %d, %d\n", ret, errno);
        _Exit(10);
    }
    
    // read crash hash value
    // -1: normal
    // other: crashed
    TotalLen = 0;
    while (TotalLen < (int)sizeof(size_t)) {
        ret = read(ReadStatusFromForkServerFD, (char *)(&hash) + TotalLen, sizeof(size_t) - TotalLen);
        TotalLen += ret;
    }
    if (TotalLen != sizeof(size_t)) {
        fprintf(stderr, "[PARENT] reading from Forkserver error, %d, %d\n", ret, errno);
        _Exit(10);
    }

    switch(ExitState) {
        case 0:
            break;
    	case SIGALRM:
            Timeout = true;
            break;
    	case SIGSEGV:
    	case SIGABRT:
    	case SIGINT:
    	case SIGTERM:
    	case SIGBUS:
    	case SIGILL:
    	case SIGFPE:
            if (hash != (size_t)-1 && hashSet.find(hash) == hashSet.end()) {
                hashSet.insert(hash);
                CrashCallback();
            }
            break;
        case 254:
            fprintf(stderr, "[PARENT INFO] interrupted...\n");
            _Exit(20);
        default:
            break;
    }
    TPC.CopyFileToModuleCounters();
    RunningUserCallback = false;
    UnitStopTime = system_clock::now();
  }
  CurrentUnitSize = 0;
}

std::string Fuzzer::WriteToOutputCorpus(const Unit &U) {
  if (Options.OnlyASCII)
    assert(IsASCII(U));
  if (Options.OutputCorpus.empty())
    return "";
  std::string Path = DirPlusFile(Options.OutputCorpus, Hash(U));
  WriteToFile(U, Path);
  if (Options.Verbosity >= 2)
    Printf("Written %zd bytes to %s\n", U.size(), Path.c_str());
  return Path;
}

void Fuzzer::WriteUnitToFileWithPrefix(const Unit &U, const char *Prefix) {
  if (!Options.SaveArtifacts)
    return;
  std::string Path = Options.ArtifactPrefix + Prefix + Hash(U);
  if (!Options.ExactArtifactPath.empty())
    Path = Options.ExactArtifactPath; // Overrides ArtifactPrefix.
  WriteToFile(U, Path);
  Printf("artifact_prefix='%s'; Test unit written to %s\n",
         Options.ArtifactPrefix.c_str(), Path.c_str());
  if (U.size() <= kMaxUnitSizeToPrint)
    Printf("Base64: %s\n", Base64(U).c_str());
}

void Fuzzer::PrintStatusForNewUnit(const Unit &U, const char *Text) {
  if (!Options.PrintNEW)
    return;
  PrintStats(Text, "");
  if (Options.Verbosity) {
    Printf(" L: %zd/%zd ", U.size(), Corpus.MaxInputSize());
    MD.PrintMutationSequence();
    Printf("\n");
  }
}

void Fuzzer::ReportNewCoverage(InputInfo *II, const Unit &U) {
  II->NumSuccessfullMutations++;
  MD.RecordSuccessfulMutationSequence();
  PrintStatusForNewUnit(U, II->Reduced ? "REDUCE" : "NEW   ");
  WriteToOutputCorpus(U);
  NumberOfNewUnitsAdded++;
  CheckExitOnSrcPosOrItem(); // Check only after the unit is saved to corpus.
  LastCorpusUpdateRun = TotalNumberOfRuns;
}

// Tries detecting a memory leak on the particular input that we have just
// executed before calling this function.
void Fuzzer::TryDetectingAMemoryLeak(const uint8_t *Data, size_t Size,
                                     bool DuringInitialCorpusExecution) {
  if (!HasMoreMallocsThanFrees)
    return; // mallocs==frees, a leak is unlikely.
  if (!Options.DetectLeaks)
    return;
  if (!DuringInitialCorpusExecution &&
      TotalNumberOfRuns >= Options.MaxNumberOfRuns)
    return;
  if (!&(EF->__lsan_enable) || !&(EF->__lsan_disable) ||
      !(EF->__lsan_do_recoverable_leak_check))
    return; // No lsan.
  // Run the target once again, but with lsan disabled so that if there is
  // a real leak we do not report it twice.
  EF->__lsan_disable();
  ExecuteCallback(Data, Size);
  EF->__lsan_enable();
  if (!HasMoreMallocsThanFrees)
    return; // a leak is unlikely.
  if (NumberOfLeakDetectionAttempts++ > 1000) {
    Options.DetectLeaks = false;
    Printf("INFO: libFuzzer disabled leak detection after every mutation.\n"
           "      Most likely the target function accumulates allocated\n"
           "      memory in a global state w/o actually leaking it.\n"
           "      You may try running this binary with -trace_malloc=[12]"
           "      to get a trace of mallocs and frees.\n"
           "      If LeakSanitizer is enabled in this process it will still\n"
           "      run on the process shutdown.\n");
    return;
  }
  // Now perform the actual lsan pass. This is expensive and we must ensure
  // we don't call it too often.
  if (EF->__lsan_do_recoverable_leak_check()) { // Leak is found, report it.
    if (DuringInitialCorpusExecution)
      Printf("\nINFO: a leak has been found in the initial corpus.\n\n");
    Printf("INFO: to ignore leaks on libFuzzer side use -detect_leaks=0.\n\n");
    CurrentUnitSize = Size;
    DumpCurrentUnit("leak-");
    PrintFinalStats();
    _Exit(Options.ErrorExitCode); // not exit() to disable lsan further on.
  }
}

void Fuzzer::MutateAndTestOne() {
  MD.StartMutationSequence();

  auto &II = Corpus.ChooseUnitToMutate(MD.GetRand());
  if (Options.DoCrossOver)
    MD.SetCrossOverWith(&Corpus.ChooseUnitToMutate(MD.GetRand()).U);
  const auto &U = II.U;
  memcpy(BaseSha1, II.Sha1, sizeof(BaseSha1));
  assert(CurrentUnitData);
  size_t Size = U.size();
  assert(Size <= MaxInputLen && "Oversized Unit");
  memcpy(CurrentUnitData, U.data(), Size);

  assert(MaxMutationLen > 0);

  size_t CurrentMaxMutationLen =
      Min(MaxMutationLen, Max(U.size(), TmpMaxMutationLen));
  assert(CurrentMaxMutationLen > 0);

  for (int i = 0; i < Options.MutateDepth; i++) {
    if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
      break;
    MaybeExitGracefully();
    size_t NewSize = 0;
    if (II.HasFocusFunction && !II.DataFlowTraceForFocusFunction.empty() &&
        Size <= CurrentMaxMutationLen)
      NewSize = MD.MutateWithMask(CurrentUnitData, Size, Size,
                                  II.DataFlowTraceForFocusFunction);

    // If MutateWithMask either failed or wasn't called, call default Mutate.
    if (!NewSize)
      NewSize = MD.Mutate(CurrentUnitData, Size, CurrentMaxMutationLen);
    assert(NewSize > 0 && "Mutator returned empty unit");
    assert(NewSize <= CurrentMaxMutationLen && "Mutator return oversized unit");
    Size = NewSize;
    II.NumExecutedMutations++;
    Corpus.IncrementNumExecutedMutations();

    bool FoundUniqFeatures = false;
    bool NewCov = RunOne(CurrentUnitData, Size, /*MayDeleteFile=*/true, &II,
                         &FoundUniqFeatures);
    TryDetectingAMemoryLeak(CurrentUnitData, Size,
                            /*DuringInitialCorpusExecution*/ false);
    if (NewCov) {
      ReportNewCoverage(&II, {CurrentUnitData, CurrentUnitData + Size});
      break;  // We will mutate this input more in the next rounds.
    }
    // if (Timeout) DumpCurrentUnit("timeout-");
    if (Options.ReduceDepth && !FoundUniqFeatures)
      break;
  }

  II.NeedsEnergyUpdate = true;
}

void Fuzzer::PurgeAllocator() {
  if (Options.PurgeAllocatorIntervalSec < 0 || !EF->__sanitizer_purge_allocator)
    return;
  if (duration_cast<seconds>(system_clock::now() -
                             LastAllocatorPurgeAttemptTime)
          .count() < Options.PurgeAllocatorIntervalSec)
    return;

  if (Options.RssLimitMb <= 0 ||
      GetPeakRSSMb() > static_cast<size_t>(Options.RssLimitMb) / 2)
    EF->__sanitizer_purge_allocator();

  LastAllocatorPurgeAttemptTime = system_clock::now();
}

void Fuzzer::ReadAndExecuteSeedCorpora(Vector<SizedFile> &CorporaFiles) {
  const size_t kMaxSaneLen = 1 << 20;
  const size_t kMinDefaultLen = 4096;
  size_t MaxSize = 0;
  size_t MinSize = -1;
  size_t TotalSize = 0;
  for (auto &File : CorporaFiles) {
    MaxSize = Max(File.Size, MaxSize);
    MinSize = Min(File.Size, MinSize);
    TotalSize += File.Size;
  }
  if (Options.MaxLen == 0)
    SetMaxInputLen(std::min(std::max(kMinDefaultLen, MaxSize), kMaxSaneLen));
  assert(MaxInputLen > 0);

  // Test the callback with empty input and never try it again.
  uint8_t dummy = 0;
  ExecuteCallback(&dummy, 0);

  if (CorporaFiles.empty()) {
    Printf("INFO: A corpus is not provided, starting from an empty corpus\n");
    Unit U({'\n'}); // Valid ASCII input.
    RunOne(U.data(), U.size());
  } else {
    Printf("INFO: seed corpus: files: %zd min: %zdb max: %zdb total: %zdb"
           " rss: %zdMb\n",
           CorporaFiles.size(), MinSize, MaxSize, TotalSize, GetPeakRSSMb());
    if (Options.ShuffleAtStartUp)
      std::shuffle(CorporaFiles.begin(), CorporaFiles.end(), MD.GetRand());

    if (Options.PreferSmall) {
      std::stable_sort(CorporaFiles.begin(), CorporaFiles.end());
      assert(CorporaFiles.front().Size <= CorporaFiles.back().Size);
    }

    // Load and execute inputs one by one.
    for (auto &SF : CorporaFiles) {
      auto U = FileToVector(SF.File, MaxInputLen, /*ExitOnError=*/false);
      assert(U.size() <= MaxInputLen);
      RunOne(U.data(), U.size());
      CheckExitOnSrcPosOrItem();
      TryDetectingAMemoryLeak(U.data(), U.size(),
                              /*DuringInitialCorpusExecution*/ true);
    }
  }

  PrintStats("INITED");
  if (!Options.FocusFunction.empty()) {
    Printf("INFO: %zd/%zd inputs touch the focus function\n",
           Corpus.NumInputsThatTouchFocusFunction(), Corpus.size());
    if (!Options.DataFlowTrace.empty())
      Printf("INFO: %zd/%zd inputs have the Data Flow Trace\n",
             Corpus.NumInputsWithDataFlowTrace(),
             Corpus.NumInputsThatTouchFocusFunction());
  }

  if (Corpus.empty() && Options.MaxNumberOfRuns) {
    Printf("ERROR: no interesting inputs were found. "
           "Is the code instrumented for coverage? Exiting.\n");
    exit(1);
  }
}

void Fuzzer::InitializeForkserver() {
  if (!UseFile) {
    char TmpFuzzingStdioFileName[0x100];
    snprintf(TmpFuzzingStdioFileName, 0xff, "/dev/shm/.libfuzzer_%d_cur_input", Options.FuzzingNumber);

    // just to make sure...
    unlink(TmpFuzzingStdioFileName);
    FuzzingStdioFileFD = open(TmpFuzzingStdioFileName, O_RDWR | O_CREAT | O_EXCL, 0600);     
  }

  fprintf(stderr, "[STARTUP] creating fork server...\n");
  // create fork server
  int Pipe1[2], Pipe2[2];
  assert(pipe(Pipe1) >= 0);
  assert(pipe(Pipe2) >= 0);
  ReadStartFromParentFD = Pipe1[0];
  WriteStartToForkServerFD = Pipe1[1];
  ReadStatusFromForkServerFD = Pipe2[0];
  WriteStatusToParentFD = Pipe2[1];

  // just to make sure...
  int flags = fcntl(ReadStartFromParentFD, F_GETFL, 0);
  fcntl(ReadStartFromParentFD, F_SETFL, flags & (~O_NONBLOCK));
  flags = fcntl(ReadStatusFromForkServerFD, F_GETFL, 0);
  fcntl(ReadStatusFromForkServerFD, F_SETFL, flags & (~O_NONBLOCK));

  // create fork server
  ForkServerPid = fork();
  if (ForkServerPid == 0) { // in fork serveri
    int ret;
    // some trick to improve performance
    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);
    struct rlimit r;
    r.rlim_max = r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */
    setsid();

    // Umpf. On OpenBSD, the default fd limit for root users is set to
    // soft 128. Let's try to fix that... 
    fprintf(stderr, "[FORKSERVER] prepare for dup2(%d, %d)\n", ReadStartFromParentFD, FORKSERVER_FD);
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSERVER_FD + 2) {
      r.rlim_cur = FORKSERVER_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
    }

    fprintf(stderr, "[FORKSERVER] start opening /dev/null...\n");
    int DevNullFD = open("/dev/null", O_RDWR);
    fprintf(stderr, "[FORKSERVER] start closing stdout and stderr...\n");
    if (UseFile) 
        dup2(DevNullFD, 0);
    else {
        dup2(FuzzingStdioFileFD, 0);
        close(FuzzingStdioFileFD);
    }
    dup2(DevNullFD, 1);
    dup2(DevNullFD, 2);
    close(DevNullFD);

    fprintf(stderr, "[FORKSERVER] start dup2 for communicating pipe\n");
    ret = dup2(ReadStartFromParentFD, FORKSERVER_FD);
    if (ret == -1) {
        fprintf(stderr, "[FORKSERVER ERROR] dup2(ReadStartFromParentFD, FORKSERVER_FD) error, %d, %d", ret, errno);
        exit(255);
    }
    ret = dup2(WriteStatusToParentFD, FORKSERVER_FD+1);
    if (ret == -1) {
        fprintf(stderr, "[FORKSERVER ERROR] dup2(WriteStatusToParentFD, FORKSERVER_FD + 1) error, %d, %d", ret, errno);
        exit(255);
    }
    close(WriteStartToForkServerFD);
    close(WriteStatusToParentFD);
    close(ReadStartFromParentFD);
    close(ReadStatusFromForkServerFD);

    fprintf(stderr, "[FORKSERVER] start testing pipe\n");
    size_t dummy;
    assert(write(FORKSERVER_FD+1, "a", 1));
    ret = read(FORKSERVER_FD, &dummy, 1);
    if (ret != 1) {
        fprintf(stderr, "[ERROR] reading from ReadStartFromParentFD, %d, %d\n", ret, errno);
        exit(255);
    }
    for (int i = 0; i < __libfuzzer_argc; ++i) {
        fprintf(stderr, "[FORKSERVER] %s\n", __libfuzzer_argv[i]);
    }

    if (__libfuzzer_argv[__libfuzzer_argc-1] != NULL) {
        __libfuzzer_argv = (char **) realloc(__libfuzzer_argv, (__libfuzzer_argc+1) * sizeof(char *));
        __libfuzzer_argv[__libfuzzer_argc] = NULL;
    }
    for (int i = 0; i < __libfuzzer_argc; ++i) {
        fprintf(stderr, "[FORKSERVER] %s\n", __libfuzzer_argv[i]);
    }
    ret = execv(__libfuzzer_argv[0], __libfuzzer_argv);
    fprintf(stderr, "[FORKSERVER ERROR] error calling execv, %d, %d\n", ret, errno);
  }

  close(WriteStatusToParentFD);
  close(ReadStartFromParentFD);

  InstallInterruptCallback(SIGINT);
  InstallInterruptCallback(SIGABRT);
  InstallInterruptCallback(SIGILL);
  InstallInterruptCallback(SIGTRAP);
  InstallInterruptCallback(SIGSEGV);
  // check forkserver communication
  size_t dummy;
  int ret;
  assert(read(ReadStatusFromForkServerFD, &dummy, 1) == 1);
  ret = write(WriteStartToForkServerFD, "a", 1);
  if (ret != 1) {
      fprintf(stderr, "[PARENT ERROR] writing to forkserver, %d, %d\n", ret, errno);
      exit(255);
  }

  // write FuzzingNumber and TimeOutUSec to forkserver
  uint32_t TimeoutUSec = Options.UnitTimeoutMSec * 1000;
  uint32_t FuzzingNumber = Options.FuzzingNumber;
  assert(write(WriteStartToForkServerFD, &FuzzingNumber, 4) == 4);
  assert(write(WriteStartToForkServerFD, &TimeoutUSec, 4) == 4);
  // TPC.CheckSameSizeToForkserver(WriteStartToForkServerFD); 
  // TPC.ReadModulesFromForkserver(ReadStatusFromForkServerFD);
  // TPC.ReadModulePCTableFromForkserver(ReadStatusFromForkServerFD);
}

void Fuzzer::Loop(Vector<SizedFile> &CorporaFiles) {
  auto FocusFunctionOrAuto = Options.FocusFunction;
  DFT.Init(Options.DataFlowTrace, &FocusFunctionOrAuto, CorporaFiles,
           MD.GetRand());
  TPC.SetFocusFunction(FocusFunctionOrAuto);

  TPC.Initialize();
  InitializeForkserver();

  ReadAndExecuteSeedCorpora(CorporaFiles);
  DFT.Clear();  // No need for DFT any more.
  TPC.SetPrintNewPCs(Options.PrintNewCovPcs);
  TPC.SetPrintNewFuncs(Options.PrintNewCovFuncs);
  system_clock::time_point LastCorpusReload = system_clock::now();

  TmpMaxMutationLen =
      Min(MaxMutationLen, Max(size_t(4), Corpus.MaxInputSize()));

  StartFuzzingTime = system_clock::now();
  while (true) {
    auto Now = system_clock::now();
    if (!Options.StopFile.empty() &&
        !FileToVector(Options.StopFile, 1, false).empty())
      break;
    if (duration_cast<seconds>(Now - LastCorpusReload).count() >=
        Options.ReloadIntervalSec) {
      RereadOutputCorpus(MaxInputLen);
      LastCorpusReload = system_clock::now();
    }
    if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
      break;
    if (TimedOut())
      break;

    // Update TmpMaxMutationLen
    if (Options.LenControl) {
      if (TmpMaxMutationLen < MaxMutationLen &&
          TotalNumberOfRuns - LastCorpusUpdateRun >
              Options.LenControl * Log(TmpMaxMutationLen)) {
        TmpMaxMutationLen =
            Min(MaxMutationLen, TmpMaxMutationLen + Log(TmpMaxMutationLen));
        LastCorpusUpdateRun = TotalNumberOfRuns;
      }
    } else {
      TmpMaxMutationLen = MaxMutationLen;
    }

    // Perform several mutations and runs.
    MutateAndTestOne();

    // PurgeAllocator();
  }

  PrintStats("DONE  ", "\n");
  MD.PrintRecommendedDictionary();
}

void Fuzzer::MinimizeCrashLoop(const Unit &U) {
  if (U.size() <= 1)
    return;
  while (!TimedOut() && TotalNumberOfRuns < Options.MaxNumberOfRuns) {
    MD.StartMutationSequence();
    memcpy(CurrentUnitData, U.data(), U.size());
    for (int i = 0; i < Options.MutateDepth; i++) {
      size_t NewSize = MD.Mutate(CurrentUnitData, U.size(), MaxMutationLen);
      assert(NewSize > 0 && NewSize <= MaxMutationLen);
      ExecuteCallback(CurrentUnitData, NewSize);
      PrintPulseAndReportSlowInput(CurrentUnitData, NewSize);
      TryDetectingAMemoryLeak(CurrentUnitData, NewSize,
                              /*DuringInitialCorpusExecution*/ false);
    }
  }
}

} // namespace fuzzer

extern "C" {

ATTRIBUTE_INTERFACE size_t
LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  assert(fuzzer::F);
  return fuzzer::F->GetMD().DefaultMutate(Data, Size, MaxSize);
}

} // extern "C"
