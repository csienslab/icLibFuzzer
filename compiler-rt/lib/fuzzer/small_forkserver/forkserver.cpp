#define _GNU_SOURCE 1 
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>
#include <time.h>
#include <boost/functional/hash.hpp>
#include "sanitizer_internal_defs.h"
#include "TracePC.h"
#ifdef CPLUSPLUS
extern "C" {
#endif
void __libfuzzer_initializer();
#ifdef CPLUSPLUS
}
#endif
extern TracePC TPC;

int FORKSERVER_FD = 1022;
uint32_t FuzzingNumber;
bool Fuzzing = false;
struct timespec UnitStartTime, FuzzingStartTime, LastLogTime;
uint32_t Timeout;
pid_t pid;

// record every hours
#define LogStatus() do { \
        char buf[0x100]; \
        snprintf(buf, 0xff, "/tmp/__libfuzzer_status_%d", FuzzingNumber); \
        int FuzzingStatusFileFD = open(buf, O_RDWR | O_CREAT, 0600); \
        int Length; \
        Length = snprintf(buf, 0xff, "total seconds : %ld s\n", UnitStartTime.tv_sec - FuzzingStartTime.tv_sec); \
        write(FuzzingStatusFileFD, buf, Length); \
        Length = snprintf(buf, 0xff, "exec/s : %lu\n", TotalNumberOfRuns / (UnitStartTime.tv_sec - FuzzingStartTime.tv_sec)); \
        write(FuzzingStatusFileFD, buf, Length); \
        Length = snprintf(buf, 0xff, "Total exec : %lu\n", TotalNumberOfRuns); \
        write(FuzzingStatusFileFD, buf, Length); \
        Length = snprintf(buf, 0xff, "timeout value : %u ms\n", Timeout / 1000); \
        write(FuzzingStatusFileFD, buf, Length); \
        close(FuzzingStatusFileFD); \
    } while(0);



#if defined(__x86_64__)
# define REG_PC REG_RIP
# define REG_BP REG_RBP
#else
# define REG_PC REG_EIP
# define REG_BP REG_EBP
#endif

using __sanitizer::u32;
using __sanitizer::uptr;
using __sanitizer::uhwptr;

static inline bool IsValidFrame(uptr frame, uptr stack_top, uptr stack_bottom) {
    return frame > stack_bottom && frame < stack_top - 2 * sizeof (uhwptr);
}

inline bool IsAligned(uptr a, uptr alignment) {
    return (a & (alignment - 1)) == 0;
}


void GetThreadStackTopAndBottom(uptr *stack_top, uptr *stack_bottom) {
    pthread_attr_t attr;
    CHECK_EQ(pthread_getattr_np(pthread_self(), &attr), 0);
    void *base;
    size_t size;
    CHECK_EQ(pthread_attr_getstack(&attr, &base, &size), 0);
    CHECK_EQ(pthread_attr_destroy(&attr), 0);

    *stack_bottom = reinterpret_cast<uptr>(base);
    *stack_top = *stack_bottom + size;
}

size_t unwind(uptr pc, uptr bp, uptr stack_top, uptr stack_bottom, u32 max_depth) {
    size_t seed = 0;
    boost::hash_combine(seed, pc);
    // boost::hash_combine(seed, TPC.Checksum());
    const uptr kPageSize = 0x1000;
    CHECK_GE(max_depth, 2);
    if (stack_top < 4096) return -1;  // Sanity check for stack top.
    uhwptr *frame = (uhwptr*)bp;
    // Lowest possible address that makes sense as the next frame pointer.
    // Goes up as we walk the stack.
    uptr bottom = stack_bottom;
    u32 size = 0;
    // Avoid infinite loop when frame == frame[0] by using frame > prev_frame.
    while (IsValidFrame((uptr)frame, stack_top, bottom) &&
         IsAligned((uptr)frame, sizeof(*frame)) &&
         size++ < max_depth) {
        uhwptr pc1 = frame[1];
        // Let's assume that any pointer in the 0th page (i.e. <0x1000 on i386 and
        // x86_64) is invalid and stop unwinding here.  If we're adding support for
        // a platform where this isn't true, we need to reconsider this check.
        if (pc1 < kPageSize)
          break;
        if (pc1 != pc) {
            boost::hash_combine(seed, pc1);
        }
        bottom = (uptr)frame;
        frame = (uhwptr *)(frame[0]);
    }
    return seed;
}

static void crash_hook(int sig, siginfo_t *siginfo, void *context) {
    const ucontext_t *ctx = (ucontext_t*)context;
    uptr pc = ctx->uc_mcontext.gregs[REG_PC];
    uptr bp = ctx->uc_mcontext.gregs[REG_BP];
    uptr top, bottom;
    GetThreadStackTopAndBottom(&top, &bottom);
    //printf("[*] crash pc: 0x%lx, bp: 0x%lx\n", pc, bp);
    uint8_t Res = sig;
    size_t dummy = unwind(pc, bp, top, bottom, 64);

    TPC.CopyModuleCountersToFile(); 
    assert(write(FORKSERVER_FD+1, &Res, 1) == 1);
    assert(write(FORKSERVER_FD+1, &dummy, sizeof(size_t)) == sizeof(size_t));
    _exit(0);
}

int SigactionWrapper(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (signum == SIGSEGV ||
        signum == SIGBUS ||
        signum == SIGABRT ||
        signum == SIGILL ||
        signum == SIGFPE ||
        signum == SIGTERM) {
        //printf("[+] add custom crash hook!\n");
        struct sigaction sa;
        sa.sa_flags = SA_SIGINFO;
        sigfillset(&sa.sa_mask);
        sa.sa_sigaction = crash_hook;
        return sigaction(signum, &sa, NULL);
    }
    return sigaction(signum, act, oldact);
}



static void ExitCallback() {
    // send back fuzzing result
    uint8_t Res = 0;
    size_t dummy = -1;
    TPC.CopyModuleCountersToFile(); 
    assert(write(FORKSERVER_FD+1, &Res, 1) == 1);
    assert(write(FORKSERVER_FD+1, &dummy, sizeof(size_t)) == sizeof(size_t));

    _exit(0);
}


static void CustomAlarmHandler(int SigNum, siginfo_t *__, void *___) {
    if (!Fuzzing) {
        if (pid > 0) 
            kill(pid, SIGALRM);
        /*
        struct timespec Now;
        clock_gettime(CLOCK_MONOTONIC_RAW, &Now);
        uint32_t tt = (Now.tv_sec - UnitStartTime.tv_sec) * 1000000 + (Now.tv_nsec - UnitStartTime.tv_nsec) / 1000;
        if (tt >= Timeout) {
            kill(pid, SIGALRM);
        }
        */
        return;
    }
    uint8_t Res = SigNum;
    size_t dummy = -1;
    TPC.CopyModuleCountersToFile();
    assert(write(FORKSERVER_FD+1, &Res, 1) == 1);
    assert(write(FORKSERVER_FD+1, &dummy, sizeof(size_t)) == sizeof(size_t));
    _exit(0);
}


static void CustomInterruptHandler(int SigNum, siginfo_t *__, void *___) {
    kill(pid, SIGKILL);
    uint8_t Res = 254;
    size_t dummy = -1;
    TPC.CopyModuleCountersToFile();
    assert(write(FORKSERVER_FD+1, &Res, 1) == 1);
    assert(write(FORKSERVER_FD+1, &dummy, sizeof(size_t)) == sizeof(size_t));
    _exit(0);
}

void InstallCrashCallback(int SigNum,
                            void (*Callback)(int, siginfo_t *, void *)) {
    struct sigaction sigact = {};
    sigact.sa_flags = SA_SIGINFO;
    sigact.sa_sigaction = Callback;
    sigfillset(&sigact.sa_mask);
    if (SigactionWrapper(SigNum, &sigact, 0)) {
      exit(1);
    }
}

void __libfuzzer_initializer() {
    // FORKSERVER_FD    : read info from parent
    // FORKSERVER_FD + 1: write status to parent
    if (read(FORKSERVER_FD, &FuzzingNumber, 4) != 4) {
        return;
    }
    if (read(FORKSERVER_FD, &Timeout, 4) != 4) {
        return;
    }
    TPC.SetFuzzingNumber(FuzzingNumber);
    TPC.Initialize();
    // TPC.CheckSameSizeToParent(FORKSERVER_FD);
    // TPC.TellParentAboutModules(FORKSERVER_FD+1);
    // TPC.TellParentAboutModulePCTable(FORKSERVER_FD+1);
    // set alarm
    // we now read this from pipe
    struct itimerval T {
      {Timeout / 1000000, Timeout % 1000000}, {Timeout / 1000000, Timeout % 1000000}
    };
    struct itimerval T0 {
        {0, 0}, {0, 0}
    };
    InstallCrashCallback(SIGINT, CustomInterruptHandler);
    InstallCrashCallback(SIGALRM, CustomAlarmHandler);
    InstallCrashCallback(SIGSEGV, NULL);
    InstallCrashCallback(SIGABRT, NULL);
    InstallCrashCallback(SIGTERM, NULL);
    InstallCrashCallback(SIGBUS, NULL);
    InstallCrashCallback(SIGILL, NULL);
    InstallCrashCallback(SIGFPE, NULL);
    atexit(ExitCallback);

    char dummy;
    int ret;
    Fuzzing = false;

    // TotalNumberOfRuns now represent how many times has we fuzzed
    // and we will set a more correct timeout value
    bool ReviseTimeout = true;
    int status = 0;
    uint8_t Res = 0;
    uint64_t TotalNumberOfRuns = 0;
    clock_gettime(CLOCK_MONOTONIC_RAW, &FuzzingStartTime);
    LastLogTime = FuzzingStartTime;

    while(1) {
        // wait for parent to start
        do {
            ret = read(FORKSERVER_FD, &dummy, 1);
            if (ret == 1) break;
        } while (1);

        setitimer(ITIMER_REAL, &T, nullptr);
        pid = fork();
        if (pid) {
            do {
                ret = waitpid(pid, &status, 0);
                if (ret == pid) break;
                else if (errno == ECHILD) exit(255);
            } while (1);

            // tell parent we finish fuzzing
            if (WIFSIGNALED(status))
                Res = WTERMSIG(status);
            else
                Res = WEXITSTATUS(status);
            if (Res != 0) {
                _exit(0);
            }
            setitimer(ITIMER_REAL, &T0, nullptr);
        }
        else {
            Fuzzing = true;
            return;
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &UnitStartTime);
        ++TotalNumberOfRuns;
        if (UnitStartTime.tv_sec - LastLogTime.tv_sec > 3600) {
            LogStatus();
            LastLogTime = UnitStartTime;
        }
        if (ReviseTimeout) {
            if (UnitStartTime.tv_sec - FuzzingStartTime.tv_sec > 60) {
                ReviseTimeout = false;
                uint32_t TmpTimeout;
                uint64_t Average = ((UnitStartTime.tv_sec - FuzzingStartTime.tv_sec) * 1000000000 +
                                    (UnitStartTime.tv_nsec - FuzzingStartTime.tv_nsec)) / TotalNumberOfRuns; // nano seconds
                if (Average > 50000000) TmpTimeout = (uint32_t) (Average * 3 / 1000);
                else if (Average > 10000000) TmpTimeout = (uint32_t) (Average * 4 / 1000);
                else TmpTimeout = (uint32_t) (Average * 6 / 1000);
                TmpTimeout = Max(TmpTimeout, (uint32_t)1000);
                TmpTimeout = (TmpTimeout + 20000) / 20000 * 20000;
                if (TmpTimeout > Timeout) Timeout = TmpTimeout;
                T.it_interval.tv_sec = Timeout / 1000000;
                T.it_interval.tv_usec = Timeout % 1000000;
                T.it_value.tv_sec = Timeout / 1000000;
                T.it_value.tv_usec = Timeout % 1000000;
            }
        }
    }
}
