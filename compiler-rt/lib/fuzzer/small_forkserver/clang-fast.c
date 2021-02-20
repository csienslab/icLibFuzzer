#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>

#define alloc_printf(_str...) ({ \
            uint8_t *_tmp; \
            size_t _len = snprintf(NULL, 0, _str); \
            if (_len < 0) { \
                fprintf(stderr, "snprintf error\n"); \
                exit(255); \
            } \
            _tmp = calloc(_len + 1, 1); \
            snprintf((char*)_tmp, _len + 1, _str); \
            _tmp; \
          })

static uint8_t *BINARY_NAME;
static uint8_t *OBJECT_NAME;
static uint8_t *BIN_PATH;
static uint8_t *object_path;               /* Path to runtime libraries         */
static uint8_t *linker_script;
static uint8_t *llvm_pass;
static uint8_t **cc_params;              /* Parameters passed to the real CC  */
static uint32_t cc_par_cnt = 1;         /* Param count, including argv0      */

int endswith(const uint8_t *str, const uint8_t *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix > lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}


/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(uint8_t *argv0) {
    uint8_t *tmp;
    uint8_t *objectpp_suffix, *object_suffix, *linker_suffix;

    linker_suffix = "%s%s/../lib/linker.ld";
    if (!strcmp(OBJECT_NAME, "forkserver")) {
        object_suffix = "%s/../lib/libfuzzer.a";
        llvm_pass = "%s/../LLVMPass/build/skeleton/libForkserverPass.so"; 
    }
    else {
        object_suffix = "%s/../lib/libfuzzer.a";
        llvm_pass = "%s/../LLVMPass/build/skeleton/libParentPass.so"; 
    }

    tmp = alloc_printf(object_suffix, BIN_PATH);
    if (access(tmp, R_OK)) {
        fprintf(stderr, "Could not find 'libfuzzer.o' at %s, please don't change the location of this binary!\n", tmp);
        exit(255); 

    }
    object_path = tmp;

    tmp = alloc_printf(llvm_pass, BIN_PATH);
    if (access(tmp, R_OK)) {
        fprintf(stderr, "Could not find llvm pass at %s, please don't change the location of this binary!\n", tmp);
        exit(255); 
    }
    llvm_pass = tmp;

    tmp = alloc_printf(linker_suffix, "", BIN_PATH);
    if (access(tmp, R_OK)) {
        fprintf(stderr, "Could not find linker script at %s, please don't change the location of this binary!\n", tmp);
        exit(255); 
    }
    tmp = alloc_printf(linker_suffix, "-T", BIN_PATH);
    linker_script = tmp;
}


/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(uint32_t argc, char **argv) {
  uint8_t need_main = 0, is_rename = 0, maybe_target = 0;
  uint8_t fortify_set = 0, asan_set = 0, x_set = 0, maybe_linking = 1, bit_mode = 0;
  uint8_t *name;

  cc_params = calloc((argc + 128), sizeof(uint8_t*));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (!strcmp(name, "clang-fast++")) 
    cc_params[0] = (uint8_t*) "clang++";
  else 
    cc_params[0] = (uint8_t*) "clang";
  

  /* There are two ways to compile afl-clang-fast. In the traditional mode, we
     use afl-llvm-pass.so to inject instrumentation. In the experimental
     'trace-pc-guard' mode, we use native LLVM instrumentation callbacks
     instead. The latter is a very recent addition - see:

     http://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards */

  cc_params[cc_par_cnt++] = "-g";
  cc_params[cc_par_cnt++] = "-O2";
  cc_params[cc_par_cnt++] = "-fsanitize=fuzzer-no-link";
  cc_params[cc_par_cnt++] = "-funroll-loops";
  cc_params[cc_par_cnt++] = "-Qunused-arguments";

  /* Detect stray -v calls from ./configure scripts. */

  if (argc == 1 && !strcmp(argv[1], "-v")) maybe_linking = 0;

  while (--argc) {
    uint8_t* cur = *(++argv);

    if (strstr(cur, BINARY_NAME))
      maybe_target = 1;

    if (is_rename) {
      is_rename = 0;
      if (endswith(cur, BINARY_NAME)) need_main = 1;
    }
    if (!strcmp(cur, "-o")) is_rename = 1;
    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
      maybe_linking = 0;

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-shared")) maybe_linking = 0;

    if (!strcmp(cur, "-Wl,-z,defs") ||
        !strcmp(cur, "-Wl,--no-undefined")) continue;

    cc_params[cc_par_cnt++] = cur;

  }


  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by afl-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __afl_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = "-load";
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = llvm_pass;

  if (maybe_linking) {

    if (x_set) {
      cc_params[cc_par_cnt++] = "-x";
      cc_params[cc_par_cnt++] = "none";
    }

    cc_params[cc_par_cnt++] = "-Xlinker";
    cc_params[cc_par_cnt++] = linker_script;
    // if (need_main) {
    //   if (!strcmp(OBJECT_NAME, "parent"))
    //     cc_params[cc_par_cnt++] = "-fsanitize=fuzzer";
    // }
    if (!strcmp(OBJECT_NAME, "parent"))
      cc_params[cc_par_cnt++] = "-fsanitize=fuzzer";
    if (!strcmp(OBJECT_NAME, "forkserver"))
      cc_params[cc_par_cnt++] = object_path;
  }

  cc_params[cc_par_cnt] = NULL;

}

void get_clang_fast_path() {
    BIN_PATH = (uint8_t*) calloc(256, 1);
    int bytes = readlink("/proc/self/exe", BIN_PATH, 255);
    if(bytes >= 0)
        BIN_PATH[bytes] = '\0';
    BIN_PATH = dirname(BIN_PATH);
}

/* Main entry point */

int main(int argc, char** argv) {
    get_clang_fast_path();
 
    OBJECT_NAME = getenv("LIBFUZZER_OBJECT_NAME");
    if (!OBJECT_NAME) {
        // fprintf(stdout, "Please set LIBFUZZER_OBJECT_NAME to either 'parent' or 'forkserver'\n Default is forkserver\n");
        OBJECT_NAME = "forkserver";
    }

    BINARY_NAME = getenv("LIBFUZZER_BINARY_NAME");
    if (!BINARY_NAME) {
        BINARY_NAME = "a.out";
    }
   
    if (argc < 2) {
        fprintf(stderr, "\n"
             "This is a helper application for FM-LibFuzzer. It serves as a drop-in replacement\n"
             "for clang, letting you recompile third-party code with the required runtime\n"
             "instrumentation. A common use pattern would be one of the following:\n\n"

             "  CC=%s/clang-fast ./configure\n"
             "  CXX=%s/clang-fast++ ./configure\n\n",
             BIN_PATH, BIN_PATH);
        exit(1);
    }

    find_obj(argv[0]);
    edit_params(argc, argv);
    /*
    for (int i = 0; i < cc_par_cnt; ++i) {
        fprintf(stderr, "%s ", cc_params[i]);
    }
    fprintf(stderr, "\n");
    */
    execvp(cc_params[0], (char**)cc_params);
    fprintf(stderr, "Executing '%s' error\n", cc_params[0]);
    exit(255);
}
