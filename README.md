# icLibFuzzer


- [Support Version](#Support-Version)
- [Install](#Install)
- [Usage](#Usage)
- [Error](#Error)


## Support Version
Only following branch support icLibFuzzer
Please checkout to following branch (the version indicated LLVM version)
 - 11.x


## Install
```bash=
## get source
export INSTALL_LLVM=/path/to/install/llvm
git clone https://github.com/csienslab/icLibFuzzer ${INSTALL_LLVM}/llvm-project
git checkout 11.x

## build and install
cd ${INSTALL_LLVM}/llvm-project
mkdir build && cd build
cmake -DLLVM_ENABLE_PROJECTS=clang -G "Unix Makefiles" ../llvm/
make && make install

## build forkserver tools
cd compiler-rt/lib/fuzzer/small_forkserver/ && LLVM_HOME=${INSTALL_LLVM}/llvm-project make all
cd ../ && ./move.py -m small

## add our compiler wrapper into PATH
echo export PATH=$PATH:`pwd`/bin >> ~/.bashrc  
export PATH=$PATH:`pwd`/bin 

## now we build and install compiler-rt alone
## you then only need to compile and install this part 
## whenever you make any change to icLibFuzzer
cd ${INSTALL}/llvm-project/compiler-rt/
mkdir build && cd build
cmake .. && make `nproc` && make install

```

 PS: You can use `move.py` located under `./llvm-project/compiler-rt/lib/fuzzer/` to switch between different version of libFuzzer.
 For details, run with `python move.py`.

 ## Usage
 ```bash=
 export CC=clang-fast
 export CXX=clang-fast++
 export CFLAGS=' -g -O2 '
 ./configure --disable-shared

 ## create forkserver binary
 make `nproc`

 ## now move the compiled binary to forkserver
 mv <compiled_binary> ./forkserver

 ## create parent binary
 make clean
 LIBFUZZER_OBJECT_NAME=parent make `nproc`

 ## now move the compiled binary to parent
 mv <compiled_binary> ./parent

 ## fuzz it!
 ## note that @@ represent the file input to fuzzing target
 ## just ignore it if the fuzzing target read input from stdin
 ## currently we doesn't support input from both stdin and file
 mkdir corpus
 echo 'initial seed' > corpus/init1
 ./parent -entropic=1 -use_value_profile=1 -reload=0 -timeout=50 ./corpus -ignore_remaining_args=1 -- ./forkserver $ARGV @@ 

 ```

## Error

### linker complain about 'libclang-rtxxx.a' not found 
```bash

## LLVM sometimes somehow does not install sanitizer in /usr/local/bin/clang/<version>/lib
## add it manually
mkdir -p /usr/local/lib/clang/<version>/lib
sudo ln -sF /usr/local/lib/linux /usr/local/lib/clang/<version>/lib/linux
```


# The LLVM Compiler Infrastructure

This directory and its sub-directories contain source code for LLVM,
a toolkit for the construction of highly optimized compilers,
optimizers, and run-time environments.

The README briefly describes how to get started with building LLVM.
For more information on how to contribute to the LLVM project, please
take a look at the
[Contributing to LLVM](https://llvm.org/docs/Contributing.html) guide.

## Getting Started with the LLVM System

Taken from https://llvm.org/docs/GettingStarted.html.

### Overview

Welcome to the LLVM project!

The LLVM project has multiple components. The core of the project is
itself called "LLVM". This contains all of the tools, libraries, and header
files needed to process intermediate representations and converts it into
object files.  Tools include an assembler, disassembler, bitcode analyzer, and
bitcode optimizer.  It also contains basic regression tests.

C-like languages use the [Clang](http://clang.llvm.org/) front end.  This
component compiles C, C++, Objective-C, and Objective-C++ code into LLVM bitcode
-- and from there into object files, using LLVM.

Other components include:
the [libc++ C++ standard library](https://libcxx.llvm.org),
the [LLD linker](https://lld.llvm.org), and more.

### Getting the Source Code and Building LLVM

The LLVM Getting Started documentation may be out of date.  The [Clang
Getting Started](http://clang.llvm.org/get_started.html) page might have more
accurate information.

This is an example work-flow and configuration to get and build the LLVM source:

1. Checkout LLVM (including related sub-projects like Clang):

     * ``git clone https://github.com/llvm/llvm-project.git``

     * Or, on windows, ``git clone --config core.autocrlf=false
    https://github.com/llvm/llvm-project.git``

2. Configure and build LLVM and Clang:

     * ``cd llvm-project``

     * ``mkdir build``

     * ``cd build``

     * ``cmake -G <generator> [options] ../llvm``

        Some common build system generators are:

        * ``Ninja`` --- for generating [Ninja](https://ninja-build.org)
          build files. Most llvm developers use Ninja.
        * ``Unix Makefiles`` --- for generating make-compatible parallel makefiles.
        * ``Visual Studio`` --- for generating Visual Studio projects and
          solutions.
        * ``Xcode`` --- for generating Xcode projects.

        Some Common options:

        * ``-DLLVM_ENABLE_PROJECTS='...'`` --- semicolon-separated list of the LLVM
          sub-projects you'd like to additionally build. Can include any of: clang,
          clang-tools-extra, libcxx, libcxxabi, libunwind, lldb, compiler-rt, lld,
          polly, or debuginfo-tests.

          For example, to build LLVM, Clang, libcxx, and libcxxabi, use
          ``-DLLVM_ENABLE_PROJECTS="clang;libcxx;libcxxabi"``.

        * ``-DCMAKE_INSTALL_PREFIX=directory`` --- Specify for *directory* the full
          path name of where you want the LLVM tools and libraries to be installed
          (default ``/usr/local``).

        * ``-DCMAKE_BUILD_TYPE=type`` --- Valid options for *type* are Debug,
          Release, RelWithDebInfo, and MinSizeRel. Default is Debug.

        * ``-DLLVM_ENABLE_ASSERTIONS=On`` --- Compile with assertion checks enabled
          (default is Yes for Debug builds, No for all other build types).

      * ``cmake --build . [-- [options] <target>]`` or your build system specified above
        directly.

        * The default target (i.e. ``ninja`` or ``make``) will build all of LLVM.

        * The ``check-all`` target (i.e. ``ninja check-all``) will run the
          regression tests to ensure everything is in working order.

        * CMake will generate targets for each tool and library, and most
          LLVM sub-projects generate their own ``check-<project>`` target.

        * Running a serial build will be **slow**.  To improve speed, try running a
          parallel build.  That's done by default in Ninja; for ``make``, use the option
          ``-j NNN``, where ``NNN`` is the number of parallel jobs, e.g. the number of
          CPUs you have.

      * For more information see [CMake](https://llvm.org/docs/CMake.html)

Consult the
[Getting Started with LLVM](https://llvm.org/docs/GettingStarted.html#getting-started-with-llvm)
page for detailed information on configuring and compiling LLVM. You can visit
[Directory Layout](https://llvm.org/docs/GettingStarted.html#directory-layout)
to learn about the layout of the source code tree.
