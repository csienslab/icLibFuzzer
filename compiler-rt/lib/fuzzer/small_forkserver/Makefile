.PHONY:clean clang forkserver parent TracePC pass
INCLUDE = /home/llvm-project/compiler-rt/lib/sanitizer_common/

all: forkserver clang pass

pass:
	make -C LLVMPass/

forkserver: TracePC 
	clang -O2 -g ./forkserver.cpp -DCPLUSPLUS -I$(INCLUDE) -I./include -c -o ./lib/forkserver.o
	# ld -r lib/forkserver.o lib/TracePC.o -o lib/libfuzzer.o
	ar ru lib/libfuzzer.a lib/forkserver.o lib/TracePC.o

TracePC: TracePC.cpp
	clang -O2 -g ./TracePC.cpp -I./include -c -o ./lib/TracePC.o

clang:
	gcc clang-fast.c -o ./bin/clang-fast

parent:
	clang -O2 -g ./parent.cpp -fsanitize=fuzzer -o ./bin/parent

clean:
	rm -rf ./*.o ./forkserver ./parent ./lib/*.o
	make -C LLVMPass clean
