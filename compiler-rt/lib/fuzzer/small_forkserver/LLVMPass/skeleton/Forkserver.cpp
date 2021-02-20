#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
  struct ForkserverPass : public ModulePass {
    static char ID;
    LLVMContext* C;
    Type *Int8Ty, *Int32Ty, *Int8PtrTy, *VoidTy;
    FunctionCallee LibfuzzerInitializerFunction;

    ForkserverPass() : ModulePass(ID) {}

    StringRef getPassName() const override {
        return "ForkserverPass";
    }
    virtual bool runOnModule(Module &M) {
        C = &(M.getContext());
        Int8Ty = Type::getInt8Ty(*C);
        Int32Ty = Type::getInt32Ty(*C);
        VoidTy = Type::getVoidTy(*C);
        Int8PtrTy = PointerType::getUnqual(Int8Ty);
        

        /*LibfuzzerInitializerFunction = M.getOrInsertFunction("__libfuzzer_initializer",
                VoidTy,
                Int32Ty,
                Int8PtrTy);
        */
        LibfuzzerInitializerFunction = M.getOrInsertFunction("__libfuzzer_initializer",
                VoidTy);
        if (!LibfuzzerInitializerFunction) {
            errs() << "cannot find / insert __libfuzzer_initializer\n";
            return false;
        }

    
        for (auto& F: M) {
            if (F.getName() == "main") {
                /*Value *args[] = {NULL, NULL};
                int idx = 0;
                for (auto arg = F.arg_begin(); arg != F.arg_end(); ++idx, ++arg) {
                    args[idx] = arg;
                }*/
                IRBuilder<> IRB(&*(F.getEntryBlock().getFirstInsertionPt()));
                IRB.CreateCall(LibfuzzerInitializerFunction, {});
                return true;
            }
        }
  
        return false;
    }
  };
}

char ForkserverPass::ID = 0;

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerForkserverPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new ForkserverPass());
}
static RegisterStandardPasses
  RegisterMyPass1(PassManagerBuilder::EP_EnabledOnOptLevel0,
                 registerForkserverPass);
static RegisterStandardPasses
  RegisterMyPass2(PassManagerBuilder::EP_ModuleOptimizerEarly,
                 registerForkserverPass);
