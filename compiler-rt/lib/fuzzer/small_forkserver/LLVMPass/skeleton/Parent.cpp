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
  struct ParentPass : public ModulePass {
    static char ID;
    LLVMContext* C;
    Type *VoidTy;
    ParentPass() : ModulePass(ID) {}

    StringRef getPassName() const override {
        return "ParentPass";
    }
    virtual bool runOnModule(Module &M) {
        for (auto& F: M) {
            if (F.getName() == "main") {
                F.setName("tmp_main");
                return true;
            }
        }
        return false;
    }
  };
}

char ParentPass::ID = 0;

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerParentPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new ParentPass());
}
static RegisterStandardPasses
  RegisterMyPass1(PassManagerBuilder::EP_EnabledOnOptLevel0,
                 registerParentPass);
static RegisterStandardPasses
  RegisterMyPass2(PassManagerBuilder::EP_ModuleOptimizerEarly,
                 registerParentPass);
