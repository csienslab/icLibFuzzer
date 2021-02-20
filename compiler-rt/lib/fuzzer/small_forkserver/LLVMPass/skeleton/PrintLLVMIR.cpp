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
  struct SkeletonModulePass : public ModulePass {
    static char ID;

    SkeletonModulePass() : ModulePass(ID) {}

    StringRef getPassName() const override {
        return "SkeletonModulePass";
    }
    virtual bool runOnModule(Module &M) {
        errs() << "*********************************\n\n";
        for (auto& F: M) {
            errs() << F.getName() << "\n";
            for (auto& B: F) {
                errs() << B << "\n";
            }
        }
        errs() << "*********************************\n\n";
        return false;
    }

  };
}

char SkeletonModulePass::ID = 0;

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerSkeletonPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new SkeletonModulePass());
}

static RegisterStandardPasses
  RegisterMyPass1(PassManagerBuilder::EP_EnabledOnOptLevel0,
                 registerSkeletonPass);
static RegisterStandardPasses
  RegisterMyPass2(PassManagerBuilder::EP_ModuleOptimizerEarly,
                 registerSkeletonPass);
