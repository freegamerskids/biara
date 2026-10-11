// Collapse completed functions while lifting, without revisiting the prefix
// of the module or retaining analyses for functions already processed.
#include "llvm-c/Types.h"
#include "llvm/IR/Function.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/SROA.h"

using namespace llvm;

namespace {
struct Trimmer {
  LoopAnalysisManager LAM;
  FunctionAnalysisManager FAM;
  CGSCCAnalysisManager CGAM;
  ModuleAnalysisManager MAM;
  FunctionPassManager FPM;

  explicit Trimmer(TargetMachine *TM) {
    PassBuilder PB(TM);
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
    // Matches function(sroa,early-cse<memssa>,
    // instcombine<no-verify-fixpoint>) in LLVM 23.
    FPM.addPass(SROAPass(SROAOptions(SROAOptions::ModifyCFG)));
    FPM.addPass(EarlyCSEPass(true));
    FPM.addPass(InstCombinePass(InstCombineOptions().setVerifyFixpoint(false)));
  }

  void run(Function &F) {
    FPM.run(F, FAM);
    // The module is still being constructed. Do not carry cached analyses
    // across runs, or let their storage grow with the number of functions.
    FAM.clear();
    CGAM.clear();
    MAM.clear();
    LAM.clear();
  }
};
} // namespace

extern "C" void *biara_trimmer_create(void *TM) {
  return new Trimmer(static_cast<TargetMachine *>(TM));
}

extern "C" void biara_trimmer_run(void *Ctx, LLVMValueRef F) {
  static_cast<Trimmer *>(Ctx)->run(*unwrap<Function>(F));
}

extern "C" void biara_trimmer_dispose(void *Ctx) {
  delete static_cast<Trimmer *>(Ctx);
}
