// Unsigned value ranges at given program points (see src/calls.rs), from
// LazyValueInfo (which the C API does not expose), refined by shared
// control-flow-edge facts (edge_ranges.h). The refinement only narrows the
// baseline range; exhausted budgets keep that range.

#include "edge_ranges.h"

#include "llvm-c/Types.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"

#include <cstdint>

using namespace llvm;

// For each i < N: the unsigned range [Lo[i], Hi[i]] of integer value Vals[i]
// just before instruction Ctx[i] (both in Fn), with Known[i] = 0 when
// nothing better than the full range is known.
extern "C" void biara_value_ranges(LLVMValueRef Fn, size_t N, LLVMValueRef *Vals,
                                   LLVMValueRef *Ctx, uint64_t *Lo, uint64_t *Hi,
                                   int *Known) {
  Function *F = unwrap<Function>(Fn);
  PassBuilder PB;
  FunctionAnalysisManager FAM;
  PB.registerFunctionAnalyses(FAM);
  LazyValueInfo &LVI = FAM.getResult<LazyValueAnalysis>(*F);
  const DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(*F);
  // One shared batch: the dominator tree and LVI handle are built once per
  // function, not once per queried operand, so many queries over very large
  // CFGs stay bounded.
  biara::EdgeRanges Edges(LVI, DT);
  for (size_t I = 0; I < N; ++I) {
    Value *V = unwrap(Vals[I]);
    auto *CxtI = dyn_cast<Instruction>(unwrap(Ctx[I]));
    Known[I] = 0;
    if (!CxtI || !V->getType()->isIntegerTy() || V->getType()->getIntegerBitWidth() > 64)
      continue;
    ConstantRange Base = LVI.getConstantRange(V, CxtI, /*UndefAllowed=*/false);
    ConstantRange R = Edges.refine(V, CxtI, Base);
    if (R.isFullSet() || R.isEmptySet())
      continue;
    Lo[I] = R.getUnsignedMin().getZExtValue();
    Hi[I] = R.getUnsignedMax().getZExtValue();
    Known[I] = 1;
  }
}
