// Jump tables in the C output (src/decompile.rs): the lifted code switches
// on the jump target, loaded from a table in guest memory. Where that target
// is a function of one bounded value (the index), evaluate it for every
// index, reading the table through a callback, and switch on the index
// instead: `switch (i) { case 0: ... }` rather than on code addresses.

#include "llvm-c/Types.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
 #include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Operator.h"


#include "llvm/Passes/PassBuilder.h"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

using namespace llvm;

extern "C" {
// Read `len` bytes of guest memory at `addr`; return 0 if unmapped.
typedef int (*biara_index_read_fn)(void *ctx, uint64_t addr, uint8_t *buf, size_t len);
}

namespace {

constexpr uint64_t kMaxIndices = 4096;
constexpr unsigned kMaxDepth = 32;

bool supported(const Value *V) {
  if (isa<ConstantInt>(V))
    return true;
  auto *O = dyn_cast<Operator>(V);
  if (!O)
    return false;
  switch (O->getOpcode()) {
  case Instruction::Add:
  case Instruction::Sub:
  case Instruction::Mul:
  case Instruction::Shl:
  case Instruction::LShr:
  case Instruction::AShr:
  case Instruction::And:
  case Instruction::Or:
  case Instruction::Xor:
  case Instruction::ZExt:
  case Instruction::SExt:
  case Instruction::Trunc:
  case Instruction::IntToPtr:
  case Instruction::PtrToInt:
  case Instruction::GetElementPtr:
  case Instruction::Load:
  case Instruction::Freeze:
  case Instruction::Call:
    return true;
  default:
    return false;
  }
}

 // The values `V` depends on that the evaluator cannot compute (or that
 // it is given: `Stop`). Called functions are not values of interest.
 void leaves(Value *V, Value *Stop, std::set<Value *> &Out, unsigned Depth = 0) {
   if (Depth > kMaxDepth || isa<ConstantInt>(V) || isa<Function>(V))
     return;
   if (V == Stop || !supported(V)) {
     Out.insert(V);
     return;
   }
   auto *U = dyn_cast<User>(V);
   if (!U)
     return;
   if (auto *CB = dyn_cast<CallBase>(V)) {
     for (Value *Op : CB->args())
       leaves(Op, Stop, Out, Depth + 1);
     return;
   }
   for (unsigned K = 0; K < U->getNumOperands(); ++K)
     if (Value *Op = U->getOperand(K))
       leaves(Op, Stop, Out, Depth + 1);
 }

struct Eval {
  const DataLayout &DL;
  biara_index_read_fn Read;
  void *Ctx;
  Value *Fixed;
  APInt FixedVal;

   std::optional<APInt> eval(Value *V, unsigned Depth = 0) {
     if (Depth > kMaxDepth)
       return std::nullopt;
     if (V == Fixed)
       return FixedVal;
     if (auto *C = dyn_cast<ConstantInt>(V))
       return C->getValue();
     auto *O = dyn_cast<Operator>(V);
    if (!O)
      return std::nullopt;
    auto *CB = dyn_cast<CallBase>(V);
    if (CB && !CB->getCalledFunction())
      return std::nullopt;
     unsigned Bits = V->getType()->isPointerTy() ? 64 : V->getType()->getScalarSizeInBits();
     auto op = [&](unsigned K) -> std::optional<APInt> {
       if (K >= O->getNumOperands())
         return std::nullopt;
       if (CB && K == 0 && isa<Function>(O->getOperand(0)))
         return std::nullopt;
       return eval(O->getOperand(K), Depth + 1);
     };
     switch (O->getOpcode()) {
    case Instruction::ZExt:
    case Instruction::SExt:
    case Instruction::Trunc:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt: {
      auto A = op(0);
      if (!A)
        return std::nullopt;
      return O->getOpcode() == Instruction::SExt ? A->sextOrTrunc(Bits) : A->zextOrTrunc(Bits);
    }
    case Instruction::Freeze:
      return op(0);
    case Instruction::Call: {
      if (!CB || isa<Function>(O->getOperand(0)))
        return std::nullopt;
      Function *Callee = CB->getCalledFunction();
      if (!Callee || !Callee->isIntrinsic())
        return std::nullopt;
      Intrinsic::ID ID = Callee->getIntrinsicID();
      // A rotate (`fshl(x, x, k)`): `shl` cannot shift by the width, and
      // folds in the table resolver fail as shifts by 64; fix both.
      if ((ID == Intrinsic::fshl || ID == Intrinsic::fshr) &&
          O->getNumOperands() > 2 && O->getOperand(0) == O->getOperand(1)) {
        auto A = op(0), K = op(2);
        if (!A || !K)
          return std::nullopt;
        uint64_t N = K->urem(APInt(K->getBitWidth(), Bits)).getZExtValue();
        if (N == 0)
          return *A;
        return ID == Intrinsic::fshl ? A->rotl(N) : A->rotr(N);
      }
      return std::nullopt;
    }
    case Instruction::GetElementPtr: {
      auto *G = cast<GEPOperator>(O);
      auto P = op(0);
      if (!P)
        return std::nullopt;
      APInt Addr = *P;
      unsigned K = 1;
      for (auto It = gep_type_begin(G), E = gep_type_end(G); It != E; ++It, ++K) {
        auto I = op(K);
        if (!I)
          return std::nullopt;
        if (StructType *ST = It.getStructTypeOrNull())
          Addr += DL.getStructLayout(ST)->getElementOffset(I->getZExtValue());
        else
          Addr += I->sextOrTrunc(64) * It.getSequentialElementStride(DL).getFixedValue();
      }
      return Addr;
    }
    case Instruction::Load: {
      auto A = op(0);
      unsigned Bytes = DL.getTypeStoreSize(V->getType());
      if (!A || Bytes > 8 || !V->getType()->isIntegerTy())
        return std::nullopt;
      uint8_t Buf[8] = {};
      if (!Read(Ctx, A->getZExtValue(), Buf, Bytes))
        return std::nullopt;
      uint64_t W = 0;
      for (unsigned I = 0; I < Bytes; ++I)
        W |= uint64_t(Buf[I]) << (8 * I);
      return APInt(Bits, W);
    }
    default:
      break;
    }
    auto A = op(0), B = op(1);
    if (!A || !B)
      return std::nullopt;
    switch (O->getOpcode()) {
    case Instruction::Add:
      return *A + *B;
    case Instruction::Sub:
      return *A - *B;
    case Instruction::Mul:
      return *A * *B;
    case Instruction::Shl:
      return B->uge(Bits) ? std::nullopt : std::optional<APInt>(A->shl(*B));
    case Instruction::LShr:
      return B->uge(Bits) ? std::nullopt : std::optional<APInt>(A->lshr(*B));
    case Instruction::AShr:
      return B->uge(Bits) ? std::nullopt : std::optional<APInt>(A->ashr(*B));
    case Instruction::And:
      return *A & *B;
    case Instruction::Or:
      return *A | *B;
    case Instruction::Xor:
      return *A ^ *B;
    default:
      return std::nullopt;
    }
  }
};

// A range for `V` from a dominating `if` guard: walking up the
// single-predecessor chain, an `if (V > Bound) return...` (or `< Bound`,
// `>= Bound`) whose other arm we came down means `V <= Bound` (below) here.
// Sound: each step's block is its child's only predecessor, so the guard
// dominates the switch.
std::optional<ConstantRange> guardRange(SwitchInst &Sw, Value *V) {
  BasicBlock *BB = Sw.getParent();
  for (unsigned D = 0; D < 16; ++D) {
    BasicBlock *P = BB->getSinglePredecessor();
    if (!P)
      return std::nullopt;
    auto *Br = dyn_cast<CondBrInst>(P->getTerminator());
    if (!Br || Br->getSuccessor(0) == BB || Br->getSuccessor(1) != BB)
      return std::nullopt;
    if (auto *Cmp = dyn_cast<ICmpInst>(Br->getCondition())) {
      auto *K = dyn_cast<ConstantInt>(Cmp->getOperand(1));
      if (K && Cmp->getOperand(0) == V) {
        uint64_t Bound = K->getZExtValue();
        // BB is the guard's false arm: `V > Bound` failed (so `V <= Bound`),
        // or `V >= Bound` failed (`V < Bound`). A failed `V < Bound` bounds
        // nothing from above, so it gives no range.
        switch (Cmp->getUnsignedPredicate()) {
        case CmpInst::ICMP_UGT:
          return ConstantRange(APInt(64, 0), APInt(64, Bound + 1));
        case CmpInst::ICMP_UGE:
          return ConstantRange(APInt(64, 0), APInt(64, Bound));
        default:
          break;
        }
      }
    }
    BB = P;
  }
  return std::nullopt;
}

// A switch on `(X << S) & M` whose cases are all multiples of `1 << S`
// reads as a switch on `X & (M >> S)`, with divided cases. (A handler table
// indexed by `which % 4`: the lifted address arithmetic scales the index.)
// Same successors, so no phi fixups; returns whether it rewrote.
bool unscale(SwitchInst &Sw) {
  auto *A = dyn_cast<Operator>(Sw.getCondition());
  if (!A || A->getOpcode() != Instruction::And)
    return false;
  auto *Sh = dyn_cast<Operator>(A->getOperand(0));
  auto *Mc = dyn_cast<ConstantInt>(A->getOperand(1));
  if (!Sh || Sh->getOpcode() != Instruction::Shl || !Mc)
    return false;
  auto *S = dyn_cast<ConstantInt>(Sh->getOperand(1));
  if (!S)
    return false;
  uint64_t ShAmt = S->getZExtValue();
  APInt M = Mc->getValue();
  if (ShAmt == 0 || ShAmt >= M.getBitWidth())
    return false;
  for (auto &C : Sw.cases())
    if (!C.getCaseValue()->getValue().urem(APInt(M.getBitWidth(), 1) << ShAmt).isZero())
      return false;
  Value *X = Sh->getOperand(0);
  IRBuilder<> B(&Sw);
  Value *NewC = B.CreateAnd(X, ConstantInt::get(Sw.getContext(), M.lshr(ShAmt)));
  Sw.setCondition(NewC);
  std::vector<std::pair<ConstantInt *, BasicBlock *>> Cases;
  for (auto &C : Sw.cases())
    Cases.push_back({C.getCaseValue(), C.getCaseSuccessor()});
  while (Sw.case_begin() != Sw.case_end())
    Sw.removeCase(Sw.case_begin());
  for (auto &[V, D] : Cases)
    Sw.addCase(ConstantInt::get(Sw.getContext(), V->getValue().lshr(ShAmt)), D);
  return true;
}

// A switch whose condition a dominating guard bounds and whose cases cover
// every value in the bound: the default cannot happen; point it at
// `unreachable`. (The table fallback a resolver left behind.)
bool guardDefault(SwitchInst &Sw) {
  Value *Cond = Sw.getCondition();
  if (!Cond->getType()->isIntegerTy() || Cond->getType()->getIntegerBitWidth() > 64)
    return false;
  auto R = guardRange(Sw, Cond);
  if (!R || R->isFullSet() || R->isEmptySet())
    return false;
  uint64_t N = (R->getUpper() - R->getLower()).getZExtValue();
  if (N != Sw.getNumCases() || N > kMaxIndices)
    return false;
  for (auto &Case : Sw.cases()) {
    APInt V = Case.getCaseValue()->getValue().zextOrTrunc(64);
    if (V.ult(R->getLower()) || V.uge(R->getUpper()))
      return false;
  }
  BasicBlock *BB = Sw.getParent();
  std::map<BasicBlock *, int> Delta;
  for (BasicBlock *S : successors(&Sw))
    --Delta[S];
  BasicBlock *Un = BasicBlock::Create(Sw.getContext(), "unreachable", BB->getParent());
  new UnreachableInst(Sw.getContext(), Un);
  Sw.setSuccessor(0, Un);
  for (BasicBlock *S : successors(&Sw))
    ++Delta[S];
  for (auto &[S, D] : Delta) {
    for (PHINode &P : S->phis()) {
      Value *In = P.getIncomingValueForBlock(BB);
      for (int I = 0; I < D; ++I)
        P.addIncoming(In, BB);
      for (int I = 0; I > D; --I)
        P.removeIncomingValue(BB, /*DeletePHIIfEmpty=*/false);
    }
  }
  return true;
}

 bool index(SwitchInst &Sw, LazyValueInfo &LVI, const DataLayout &DL, biara_index_read_fn Read,
            void *Ctx) {
   Value *Cond = Sw.getCondition();
   if (isa<ConstantInt>(Cond) || !supported(Cond))
     return false;
   // Only switches on something loaded: the table.
   bool Loads = false;
   std::vector<Value *> Nodes{Cond};
   for (size_t I = 0; I < Nodes.size() && I < 256; ++I) {
     Loads |= isa<LoadInst>(Nodes[I]);
     auto *U = dyn_cast<User>(Nodes[I]);
     if (!U || !supported(U) || isa<ConstantInt>(U))
       continue;
     for (unsigned K = 0; K < U->getNumOperands(); ++K) {
       Value *Op = U->getOperand(K);
       if (!Op || isa<Constant>(Op))
         continue;
       if (auto *CB = dyn_cast<CallBase>(U); CB && K == 0 && isa<Function>(Op))
         continue;
       Nodes.push_back(Op);
     }
   }
   if (!Loads)
     return false;
   Value *X = nullptr;
  ConstantRange R(1, true);
  ConstantRange BestR(1, true);
  uint64_t BestSize = UINT64_MAX;
   for (size_t NI = 0; NI < Nodes.size(); ++NI) {
     Value *N = Nodes[NI];
     if (isa<LoadInst>(N) || !N->getType()->isIntegerTy() ||
         N->getType()->getIntegerBitWidth() > 64)
       continue;
     if (auto *CB = dyn_cast<CallBase>(N)) {
       Function *CF = CB->getCalledFunction();
       if (CF && CF->isIntrinsic() &&
           (CF->getIntrinsicID() == Intrinsic::fshl || CF->getIntrinsicID() == Intrinsic::fshr) &&
           CB->getNumOperands() > 2 && CB->getArgOperand(0) == CB->getArgOperand(1) &&
           isa<ConstantInt>(CB->getArgOperand(2))) {
         Nodes.push_back(CB->getArgOperand(0));
         continue;
       }
     }
    std::set<Value *> Leaves;
    leaves(Cond, N, Leaves);
    R = LVI.getConstantRange(N, &Sw, /*UndefAllowed=*/false);
    if (R.isFullSet() || R.isEmptySet() ||
        (R.getUpper() - R.getLower()).ugt(kMaxIndices)) {
      if (auto BR = guardRange(Sw, N))
        if (R.contains(*BR))
          R = *BR;
    }
    if (!R.isFullSet() && !R.isEmptySet() && (R.getUpper() - R.getLower()).ule(kMaxIndices)) {
      uint64_t Size = (R.getUpper() - R.getLower()).getZExtValue();
      // Later candidates are deeper in the tree (nearer the index);
      // strictly-smaller ranges always win.
      if (Size < BestSize) {
        X = N;
        BestR = R;
        BestSize = Size;
      }
    }
   }
   if (!X)
     return false;
   R = BestR;
  Eval E{DL, Read, Ctx, X, APInt(64, 0)};
  std::map<uint64_t, BasicBlock *> Cases;
  APInt Lo = R.getLower();
  uint64_t N = (R.getUpper() - R.getLower()).getZExtValue();
  for (uint64_t K = 0; K < N; ++K) {
    E.FixedVal = Lo + K;
     auto T = E.eval(Cond);
     if (!T)
       return false;
    ConstantInt *C = ConstantInt::get(Sw.getContext(), *T);
    BasicBlock *Dest = Sw.findCaseValue(C)->getCaseSuccessor();
    if (Dest != Sw.getDefaultDest())
      Cases[E.FixedVal.getZExtValue()] = Dest;
  }

  // Edges per successor before and after, for the phis.
  BasicBlock *BB = Sw.getParent();
  std::map<BasicBlock *, int> Delta;
  for (BasicBlock *S : successors(&Sw))
    --Delta[S];
  // Every index in range has its case: other values cannot occur.
  // (Keep the original default: the range proof is only as good as LVI.)
  BasicBlock *Default = Sw.getDefaultDest();
  IRBuilder<> B(&Sw);
  SwitchInst *New = B.CreateSwitch(X, Default, Cases.size());
  for (auto &[V, Dest] : Cases)
    New->addCase(ConstantInt::get(cast<IntegerType>(X->getType()), V), Dest);
  for (BasicBlock *S : successors(New))
    ++Delta[S];
  for (auto &[S, D] : Delta) {
    for (PHINode &P : S->phis()) {
      Value *In = P.getIncomingValueForBlock(BB);
      for (int I = 0; I < D; ++I)
        P.addIncoming(In, BB);
      for (int I = 0; I > D; --I)
        P.removeIncomingValue(BB, /*DeletePHIIfEmpty=*/false);
    }
  }
  Sw.eraseFromParent();
  return true;
}

} // namespace

// Rewrite every table switch of `M` to switch on its index; returns how
// many.
extern "C" size_t biara_index_switches(LLVMModuleRef MRef, biara_index_read_fn Read, void *Ctx) {
  Module &M = *unwrap(MRef);
  size_t N = 0;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::vector<SwitchInst *> Switches;
    for (Instruction &I : instructions(F))
      if (auto *Sw = dyn_cast<SwitchInst>(&I))
        Switches.push_back(Sw);
    // Fresh analyses per switch: rewriting one changes what LazyValueInfo
    // knows on the edges of the others. Then a guard that a dominating `if`
    // bounds (found once the switch is on its index) kills a fully-covered
    // default.
     for (SwitchInst *Sw : Switches) {
       if (Sw->getParent() == nullptr)
         continue;
       unscale(*Sw);
       PassBuilder PB;
       FunctionAnalysisManager FAM;
       PB.registerFunctionAnalyses(FAM);
       LazyValueInfo &LVI = FAM.getResult<LazyValueAnalysis>(F);
       N += index(*Sw, LVI, F.getDataLayout(), Read, Ctx);
     }
    Switches.clear();
    for (Instruction &I : instructions(F))
      if (auto *Sw = dyn_cast<SwitchInst>(&I))
        Switches.push_back(Sw);
    for (SwitchInst *Sw : Switches) {
      unscale(*Sw);
      N += guardDefault(*Sw);
    }
  }
  return N;
}
