// Indirect call/jump resolution on lifted LLVM IR (see src/tables.rs).
//
// Each site is announced by `call void @biara.target(i64 %pc, i64 site)`.
// For every such call we look for a single non-constant value feeding %pc
// whose range at the call is bounded (LazyValueInfo: dominating compares),
// then evaluate %pc for every value in that range, reading constant memory
// (the table) through a callback into the guest image.
//
// Uses the C++ API because LazyValueInfo is not exposed through the C API.

// Range bounds come from the shared control-flow-edge refinement
// (edge_ranges.h), also used by audit argument ranges in ranges.cpp: one
// implementation, no duplicate refiner.
// Shared edge refinement (one implementation with ranges.cpp).
#include "edge_ranges.h"
#include "llvm-c/Types.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/KnownBits.h"

#include <cstdint>
#include <optional>
#include <vector>

using namespace llvm;

extern "C" {
// Read `len` bytes of guest memory at `addr`; return 0 if unmapped.
typedef int (*biara_read_fn)(void *ctx, uint64_t addr, uint8_t *buf, size_t len);
// Report one possible target of an indirect site.
typedef void (*biara_emit_fn)(void *ctx, uint64_t site, uint64_t target);
// Finish a site: 0 exhaustive, 1 residual unknown, 2 enumeration limit.
typedef void (*biara_site_fn)(void *ctx, uint64_t site, int status);
}

namespace {

constexpr unsigned kMaxDepth = 32;

struct Evaluator {
  const DataLayout &DL;
  biara_read_fn Read;
  void *ReadCtx;
  // Values fixed for the evaluation: the enumerated node, and the operands
  // of casts it is (`bind`).
  std::vector<std::pair<const Value *, APInt>> Holes;

  // Fix `V` to `X`, along with what `V` extends: a zext/sext of `Y` that
  // is `X` makes `Y` the truncation of `X`. False if no value extends to
  // `X`.
  bool bind(const Value *V, APInt X) {
    Holes.clear();
    for (;;) {
      Holes.push_back({V, X});
      auto *C = dyn_cast<CastInst>(V);
      if (!C || !(isa<ZExtInst>(C) || isa<SExtInst>(C)) || !C->getSrcTy()->isIntegerTy())
        return true;
      APInt T = X.trunc(C->getSrcTy()->getIntegerBitWidth());
      if ((isa<ZExtInst>(C) ? T.zext(X.getBitWidth()) : T.sext(X.getBitWidth())) != X)
        return false;
      V = C->getOperand(0);
      X = T;
    }
  }

  std::optional<APInt> eval(const Value *V, unsigned Depth = 0) const {
    if (Depth > kMaxDepth)
      return std::nullopt;
    for (auto &[H, X] : Holes)
      if (V == H)
        return X;
    if (auto *CI = dyn_cast<ConstantInt>(V))
      return CI->getValue();
    if (isa<ConstantPointerNull>(V))
      return APInt(DL.getPointerSizeInBits(), 0);
    auto *Op = dyn_cast<Operator>(V);
    if (!Op)
      return std::nullopt;

    switch (Op->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::Shl:
    case Instruction::LShr:
    case Instruction::AShr:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor: {
      auto A = eval(Op->getOperand(0), Depth + 1);
      auto B = eval(Op->getOperand(1), Depth + 1);
      if (!A || !B || A->getBitWidth() != B->getBitWidth())
        return std::nullopt;
      unsigned W = A->getBitWidth();
      switch (Op->getOpcode()) {
      case Instruction::Add: return *A + *B;
      case Instruction::Sub: return *A - *B;
      case Instruction::Mul: return *A * *B;
      case Instruction::Shl: return B->uge(W) ? APInt(W, 0) : A->shl(*B);
      case Instruction::LShr: return B->uge(W) ? APInt(W, 0) : A->lshr(*B);
      case Instruction::AShr: return A->ashr(B->getLimitedValue(W - 1));
      case Instruction::And: return *A & *B;
      case Instruction::Or: return *A | *B;
      default: return *A ^ *B;
      }
    }
    case Instruction::ZExt:
    case Instruction::SExt:
    case Instruction::Trunc:
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
    case Instruction::BitCast: {
      auto A = eval(Op->getOperand(0), Depth + 1);
      if (!A)
        return std::nullopt;
      Type *T = Op->getType();
      unsigned W = T->isPointerTy() ? DL.getPointerSizeInBits() : T->getScalarSizeInBits();
      if (W == 0)
        return std::nullopt;
      return Op->getOpcode() == Instruction::SExt ? A->sextOrTrunc(W) : A->zextOrTrunc(W);
    }
    case Instruction::GetElementPtr: {
      auto *GEP = cast<GEPOperator>(Op);
      auto Base = eval(GEP->getPointerOperand(), Depth + 1);
      if (!Base)
        return std::nullopt;
      APInt Off(64, 0);
      for (gep_type_iterator I = gep_type_begin(GEP), E = gep_type_end(GEP); I != E; ++I) {
        if (StructType *S = I.getStructTypeOrNull()) {
          auto *Field = dyn_cast<ConstantInt>(I.getOperand());
          if (!Field)
            return std::nullopt;
          Off += DL.getStructLayout(S)->getElementOffset(Field->getZExtValue());
          continue;
        }
        auto Idx = eval(I.getOperand(), Depth + 1);
        TypeSize Stride = I.getSequentialElementStride(DL);
        if (!Idx || Stride.isScalable())
          return std::nullopt;
        Off += Idx->sextOrTrunc(64) * APInt(64, Stride.getFixedValue());
      }
      return Base->zextOrTrunc(64) + Off;
    }
    case Instruction::ICmp: {
      auto A = eval(Op->getOperand(0), Depth + 1);
      auto B = eval(Op->getOperand(1), Depth + 1);
      if (!A || !B || A->getBitWidth() != B->getBitWidth())
        return std::nullopt;
      return APInt(1, ICmpInst::compare(*A, *B, cast<ICmpInst>(Op)->getPredicate()));
    }
    case Instruction::Select: {
      auto C = eval(Op->getOperand(0), Depth + 1);
      if (!C)
        return std::nullopt;
      return eval(Op->getOperand(C->isOne() ? 1 : 2), Depth + 1);
    }
    case Instruction::Load: {
      auto *LI = dyn_cast<LoadInst>(Op);
      if (!LI || !LI->getType()->isIntegerTy())
        return std::nullopt;
      uint64_t Size = DL.getTypeStoreSize(LI->getType());
      auto Addr = eval(LI->getPointerOperand(), Depth + 1);
      // Tables are naturally aligned; misaligned reads only come from
      // enumerating a base pointer without knowing its stride.
      if (!Addr || Size > 8 || !DL.isLittleEndian() || Addr->getZExtValue() % Size != 0)
        return std::nullopt;
      uint8_t Buf[8] = {};
      if (!Read(ReadCtx, Addr->getZExtValue(), Buf, Size))
        return std::nullopt;
      uint64_t Raw = 0;
      for (uint64_t B = 0; B < Size; ++B)
        Raw |= uint64_t(Buf[B]) << (8 * B);
      return APInt(LI->getType()->getIntegerBitWidth(), Raw);
    }
    default:
      return std::nullopt;
    }
  }

  bool closed(const Value *V) const { return eval(V).has_value(); }
};

// The chain of values from Root down to the single non-constant leaf, root
// first. Empty if more than one operand is non-constant somewhere.
std::vector<const Value *> variableChain(const Evaluator &E, const Value *Root) {
  std::vector<const Value *> Chain;
  const Value *V = Root;
  for (unsigned D = 0; D <= kMaxDepth; ++D) {
    Chain.push_back(V);
    auto *Op = dyn_cast<Operator>(V);
    if (!Op || isa<PHINode>(V) || isa<SelectInst>(V) || isa<CallBase>(V))
      return Chain;
    // A load through env (a guest register) is a leaf; a load through a
    // computed guest address (the table entry) is part of the chain.
    if (auto *LI = dyn_cast<LoadInst>(V)) {
      auto Ptr = variableChain(E, LI->getPointerOperand());
      if (!Ptr.empty() && isa<Argument>(Ptr.back()))
        return Chain;
    }
    const Value *Var = nullptr;
    for (const Use &U : Op->operands()) {
      if (E.closed(U.get()))
        continue;
      if (Var)
        return {};
      Var = U.get();
    }
    if (!Var)
      return Chain;
    V = Var;
  }
  return {};
}

unsigned widthOf(const Value *V, const DataLayout &DL) {
  Type *T = V->getType();
  return T->isPointerTy() ? DL.getPointerSizeInBits() : T->getScalarSizeInBits();
}

// Bits of `Child` (the variable operand of `Parent`) that `Parent` depends
// on, given the bits `D` of `Parent` that matter. All bits for operations
// not modelled (loads, address arithmetic, ...).
APInt childDemanded(const Evaluator &E, const Value *Parent, const Value *Child,
                    const APInt &D) {
  unsigned CW = widthOf(Child, E.DL);
  APInt All = APInt::getAllOnes(CW);
  auto *Op = dyn_cast<Operator>(Parent);
  if (!Op || !Parent->getType()->isIntegerTy() || !Child->getType()->isIntegerTy())
    return All;
  unsigned W = D.getBitWidth();
  // The constant other operand of a binary operator, if `Child` is operand 0
  // (or either operand of a commutative one).
  auto other = [&]() -> std::optional<APInt> {
    if (Op->getNumOperands() != 2)
      return std::nullopt;
    if (Op->getOperand(0) == Child)
      return E.eval(Op->getOperand(1));
    if (Instruction::isCommutative(Op->getOpcode()) && Op->getOperand(1) == Child)
      return E.eval(Op->getOperand(0));
    return std::nullopt;
  };
  switch (Op->getOpcode()) {
  case Instruction::And:
    if (auto C = other())
      return D & *C;
    return All;
  case Instruction::Or:
  case Instruction::Xor:
    return other() ? D : All;
  case Instruction::Add:
  case Instruction::Sub:
  case Instruction::Mul:
    // Carries only move upwards.
    return APInt::getLowBitsSet(W, D.getActiveBits());
  case Instruction::Shl:
  case Instruction::LShr:
  case Instruction::AShr: {
    auto S = Op->getOperand(0) == Child ? other() : std::nullopt;
    if (!S || S->uge(W))
      return All;
    unsigned N = S->getZExtValue();
    if (Op->getOpcode() == Instruction::Shl)
      return D.lshr(N);
    APInt R = D.shl(N);
    if (Op->getOpcode() == Instruction::AShr && D.countl_zero() < N)
      R.setBit(W - 1);
    return R;
  }
  case Instruction::Trunc:
    return D.zext(CW);
  case Instruction::ZExt:
    return D.trunc(CW);
  case Instruction::SExt: {
    APInt R = D.trunc(CW);
    if (D.getActiveBits() > CW)
      R.setBit(CW - 1);
    return R;
  }
  default:
    return All;
  }
}

// A branch condition and the value it has on the way somewhere.
using Conditions = std::vector<std::pair<const Value *, bool>>;

// The conditions of the branches with an edge that dominates `BB`.
Conditions pathConditions(const BasicBlock *BB, const DominatorTree &DT) {
  Conditions Out;
  for (auto *Node = DT.getNode(BB); Node; Node = Node->getIDom()) {
    auto *Br = dyn_cast<CondBrInst>(Node->getBlock()->getTerminator());
    if (!Br || Node->getBlock() == BB)
      continue;
    for (unsigned S = 0; S < 2; ++S)
      if (DT.dominates(BasicBlockEdge(Node->getBlock(), Br->getSuccessor(S)), BB))
        Out.push_back({Br->getCondition(), S == 0});
  }
  return Out;
}

// The conditions under which `P` branches to `To`.
Conditions edgeConditions(const BasicBlock *P, const BasicBlock *To, const DominatorTree &DT) {
  Conditions Out = pathConditions(P, DT);
  if (auto *Br = dyn_cast<CondBrInst>(P->getTerminator());
      Br && Br->getSuccessor(0) != Br->getSuccessor(1))
    Out.push_back({Br->getCondition(), Br->getSuccessor(0) == To});
  return Out;
}

// Those of `Conds` that only depend on what `E` binds.
Conditions closedUnder(const Evaluator &E, const Conditions &Conds) {
  Conditions Out;
  for (auto &C : Conds)
    if (E.closed(C.first))
      Out.push_back(C);
  return Out;
}

bool holds(const Evaluator &E, const Conditions &Conds) {
  for (auto [C, Want] : Conds)
    if (auto B = E.eval(C); B && B->isOne() != Want)
      return false;
  return true;
}

// Evaluate the root with `N` set to every value of `R` consistent with
// `Known`, extended (bits beyond R's width are not demanded) to N's width,
// for which the branch conditions on the way to the jump can hold: those
// that are a function of N, and for a phi N, those on the way from some
// incoming block that are a function of its incoming value. The
// conditions catch bounds LazyValueInfo cannot use, such as a flag
// computation the optimiser left as `x > 34 && x - 35 != 0`, also when
// separately bounded paths share the jump.
bool enumerateHole(Evaluator &E, Value *N, const ConstantRange &R, const KnownBits &Known,
                   const CallBase &Call, const DominatorTree &DT, const Value *Root,
                   uint64_t Site, biara_emit_fn Emit, void *EmitCtx, bool FilterConditions) {
  unsigned W = widthOf(N, E.DL);
  APInt Lo = R.getUnsignedMin(), Hi = R.getUnsignedMax();
  const unsigned RW = Lo.getBitWidth() + 1;
  const APInt Step = APInt(RW, 1) << Known.countMinTrailingZeros();
  const APInt Last = Hi.zext(RW);
  const APInt First = (Lo.zext(RW) + Step - 1) & ~(Step - 1);
  E.bind(N, Lo.zextOrTrunc(W));
  // Projected low-bit ranges do not establish the original node's high bits.
  // Zero extension is valid for Root (demanded-bit proof), but must not reject
  // candidates through conditions on those unestablished high bits.
  Conditions OfN = FilterConditions ? closedUnder(E, pathConditions(Call.getParent(), DT))
                                   : Conditions{};
  // N, or the value it extends, may be a phi: per incoming edge, the value
  // and the conditions on it.
  const PHINode *Phi = nullptr;
  size_t PhiAt = 0;
  for (; FilterConditions && PhiAt < E.Holes.size() && !Phi; ++PhiAt)
    Phi = dyn_cast<PHINode>(E.Holes[PhiAt].first);
  if (Phi)
    --PhiAt;
  std::vector<std::pair<const Value *, Conditions>> Incoming;
  if (Phi)
    for (unsigned I = 0; I < Phi->getNumIncomingValues(); ++I) {
      const Value *In = Phi->getIncomingValue(I);
      E.bind(In, APInt(Phi->getType()->getIntegerBitWidth(), 0));
      Incoming.push_back(
          {In, closedUnder(E, edgeConditions(Phi->getIncomingBlock(I), Phi->getParent(), DT))});
    }
  bool Complete = true;
  for (APInt Candidate = First; Candidate.ule(Last); Candidate += Step) {
    APInt V = Candidate.trunc(Lo.getBitWidth());
    if (R.contains(V) && !(V & Known.Zero) && !(~V & Known.One)) {
      APInt X = V.zextOrTrunc(W);
      bool Feasible = E.bind(N, X);
      if (Feasible && Phi) {
        APInt PX = E.Holes[PhiAt].second;
        Feasible = false;
        for (auto &[In, Conds] : Incoming) {
          if (auto *C = dyn_cast<ConstantInt>(In)) {
            Feasible = C->getValue() == PX;
          } else {
            Feasible = E.bind(In, PX) && holds(E, Conds);
          }
          if (Feasible)
            break;
        }
        E.bind(N, X);
      }
      if (Feasible && holds(E, OfN)) {
        if (auto T = E.eval(Root))
          Emit(EmitCtx, Site, T->getZExtValue());
        else
          Complete = false;
      }
    }
  }
  return Complete;
}

int resolveSite(CallBase &Call, LazyValueInfo &LVI, const DominatorTree &DT,
                biara::EdgeRanges &Edges, const DataLayout &DL, biara_read_fn Read,
                void *ReadCtx, uint64_t MaxEntries, biara_emit_fn Emit, void *EmitCtx) {
  auto *SiteC = dyn_cast<ConstantInt>(Call.getArgOperand(1));
  if (!SiteC)
    return 1;
  uint64_t Site = SiteC->getZExtValue();
  Value *Root = Call.getArgOperand(0);
  Evaluator E{DL, Read, ReadCtx, {}};

  if (auto Direct = E.eval(Root)) {
    Emit(EmitCtx, Site, Direct->getZExtValue());
    return 0;
  }
  auto Chain = variableChain(E, Root);
  if (Chain.empty())
    return 1;
  // Bits of each node the target depends on, root first.
  std::vector<APInt> Demanded{APInt::getAllOnes(widthOf(Root, DL))};
  for (size_t I = 1; I < Chain.size(); ++I)
    Demanded.push_back(childDemanded(E, Chain[I - 1], Chain[I], Demanded[I - 1]));

  auto span = [](const ConstantRange &R) {
    unsigned W = R.getBitWidth() + 1;
    return R.getUnsignedMax().zext(W) - R.getUnsignedMin().zext(W) + 1;
  };
  // Enumerate the node with the fewest candidate values: its range, thinned
  // by known-zero low bits (a scaled index only takes multiples of its
  // stride). Ties go to the deepest node, which keeps the table's stride.
  struct Pick {
    Value *Node;
    const Value *Bound; // N itself, or a value holding N's low bits
    ConstantRange R;
    KnownBits Known;
    uint64_t Count;
  };
  std::optional<Pick> Pick_;
  bool Limited = false;
  for (size_t I = Chain.size(); I-- > 0;) {
    Value *N = const_cast<Value *>(Chain[I]);
    if (!N->getType()->isIntegerTy())
      continue;
    // N's own range, and when the target only depends on N's low bits, the
    // range of a value holding just those bits (`trunc N` or
    // `and N, 2^w-1`: a byte or 32-bit compare on a 64-bit register).
    auto consider = [&](const Value *V) {
      ConstantRange R = LVI.getConstantRange(const_cast<Value *>(V), &Call,
                                             /*UndefAllowed=*/false);
      // Same shared refinement as audit argument ranges: edge facts reaching
      // the site narrow LVI's baseline (branch-derived arithmetic bounds,
      // correlated low-bit conditions). Never widens; refinement failures
      // keep the baseline below, preserving completeness semantics.
      R = Edges.refine(const_cast<Value *>(V), &Call, R);
      KnownBits Known = computeKnownBits(V, DL, nullptr, &Call, &DT);
      if (R.isEmptySet())
        return;
      APInt Step = APInt(R.getBitWidth() + 1, 1) << Known.countMinTrailingZeros();
      uint64_t Count = ((span(R) + Step - 1).lshr(Known.countMinTrailingZeros())).getLimitedValue();
      if (Count > MaxEntries) {
        Limited = true;
        return;
      }
      if (!Pick_ || Count < Pick_->Count)
        Pick_ = Pick{N, V, R, Known, Count};
    };
    consider(N);
    unsigned Needed = Demanded[I].getActiveBits();
    for (User *U : N->users()) {
      unsigned Low = 0;
      if (auto *T = dyn_cast<TruncInst>(U)) {
        Low = T->getType()->getScalarSizeInBits();
      } else if (auto *A = dyn_cast<BinaryOperator>(U);
                 A && A->getOpcode() == Instruction::And && A->getOperand(0) == N) {
        if (auto *M = dyn_cast<ConstantInt>(A->getOperand(1)); M && M->getValue().isMask())
          Low = M->getValue().countr_one();
      }
      auto *UI = dyn_cast<Instruction>(U);
      if (Low && Low >= Needed && UI && DT.dominates(UI, &Call))
        consider(UI);
    }
  }
  if (Pick_)
    return enumerateHole(E, Pick_->Node, Pick_->R, Pick_->Known, Call, DT,
                         Root, Site, Emit, EmitCtx, Pick_->Node == Pick_->Bound) ? 0 : 1;
  return Limited ? 2 : 1;
}

} // namespace

extern "C" size_t biara_indirect_targets(LLVMValueRef Fn, const char *Marker, biara_read_fn Read,
                                       void *ReadCtx, uint64_t MaxEntries, biara_emit_fn Emit,
                                       void *EmitCtx, biara_site_fn Finish) {
  Function *F = unwrap<Function>(Fn);
  if (F->isDeclaration())
    return 0;
  std::vector<CallBase *> Sites;
  for (Instruction &I : instructions(*F))
    if (auto *CB = dyn_cast<CallBase>(&I))
      if (Function *Callee = CB->getCalledFunction(); Callee && Callee->getName() == Marker)
        Sites.push_back(CB);
  if (Sites.empty())
    return 0;

  PassBuilder PB;
  FunctionAnalysisManager FAM;
  PB.registerFunctionAnalyses(FAM);
  LazyValueInfo &LVI = FAM.getResult<LazyValueAnalysis>(*F);
  const DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(*F);
  const DataLayout &DL = F->getDataLayout();
  // One shared batch for every site in the function (same contract as
  // ranges.cpp): per-function state is built once, never per operand.
  biara::EdgeRanges Edges(LVI, DT);
  for (CallBase *CB : Sites) {
    int Status = resolveSite(*CB, LVI, DT, Edges, DL, Read, ReadCtx, MaxEntries, Emit, EmitCtx);
    if (auto *Site = dyn_cast<ConstantInt>(CB->getArgOperand(1)))
      Finish(EmitCtx, Site->getZExtValue(), Status);
  }
  return Sites.size();
}
