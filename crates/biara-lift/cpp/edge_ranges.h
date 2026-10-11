// Bounded control-flow-edge range refinement shared by audit argument
// ranges (cpp/ranges.cpp, see src/calls.rs) and indirect-target bounds
// (cpp/jump_tables.cpp, see src/tables.rs).
//
// Baseline queries ask LazyValueInfo for the range of a value at one
// instruction. LVI answers from dominating comparisons, but misses facts the
// lifted IR commonly leaves behind: constraints on a value feeding an
// arithmetic operand (`x < 10` before `y = x + 1`), or switch-case membership
// of a compared operand. This header refines exactly one baseline range per
// query with facts read off the CFG edges that must have executed to reach
// the query context. It never widens the baseline: intersections that come
// back empty keep the baseline, and every walk carries a hard budget whose
// exhaustion falls back to the baseline range.
//
// Soundness contract (callers rely on this; keep it):
// - A range is only narrowed by an edge whose branch/switch outcome provably
//   held on every path to the query block (edge-dominance). Facts from one
//   arm of a disjunction therefore never leak into a join: when no single
//   in-edge dominates, only branches dominating the whole join apply, and
//   each of those holds on all paths.
// - Expression transfer is width-correct LLVM wrap arithmetic on
//   ConstantRange (add/sub/mul/and/or/xor/shl/lshr/ashr/zext/sext/trunc).
//   Signed predicates use makeExactICmpRegion at the operand width, so a
//   narrow signed comparison keeps its wrapped set rather than a guessed
//   contiguous bound. Unmodelled operations (div/rem, loads, calls, GEPs,
//   ...) stop the walk with the incoming range.
// - Joins hull (union) incoming ranges: one feasible predecessor suffices.
//   Disjoint alternatives are never intersected together.
// - Boolean phis hull the constraints of every feasible incoming outcome.
//   A constant-false arm cannot reach a true branch, but an unconstrained
//   feasible arm widens the result. Rotated loop-header facts are rejected.
// - Loops get a single hull pass over the phi arms (the back edge recurses
//   with a halved depth, so nesting terminates); a loop that keeps growing
//   hulls to the baseline instead of spinning. No fixpoint iteration.
// - No Cartesian products, no path enumeration, no correlation of two
//   varying operands: correlated facts only refine the single queried chain.
// - The refined set must sit inside the baseline, else the edge walk
//   overreached and the baseline stands.
//
// Performance contract (large CFGs: tens of thousands of blocks, many
// - Build one EdgeRanges per function per query batch and reuse it for every
//   value queried in that function. The dominator tree and LVI handle are
//   shared; per-query state is a small cache plus bounded walks.
// - Never walk the whole CFG per operand: the context walk climbs at most
//   kEdgeRangeDepth dominator levels, expression walks halve their depth per
//   nesting level, and a shared instruction budget caps everything.

#ifndef BIARA_EDGE_RANGES_H
#define BIARA_EDGE_RANGES_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Function.h"

#include <cstdint>
#include <optional>

namespace biara {

namespace detail {
// Dominator levels climbed per query; expression-walk nesting depth.
constexpr unsigned kEdgeRangeDepth = 24;
// Instructions/edges touched per top-level query across all helpers.
constexpr unsigned kEdgeRangeVisits = 256;
// Distinct phi arms given exact ranges before the rest hull to unknown.
constexpr unsigned kEdgeRangeJoinPaths = 8;
} // namespace detail

// Reusable per-function refinement state for one batch of range queries.
// Owns no IR: the function, LVI and dominator tree must outlive the batch.
class EdgeRanges {
public:
  EdgeRanges(llvm::LazyValueInfo &LVI, const llvm::DominatorTree &DT) : LVI(LVI), DT(DT) {
    auto *Root = DT.getRoot();
    if (!Root)
      return;
    auto *F = Root->getParent();
    SinglePred.reserve(F->size());
    // One CFG-edge pass per batch, not a predecessor/user scan per query.
    for (auto &From : *F)
      for (auto *To : llvm::successors(&From)) {
        auto [It, Inserted] = SinglePred.try_emplace(To, &From);
        if (!Inserted)
          It->second = nullptr;
      }
  }

  // Refine `Base` (the baseline LVI range of `V` at `Ctx`) with edge facts
  // that must hold where `Ctx` runs. Returns the intersection when it is
  // non-empty and strictly inside the baseline, else `Base`.
  llvm::ConstantRange refine(llvm::Value *V, llvm::Instruction *Ctx, const llvm::ConstantRange &Base);

private:
  llvm::LazyValueInfo &LVI;
  const llvm::DominatorTree &DT;
  // Lookup-only cache: pointer hashing cannot affect traversal or output order.
  // Cap retained state for large functions; uncached queries remain bounded.
  llvm::DenseMap<std::pair<llvm::Value *, llvm::Instruction *>, llvm::ConstantRange> Cache;
  static constexpr unsigned kCacheEntries = 8192;
  llvm::DenseMap<llvm::BasicBlock *, llvm::BasicBlock *> SinglePred;

  std::optional<llvm::ConstantRange> cached(llvm::Value *V, llvm::Instruction *Ctx);
  void remember(llvm::Value *V, llvm::Instruction *Ctx, const llvm::ConstantRange &R);
  llvm::ConstantRange rangeOf(llvm::Value *V, llvm::Instruction *Ctx, unsigned Depth,
                              unsigned &Budget);
  llvm::ConstantRange transferOver(llvm::Instruction *I, llvm::Instruction *Ctx,
                                   unsigned Depth, unsigned &Budget);
  // Bound `and(X, Want)` from a dominating sibling `and(X, Have)` fact.
  // When the free bits form a low-bit mask, round a contiguous `[0, H)`
  // region up to their tile size. This includes every possible masked
  // value, including `Have == 0` comparisons. Wrapped/gapped regions and
  // budget exhaustion stay conservative; no values are enumerated.
  llvm::ConstantRange maskedRangeFor(llvm::Value *X, const llvm::APInt &Want,
                                     llvm::Instruction *Ctx, unsigned Depth,
                                     unsigned &Budget);
  static std::optional<llvm::ConstantRange> maskedRegion(const llvm::APInt &Want,
      const llvm::APInt &Have, const llvm::ConstantRange &Region);
  std::optional<llvm::ConstantRange> conditionRangeFor(llvm::Value *V, llvm::Value *Cond,
      bool Taken, unsigned Depth, unsigned &Budget);
  // Range of `V` implied by taking edge `From -> To`, or nullopt when the
  // edge condition says nothing about `V`.
  std::optional<llvm::ConstantRange> edgeRangeFor(llvm::Value *V, llvm::BasicBlock *From,
                                                llvm::BasicBlock *To, unsigned &Budget);
  // Intersect `R` with what must hold on entry to `BB` (branch/switch edges
  // dominating `BB`, found by climbing the dominator tree).
  llvm::ConstantRange applyContextFacts(llvm::Value *V, llvm::BasicBlock *BB,
                                        const llvm::ConstantRange &R, unsigned &Budget);
};

// --- inline implementation (header-only; build.rs tracks this header
// alongside the two consuming cpp units) ---

inline std::optional<llvm::ConstantRange> EdgeRanges::cached(llvm::Value *V,
                                                             llvm::Instruction *Ctx) {
  auto It = Cache.find({V, Ctx});
  if (It != Cache.end())
    return It->second;
  return std::nullopt;
}

inline void EdgeRanges::remember(llvm::Value *V, llvm::Instruction *Ctx,
                                 const llvm::ConstantRange &R) {
  auto It = Cache.find({V, Ctx});
  if (It != Cache.end())
    It->second = R;
  else if (Cache.size() < kCacheEntries)
    Cache.try_emplace({V, Ctx}, R);
}

inline std::optional<llvm::ConstantRange>
EdgeRanges::maskedRegion(const llvm::APInt &Want, const llvm::APInt &Have,
                         const llvm::ConstantRange &Region) {
  if (Want.getBitWidth() != Have.getBitWidth() ||
      Region.getBitWidth() != Want.getBitWidth() || Region.isEmptySet() ||
      Region.isFullSet() || Region.isWrappedSet() || !Region.getLower().isZero())
    return std::nullopt;
  llvm::APInt Free = Want & ~Have;
  llvm::APInt Stride = Free + 1;
  if (!Stride.isPowerOf2())
    return std::nullopt;
  // Have clears every free low bit, so round the strict upper bound to
  // the next tile. Use one extra bit to detect a full-width overflow.
  unsigned W = Want.getBitWidth();
  llvm::APInt Upper = (Region.getUpper().zext(W + 1) + Free.zext(W + 1)) & ~Free.zext(W + 1);
  if (Upper.getActiveBits() > W)
    return std::nullopt;
  return llvm::ConstantRange(llvm::APInt(W, 0), Upper.trunc(W));
}

inline std::optional<llvm::ConstantRange>
EdgeRanges::conditionRangeFor(llvm::Value *V, llvm::Value *Cond, bool Taken,
                              unsigned Depth, unsigned &Budget) {
  using namespace llvm;
  if (Depth == 0 || Budget == 0 || !V->getType()->isIntegerTy())
    return std::nullopt;
  --Budget;
  unsigned W = V->getType()->getIntegerBitWidth();
  if (Cond == V)
    return ConstantRange::makeExactICmpRegion(Taken ? CmpInst::ICMP_NE : CmpInst::ICMP_EQ,
                                             APInt(W, 0));
  if (auto *Cast = dyn_cast<CastInst>(Cond))
    if (isa<ZExtInst>(Cast) || isa<SExtInst>(Cast))
      return conditionRangeFor(V, Cast->getOperand(0), Taken, Depth / 2, Budget);
  if (auto *Phi = dyn_cast<PHINode>(Cond)) {
    // A boolean phi can select a condition that was proved on just one
    // incoming path. Discard only outcomes impossible for this boolean,
    // and hull the constraints of every remaining path. Reject rotated
    // loop-header facts about a value defined in that same header.
    if (auto *I = dyn_cast<Instruction>(V))
      if (I->getParent() == Phi->getParent() || !DT.dominates(I, Phi))
        return std::nullopt;
    if (Phi->getNumIncomingValues() > detail::kEdgeRangeJoinPaths)
      return std::nullopt;
    std::optional<ConstantRange> Out;
    for (Value *In : Phi->incoming_values()) {
      if (Budget == 0)
        return std::nullopt;
      --Budget;
      if (auto *C = dyn_cast<ConstantInt>(In)) {
        if (C->isZero() == Taken)
          continue;
        return std::nullopt;
      }
      auto Arm = conditionRangeFor(V, In, Taken, Depth / 2, Budget);
      if (!Arm)
        return std::nullopt;
      Out = Out ? Out->unionWith(*Arm) : *Arm;
    }
    return Out;
  }
  if (auto *Cmp = dyn_cast<ICmpInst>(Cond)) {
    for (unsigned K = 0; K < 2; ++K) {
      Value *Lhs = Cmp->getOperand(K);
      auto *C = dyn_cast<ConstantInt>(Cmp->getOperand(1 - K));
      if (!C)
        continue;
      CmpInst::Predicate Pred = Cmp->getPredicate();
      if (K == 1)
        Pred = CmpInst::getSwappedPredicate(Pred);
      if (!Taken)
        Pred = CmpInst::getInversePredicate(Pred);
      ConstantRange Region = ConstantRange::makeExactICmpRegion(Pred, C->getValue());
      if (Lhs == V)
        return Region;
      auto *Want = dyn_cast<BinaryOperator>(V);
      auto *Have = dyn_cast<BinaryOperator>(Lhs);
      if (Want && Have && Want->getOpcode() == Instruction::And &&
          Have->getOpcode() == Instruction::And &&
          Want->getOperand(0) == Have->getOperand(0)) {
        auto *WantC = dyn_cast<ConstantInt>(Want->getOperand(1));
        auto *HaveC = dyn_cast<ConstantInt>(Have->getOperand(1));
        if (WantC && HaveC)
          return maskedRegion(WantC->getValue(), HaveC->getValue(), Region);
      }
      if (C->isZero() && (Pred == CmpInst::ICMP_EQ || Pred == CmpInst::ICMP_NE))
        return conditionRangeFor(V, Lhs, Pred == CmpInst::ICMP_NE, Depth / 2, Budget);
    }
  }
  return std::nullopt;
}

inline std::optional<llvm::ConstantRange>
EdgeRanges::edgeRangeFor(llvm::Value *V, llvm::BasicBlock *From, llvm::BasicBlock *To,
                         unsigned &Budget) {
  using namespace llvm;
  Instruction *Term = From->getTerminator();
  if (auto *Br = dyn_cast<CondBrInst>(Term)) {
    if (Br->getSuccessor(0) == Br->getSuccessor(1))
      return std::nullopt;
    bool Taken = Br->getSuccessor(0) == To;
    if (!Taken && Br->getSuccessor(1) != To)
      return std::nullopt;
    return conditionRangeFor(V, Br->getCondition(), Taken, detail::kEdgeRangeDepth, Budget);
  }
  if (auto *Sw = dyn_cast<SwitchInst>(Term)) {
    Value *Cond = Sw->getCondition();
    if (Cond != V || !V->getType()->isIntegerTy())
      return std::nullopt;
    unsigned W = V->getType()->getIntegerBitWidth();
    if (W == 0 || W > 64)
      return std::nullopt;
    const bool IsDefault = Sw->getDefaultDest() == To;
    ConstantRange Found(W, /*isFullSet=*/true);
    bool Any = false;
    for (auto &C : Sw->cases()) {
      if (Budget == 0)
        return std::nullopt;
      --Budget;
      if (IsDefault && C.getCaseSuccessor() == To)
        return std::nullopt;
      if (!IsDefault && C.getCaseSuccessor() != To)
        continue;
      ConstantRange Single(C.getCaseValue()->getValue());
      Found = Any ? Found.unionWith(Single) : Single;
      Any = true;
    }
    if (!Any)
      return std::nullopt;
    if (!IsDefault)
      return Found;
    // Only invert an exact case union; sparse hull gaps are reachable.
    if (Found.isFullSet() ||
        (Found.getUpper() - Found.getLower()).getZExtValue() != Sw->getNumCases())
      return std::nullopt;
    return Found.inverse();
  }
  return std::nullopt;
}
inline llvm::ConstantRange EdgeRanges::maskedRangeFor(llvm::Value *X, const llvm::APInt &Want,
                                                      llvm::Instruction *Ctx, unsigned Depth,
                                                      unsigned &Budget) {
  using namespace llvm;
  unsigned W = X->getType()->isIntegerTy() ? X->getType()->getIntegerBitWidth() : 0;
  ConstantRange Full = W && W <= 64 ? ConstantRange(W, /*isFullSet=*/true)
                                    : ConstantRange(64, /*isFullSet=*/true);
  if (W == 0 || W > 64 || !Ctx || Depth == 0 || Budget == 0 || Want.getBitWidth() != W)
    return Full;
  BasicBlock *BB = Ctx->getParent();
  if (!BB)
    return Full;
  // Climb the dominator tree exactly like applyContextFacts: every outgoing
  // edge that itself dominates BB took a known outcome on all paths to BB.
  using DomTreeNode = llvm::DomTreeNodeBase<llvm::BasicBlock>;
  DomTreeNode *Node = DT.getNode(BB);
  for (unsigned Step = 0; Step < detail::kEdgeRangeDepth && Node && Budget > 0;
       Node = Node->getIDom(), ++Step) {
    llvm::BasicBlock *B = Node->getBlock();
    if (B == BB)
      continue;
    Instruction *T = B->getTerminator();
    if (!isa<CondBrInst>(T) && !isa<SwitchInst>(T))
      continue;
    for (BasicBlock *S : successors(B)) {
      if (Budget == 0)
        break;
      --Budget;
      auto Pred = SinglePred.find(S);
      if (Pred == SinglePred.end() || Pred->second != B || !DT.dominates(S, BB))
        continue;
      Instruction *Term = B->getTerminator();
      auto *Br = dyn_cast<CondBrInst>(Term);
      if (!Br || Br->getSuccessor(0) == Br->getSuccessor(1))
        continue;
      bool Taken = Br->getSuccessor(0) == S;
      if (!Taken && Br->getSuccessor(1) != S)
        continue;
      auto *Cmp = dyn_cast<ICmpInst>(Br->getCondition());
      if (!Cmp)
        continue;
      for (unsigned K = 0; K < 2; ++K) {
        Value *Lhs = Cmp->getOperand(K);
        Value *Rhs = Cmp->getOperand(1 - K);
        auto *C = dyn_cast<ConstantInt>(Rhs);
        auto *Mask = dyn_cast<Instruction>(Lhs);
        if (!C || !Mask || Mask->getOpcode() != Instruction::And)
          continue;
        Value *Base = Mask->getOperand(0);
        auto *HaveC = dyn_cast<ConstantInt>(Mask->getOperand(1));
        if (Base != X || !HaveC || HaveC->getType()->getIntegerBitWidth() != W)
          continue;
        CmpInst::Predicate Pred = Cmp->getPredicate();
        if (K == 1)
          Pred = CmpInst::getSwappedPredicate(Pred);
        if (!Taken)
          Pred = CmpInst::getInversePredicate(Pred);
        if (Pred == CmpInst::BAD_ICMP_PREDICATE)
          continue;
        if (Budget == 0)
          return Full;
        --Budget;
        ConstantRange R = ConstantRange::makeExactICmpRegion(Pred, C->getValue());
        if (auto Bound = maskedRegion(Want, HaveC->getValue(), R))
          return *Bound;
      }
    }
  }
  return Full;
}


inline llvm::ConstantRange EdgeRanges::transferOver(llvm::Instruction *I, llvm::Instruction *Ctx,
                                                   unsigned Depth, unsigned &Budget) {
  using namespace llvm;
  unsigned W = I->getType()->isIntegerTy() ? I->getType()->getIntegerBitWidth() : 0;
  ConstantRange Full = W && W <= 64 ? ConstantRange(W, /*isFullSet=*/true)
                                    : ConstantRange(64, /*isFullSet=*/true);
  if (W == 0 || W > 64 || Depth == 0 || Budget == 0)
    return Full;
  --Budget;
  // The expression may be hoisted before its guard; operand facts must be
  // read where the result is used, not where the operation was defined.
  // Depth and visit caps terminate recursive expressions and back edges.
  auto operandRange = [&](Value *V) -> ConstantRange {
    if (auto *C = dyn_cast<ConstantInt>(V))
      return ConstantRange(C->getValue());
    if (!V->getType()->isIntegerTy() || V->getType()->getIntegerBitWidth() > 64)
      return Full;
    if (auto *Op = dyn_cast<Instruction>(V)) {
      if (Op->getParent() && DT.dominates(Op, Ctx))
        return rangeOf(V, Ctx, Depth / 2, Budget);
      return ConstantRange(V->getType()->getIntegerBitWidth(), /*isFullSet=*/true);
    }
    // Arguments also inherit the use context's dominating edge facts.
    return rangeOf(V, Ctx, Depth / 2, Budget);
  };
  switch (I->getOpcode()) {
  case Instruction::Add:
    return operandRange(I->getOperand(0)).add(operandRange(I->getOperand(1)));
  case Instruction::Sub:
    return operandRange(I->getOperand(0)).sub(operandRange(I->getOperand(1)));
  case Instruction::Mul:
    return operandRange(I->getOperand(0)).multiply(operandRange(I->getOperand(1)));
  case Instruction::And: {
    ConstantRange Direct =
        operandRange(I->getOperand(0)).binaryAnd(operandRange(I->getOperand(1)));
    // `and` of a shifted/xored value with a constant mask: distribute the
    // mask to the shifted/xored core (`and(shl(X,c),M) = shl(and(X,M>>c),c)`,
    // `and(xor(X,c),M) = xor(and(X,M),c&M)`, both exact bitwise identities),
    // then bound the core mask from a sibling guard `and(X, Have)` when it
    // tiles exactly (see maskedRangeFor). Intersect-only: an empty or full
    // alternate keeps the direct transfer.
    if (Depth > 0 && Budget > 0) {
      for (unsigned K = 0; K < 2; ++K) {
        Value *A = I->getOperand(K), *B = I->getOperand(1 - K);
        auto *MC = dyn_cast<ConstantInt>(B);
        auto *Core = dyn_cast<Instruction>(A);
        if (!MC || !Core || MC->getType()->getIntegerBitWidth() != W)
          continue;
        APInt M = MC->getValue();
        if (Core->getOpcode() == Instruction::Shl) {
          auto *Amt = dyn_cast<ConstantInt>(Core->getOperand(1));
          Value *X = Core->getOperand(0);
          if (!Amt || !X->getType()->isIntegerTy() ||
              X->getType()->getIntegerBitWidth() != W)
            continue;
          uint64_t S = Amt->getValue().getZExtValue();
          if (S >= W)
            continue;
          APInt Cw = M.lshr(S);
          if ((M & (Cw.shl(S))) != M)
            continue;
          ConstantRange CoreR = maskedRangeFor(X, Cw, Ctx, Depth / 2, Budget);
          if (CoreR.isFullSet() || CoreR.isEmptySet())
            continue;
          ConstantRange Alt = CoreR.shl(ConstantRange(APInt(W, S)));
          ConstantRange Both = Direct.intersectWith(Alt);
          if (!Both.isEmptySet())
            return Both;
        } else if (Core->getOpcode() == Instruction::Xor) {
          for (unsigned J = 0; J < 2; ++J) {
            Value *X = Core->getOperand(J);
            auto *CC = dyn_cast<ConstantInt>(Core->getOperand(1 - J));
            if (!CC || !X->getType()->isIntegerTy() ||
                X->getType()->getIntegerBitWidth() != W)
              continue;
            APInt Cw = M;
            APInt Cst = CC->getValue() & M;
            ConstantRange CoreR = maskedRangeFor(X, Cw, Ctx, Depth / 2, Budget);
            if (CoreR.isFullSet() || CoreR.isEmptySet())
              continue;
            ConstantRange Alt = CoreR.binaryXor(ConstantRange(Cst));
            ConstantRange Both = Direct.intersectWith(Alt);
            if (!Both.isEmptySet())
              return Both;
          }
        }
      }
    }
    return Direct;
  }
  case Instruction::Or:
    return operandRange(I->getOperand(0)).binaryOr(operandRange(I->getOperand(1)));
  case Instruction::Xor:
    return operandRange(I->getOperand(0)).binaryXor(operandRange(I->getOperand(1)));
  case Instruction::Shl:
    return operandRange(I->getOperand(0)).shl(operandRange(I->getOperand(1)));
  case Instruction::LShr:
    return operandRange(I->getOperand(0)).lshr(operandRange(I->getOperand(1)));
  case Instruction::AShr:
    return operandRange(I->getOperand(0)).ashr(operandRange(I->getOperand(1)));
  case Instruction::Trunc:
  case Instruction::ZExt:
  case Instruction::SExt: {
    Instruction::CastOps Op = I->getOpcode() == Instruction::Trunc ? Instruction::Trunc
                             : I->getOpcode() == Instruction::ZExt ? Instruction::ZExt
                                                                   : Instruction::SExt;
    return operandRange(I->getOperand(0)).castOp(Op, W);
  }
  case Instruction::Select: {
    ConstantRange Arms[2] = {operandRange(I->getOperand(1)), operandRange(I->getOperand(2))};
    for (unsigned K = 0; K < 2; ++K)
      if (auto Bound = conditionRangeFor(I->getOperand(K + 1), I->getOperand(0),
                                         K == 0, Depth, Budget))
        Arms[K] = Arms[K].intersectWith(*Bound);
    return Arms[0].unionWith(Arms[1]);
  }
  case Instruction::PHI: {
    // Every feasible incoming value contributes to the hull. In particular,
    // never drop loop back edges: a bounded recursive query widens on cycles.
    auto *Phi = cast<PHINode>(I);
    ConstantRange Out(W, /*isFullSet=*/true);
    bool First = true;
    unsigned Arms = 0;
    for (unsigned K = 0, E = Phi->getNumIncomingValues(); K < E; ++K) {
      if (Budget == 0)
        return Full;
      --Budget;
      BasicBlock *Blk = Phi->getIncomingBlock(K);
      if (!DT.isReachableFromEntry(Blk))
        continue;
      if (++Arms > detail::kEdgeRangeJoinPaths)
        return Full;
      Value *In = Phi->getIncomingValue(K);
      ConstantRange Arm(W, /*isFullSet=*/true);
      if (!isa<Instruction>(In) || DT.dominates(cast<Instruction>(In), Blk->getTerminator())) {
        Arm = rangeOf(In, Blk->getTerminator(), Depth / 2, Budget);
        if (auto ER = edgeRangeFor(In, Blk, Phi->getParent(), Budget))
          Arm = Arm.intersectWith(ER->zextOrTrunc(W));
      }
      if (Arm.isEmptySet())
        continue;
      if (Arm.isFullSet())
        return Full;
      Out = First ? Arm : Out.unionWith(Arm);
      First = false;
    }
    return First ? Full : Out;
  }
  default:
    // Loads, calls, divisions/remainders, GEPs, inttoptr: unmodelled, keep
    // the incoming range (callers intersect with the baseline).
    return Full;
  }
}

inline llvm::ConstantRange EdgeRanges::applyContextFacts(llvm::Value *V, llvm::BasicBlock *BB,
                                                         const llvm::ConstantRange &R,
                                                         unsigned &Budget) {
  using namespace llvm;
  ConstantRange Out = R;
  // Climb the dominator tree from the query block. For each dominating
  // block, every outgoing edge that itself dominates BB took a known outcome
  // on all paths to BB, so its condition refines V. Joins contribute only
  // what dominates the whole join: facts from one arm of a disjunction never
  // leak in. Capped: dominator chains in huge CFGs stay bounded work.
  using DomTreeNode = llvm::DomTreeNodeBase<llvm::BasicBlock>;
  DomTreeNode *Node = DT.getNode(const_cast<llvm::BasicBlock *>(BB));
  for (unsigned Step = 0; Step < detail::kEdgeRangeDepth && Node && Budget > 0;
       Node = Node->getIDom(), ++Step) {
    llvm::BasicBlock *B = Node->getBlock();
    if (B == BB)
      continue; // BB's own terminator runs after any query inside it.
    Instruction *T = B->getTerminator();
    if (!isa<CondBrInst>(T) && !isa<SwitchInst>(T))
      continue;
    for (BasicBlock *S : successors(B)) {
      if (Budget == 0)
        break;
      --Budget;
      // A unique incoming edge plus block dominance is a sufficient proof;
      // general edge dominance scans arbitrary predecessor/user lists.
      auto Pred = SinglePred.find(S);
      if (Pred == SinglePred.end() || Pred->second != B || !DT.dominates(S, BB))
        continue;
      auto ER = edgeRangeFor(V, B, S, Budget);
      if (!ER)
        continue;
      ConstantRange I = Out.intersectWith(ER->zextOrTrunc(R.getBitWidth()));
      // An empty intersection contradicts the baseline (an unreachable
      // corner): keep the baseline rather than inventing emptiness at a
      // reachable query.
      if (!I.isEmptySet())
        Out = I;
    }
  }
  return Out;
}

inline llvm::ConstantRange EdgeRanges::rangeOf(llvm::Value *V, llvm::Instruction *Ctx,
                                               unsigned Depth, unsigned &Budget) {
  using namespace llvm;
  unsigned W = V->getType()->isIntegerTy() ? V->getType()->getIntegerBitWidth() : 0;
  ConstantRange Full = W && W <= 64 ? ConstantRange(W, /*isFullSet=*/true)
                                    : ConstantRange(64, /*isFullSet=*/true);
  if (W == 0 || W > 64 || !Ctx || Depth == 0 || Budget == 0)
    return Full;
  if (auto C = cached(V, Ctx))
    return C->zextOrTrunc(W);
  if (auto *CI = dyn_cast<ConstantInt>(V)) {
    ConstantRange R(CI->getValue());
    remember(V, Ctx, R);
    return R;
  }
  // Baseline at the query context (UndefAllowed=false matches both
  // callers' existing queries).
  ConstantRange Base = LVI.getConstantRange(V, Ctx, /*UndefAllowed=*/false);
  if (Base.getBitWidth() != W)
    Base = Base.zextOrTrunc(W);
  if (Base.isEmptySet() || Budget == 0) {
    // LVI reports empty for provably-unreachable contexts; callers treat
    // empty as "no fact", so keep it as-is without further work.
    remember(V, Ctx, Base);
    return Base;
  }
  --Budget;
  ConstantRange Narrowed = Base;
  if (auto *I = dyn_cast<Instruction>(V)) {
    // Defined value: transfer operand ranges over the operation, then apply
    // dominating edge facts at the query context. Loops get a single hull
    // pass (the back edge recurses with halved depth, so nesting
    // terminates); a loop that keeps growing hulls toward the baseline.
    Narrowed = transferOver(I, Ctx, Depth, Budget);
    Narrowed = applyContextFacts(V, Ctx->getParent(), Narrowed, Budget);
  } else {
    // Arguments, globals: no transfer; only edge facts at the query context
    // (the `if (n < B) ... use(n)` audit shape).
    Narrowed = applyContextFacts(V, Ctx->getParent(), Base, Budget);
  }
  // Correlated operands: transfer hulls select/phi arms and reads other
  // operands at baseline, so Narrowed over-approximates; intersect with the
  // baseline (never widen) and keep the baseline on contradiction.
  ConstantRange I2 = Base.intersectWith(Narrowed.zextOrTrunc(Base.getBitWidth()));
  Narrowed = I2.isEmptySet() ? Base : I2;
  remember(V, Ctx, Narrowed);
  return Narrowed;
}

inline llvm::ConstantRange EdgeRanges::refine(llvm::Value *V, llvm::Instruction *Ctx,
                                              const llvm::ConstantRange &Base) {
  using namespace llvm;
  if (!V || !V->getType()->isIntegerTy() || V->getType()->getIntegerBitWidth() > 64 || !Ctx)
    return Base;
  unsigned W = V->getType()->getIntegerBitWidth();
  if (Base.getBitWidth() != W)
    return Base;
  if (Base.isEmptySet())
    return Base;
  // The value must be available at the query: a fact about an instruction
  // that does not dominate the context is meaningless there.
  if (auto *I = dyn_cast<Instruction>(V))
    if (I->getParent() && !DT.dominates(I, Ctx))
      return Base;
  unsigned Budget = detail::kEdgeRangeVisits;
  ConstantRange R = rangeOf(V, Ctx, detail::kEdgeRangeDepth, Budget);
  if (Budget == 0)
    return Base;
  if (R.getBitWidth() != W)
    return Base;
  if (R.isEmptySet() || R.isFullSet())
    return Base;
  // Never widen, never contradict: the refined set must sit inside the
  // baseline, else the edge walk overreached and the baseline stands.
  if (!Base.contains(R))
    return Base;
  return R;
}

} // namespace biara
#endif // BIARA_EDGE_RANGES_H
