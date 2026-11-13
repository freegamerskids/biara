#include "layouts.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

namespace biara_layouts {


std::string jsonStr(StringRef S) {
  std::string R = "\"";
  R.reserve(S.size() + 16);
  for (unsigned char C : S.bytes()) {
    switch (C) {
    case '"':
      R += "\\\"";
      break;
    case '\\':
      R += "\\\\";
      break;
    case '\b':
      R += "\\b";
      break;
    case '\f':
      R += "\\f";
      break;
    case '\n':
      R += "\\n";
      break;
    case '\r':
      R += "\\r";
      break;
    case '\t':
      R += "\\t";
      break;
    default:
      if (C < 0x20)
        R += std::string("\\u00") + "0123456789abcdef"[C >> 4] + "0123456789abcdef"[C & 15];
      else
        R += (char)C;
    }
}
  return R + "\"";
}

// Guest entry address: `!biara.entry !{i64 entry}` attached by Rust from the
// compact summaries.
std::optional<uint64_t> entryOf(const Function &Fn, LLVMContext &Cx) {
  MDNode *N = Fn.getMetadata(Cx.getMDKindID("biara.entry"));
  if (!N || !N->getNumOperands())
    return std::nullopt;
  if (auto *C = mdconst::dyn_extract<ConstantInt>(N->getOperand(0)))
    return C->getZExtValue();
  return std::nullopt;
}

// Surviving guest PCs on an instruction: `!biara.pc !{i64 pc}`. Empty when
// erased or never attached; never guessed.
std::vector<uint64_t> pcsOf(const Instruction &I, LLVMContext &Cx) {
  std::vector<uint64_t> Out;
  MDNode *N = I.getMetadata(Cx.getMDKindID("biara.pc"));
  if (!N)
    return Out;
  for (const MDOperand &Op : N->operands())
    if (auto *C = mdconst::dyn_extract<ConstantInt>(Op))
      Out.push_back(C->getZExtValue());
  return Out;
}

// Renamed arguments: function metadata `!biara.debug_name` holding strings
// `"<original>=<name>"` (one MDString each) or two-string tuples
// `(original, name)`. Rust renames only proven unique bindings, so every
// entry here is `debug` evidence.
std::map<std::string, std::string> debugNamesOf(const Function &Fn, LLVMContext &Cx) {
  std::map<std::string, std::string> Out;
  MDNode *N = Fn.getMetadata(Cx.getMDKindID("biara.debug_name"));
  if (!N)
    return Out;
  for (const MDOperand &Op : N->operands()) {
    if (auto *S = dyn_cast<MDString>(Op)) {
      std::string E = S->getString().str();
      if (auto Eq = E.find('='); Eq != std::string::npos && Eq > 0 && Eq + 1 < E.size())
        Out[E.substr(0, Eq)] = E.substr(Eq + 1);
    } else if (auto *T = dyn_cast<MDTuple>(Op)) {
      if (T->getNumOperands() == 2)
        if (auto *A = dyn_cast<MDString>(T->getOperand(0)))
          if (auto *B = dyn_cast<MDString>(T->getOperand(1)))
            Out[A->getString().str()] = B->getString().str();
    }
}
  return Out;
}

struct DebugObj {
  uint64_t Start, End; // half-open [start, end)
  int64_t Rel;         // entry-SP-relative offset
  uint64_t Size;
  std::string Name, Type;
};

// Declared frame objects: function metadata `!biara.debug_objects`
// `!{!{i64 start, i64 end, i64 entry_offset, i64 size, !"name", !"type_name"}}`
// with half-open `[start,end)` PC ranges.
std::vector<DebugObj> debugObjectsOf(const Function &Fn, LLVMContext &Cx) {
  std::vector<DebugObj> Out;
  MDNode *N = Fn.getMetadata(Cx.getMDKindID("biara.debug_objects"));
  if (!N)
    return Out;
  for (const MDOperand &Op : N->operands()) {
    auto *T = dyn_cast<MDTuple>(Op);
    if (!T || T->getNumOperands() != 6)
      continue;
    auto *C0 = mdconst::dyn_extract<ConstantInt>(T->getOperand(0));
    auto *C1 = mdconst::dyn_extract<ConstantInt>(T->getOperand(1));
    auto *C2 = mdconst::dyn_extract<ConstantInt>(T->getOperand(2));
    auto *C3 = mdconst::dyn_extract<ConstantInt>(T->getOperand(3));
    auto *S4 = dyn_cast<MDString>(T->getOperand(4));
    auto *S5 = dyn_cast<MDString>(T->getOperand(5));
    if (!C0 || !C1 || !C2 || !C3 || !S4 || !S5)
      continue;
    uint64_t Start = C0->getZExtValue(), End = C1->getZExtValue();
    if (End < Start)
      continue;
    Out.push_back({Start, End, C2->getSExtValue(), C3->getZExtValue(), S4->getString().str(),
                   S5->getString().str()});
}
  return Out;
}

const std::set<std::string> &keywords() {
  static const std::set<std::string> K = {
      "auto",     "break",    "case",     "char",   "const",    "continue", "default",
      "do",       "double",   "else",     "enum",   "extern",   "float",    "for",
      "goto",     "if",       "inline",   "int",    "long",     "register", "restrict",
      "return",   "short",    "signed",   "sizeof", "static",   "struct",   "switch",
      "typedef",  "union",    "unsigned", "void",   "volatile", "while",    "bool",
      "true",     "false",    "biara_cpu"};
  return K;
}

std::string ident(StringRef S) {
  std::string R;
  for (char C : S)
    R += (isalnum((unsigned char)C) || C == '_') ? C : '_';
  if (R.empty() || isdigit((unsigned char)R[0]))
    R = "_" + R;
  if (keywords().count(R))
    R += "_";
  return R;
}

unsigned container(unsigned Bits) {
  if (Bits == 1)
    return 1;
  for (unsigned W : {8u, 16u, 32u, 64u, 128u})
    if (Bits <= W)
      return W;
  return 0;
}

std::string uintTy(unsigned Bits) {
  switch (container(Bits)) {
  case 1:
    return "bool";
  case 8:
    return "uint8_t";
  case 16:
    return "uint16_t";
  case 32:
    return "uint32_t";
  case 64:
    return "uint64_t";
  case 128:
    return "biara_u128";
}
  return "";
}

bool standard(unsigned Bits) { return container(Bits) == Bits; }

std::string hex(uint64_t V) {
  char B[32];
  snprintf(B, sizeof B, "0x%llx", (unsigned long long)V);
  return B;
}


// Root plus constant offset of an address (integer or pointer).
Base base(Value *V, const DataLayout &DL, unsigned Depth) {
  if (Depth > 32)
    return {V, 0};
  if (auto *C = dyn_cast<ConstantInt>(V); C && C->getBitWidth() <= 64)
    return {nullptr, (int64_t)C->getZExtValue()};
  if (auto *G = dyn_cast<GEPOperator>(V)) {
    APInt Off(64, 0);
    if (G->accumulateConstantOffset(DL, Off)) {
      Base B = base(G->getPointerOperand(), DL, Depth + 1);
      B.Off += Off.getSExtValue();
      return B;
    }
    return {V, 0};
}
  if (auto *O = dyn_cast<Operator>(V)) {
    switch (O->getOpcode()) {
    case Instruction::IntToPtr:
    case Instruction::PtrToInt:
      if (O->getOperand(0)->getType()->getScalarSizeInBits() == 64 ||
          O->getOperand(0)->getType()->isPointerTy())
        return base(O->getOperand(0), DL, Depth + 1);
      break;
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Or: {
      auto *K = dyn_cast<ConstantInt>(O->getOperand(1));
      if (!K || K->getBitWidth() != 64)
        break;
      if (O->getOpcode() == Instruction::Or && !cast<PossiblyDisjointInst>(O)->isDisjoint())
        break;
      Base B = base(O->getOperand(0), DL, Depth + 1);
      B.Off += O->getOpcode() == Instruction::Sub ? -K->getSExtValue() : K->getSExtValue();
      return B;
    }
    default:
      break;
    }
}
  return {V, 0};
}

// A root that a pointer variable can stand for.
bool pointerRoot(const Value *R) {
  return R &&
         (isa<Argument>(R) || isa<LoadInst>(R) || isa<CallBase>(R) || isa<PHINode>(R) ||
          isa<SelectInst>(R)) &&
         (R->getType()->isIntegerTy(64) || R->getType()->isPointerTy());
}



// Fields from (offset, bytes) accesses: widest per offset, then
// first-come non-overlapping.
std::vector<Field> fieldsOf(const std::map<int64_t, unsigned> &Acc, int64_t Lo, int64_t Hi) {
  std::vector<Field> Out;
  int64_t End = Lo;
  for (auto [Off, Bytes] : Acc) {
    if (Off < End || Off + (int64_t)Bytes > Hi)
      continue;
    Out.push_back({Off, Bytes, -1, -1, ""});
    End = Off + Bytes;
}
  return Out;
}

// Evidence dropped by the bounded analysis, reported rather than hidden:
// every materially dropped fact keeps the status honest (never a misleading
// `Complete` claim when evidence was discarded).


bool Types::FrameLess::operator()(const Value *A, const Value *B) const {
  auto L = Order->find(A), R = Order->find(B);
  if (L != Order->end() && R != Order->end())
    return L->second < R->second;
  if ((L != Order->end()) != (R != Order->end()))
    return L != Order->end();
  return std::less<const Value *>{}(A, B);
}

const Field *Layout::at(int64_t Off, unsigned Bytes) const {
  const Field *F = startsAt(Off);
  return F && F->Bytes == Bytes ? F : nullptr;
}
const Field *Layout::startsAt(int64_t Off) const {
  // fieldsOf and embed keep offsets sorted and unique.
  auto It = std::lower_bound(Fields.begin(), Fields.end(), Off,
                              [](const Field &F, int64_t O) { return F.Off < O; });
  return It != Fields.end() && It->Off == Off ? &*It : nullptr;
}
Types::Types(const DataLayout &DL) : DL(DL), Frames(FrameLess{&FrameOrder}) {}

int Types::rep(int X) const {
  while (Parent[X] != X)
    X = Parent[X];
  return X;
}

int Types::find(int X) {
    while (Parent[X] != X)
      X = Parent[X] = Parent[Parent[X]];
    return X;
}

void Types::unite(int A, int B) {
    A = find(A), B = find(B);
    if (A != B)
      Parent[std::max(A, B)] = std::min(A, B);
}

int Types::var(Value *R) {
    auto [It, New] = VarOf.try_emplace(R, (int)Parent.size());
    if (New)
      Parent.push_back(It->second);
    return It->second;
}

int Types::classOf(Value *V) {
    auto It = VarOf.find(V);
    return It == VarOf.end() ? -1 : find(It->second);
}

const Layout *Types::layoutOf(Value *V) {
    int C = classOf(V);
    auto It = Layouts.find(C);
    return It == Layouts.end() ? nullptr : &It->second;
}

void Types::build(Module &M, const std::vector<BiaraCField> &Cpu) {
    std::vector<std::pair<Value *, Value *>> Same; // unify
    std::vector<std::pair<Base, Value *>> Loaded, Stored;
    std::vector<std::tuple<Value *, int64_t, unsigned>> Accesses;
    // Frame addresses passed to parameters: (alloca, offset, parameter).
    std::vector<std::tuple<Value *, int64_t, Value *>> FramePasses;
    // Frame addresses stored to memory: (where, what).
    std::vector<std::pair<Base, Base>> FrameStores;
    std::vector<std::pair<Base, Value *>> RawStores;
    std::vector<std::pair<Value *, Value *>> ArgPasses; // (argument, parameter)
    // Direct calls: (actual base, formal parameter, call) for propagation.
    std::vector<std::tuple<Base, Value *, CallBase *>> CallArgs;
    // Direct-call returns feeding pointer variables: (call, user).
    std::vector<std::pair<CallBase *, Value *>> CallRets;
    // Callee return bases: function -> reduced bases of returned values.
    // A base rooted at a formal instantiates per call site (the result
    // aliases that site's actual, shifted); other roots are skipped.
    std::map<Function *, std::vector<Base>> RetBases;
    for (GlobalVariable &G : M.globals())
      FrameOrder.try_emplace(&G, FrameOrder.size());
    for (Function &F : M) {
      for (Instruction &I : instructions(F)) {
        if (isa<AllocaInst>(I))
          FrameOrder.try_emplace(&I, FrameOrder.size());
        auto access = [&](Value *Ptr, Type *Ty) -> Base {
          Base B = base(Ptr, DL);
          unsigned Bytes = DL.getTypeStoreSize(Ty);
          Accesses.push_back({B.Root, B.Off, Bytes});
          return B;
        };
        if (auto *L = dyn_cast<LoadInst>(&I)) {
          Loaded.push_back({access(L->getPointerOperand(), L->getType()), L});
        } else if (auto *S = dyn_cast<StoreInst>(&I)) {
          Base Dest = access(S->getPointerOperand(), S->getValueOperand()->getType());
          Stored.push_back({Dest, S->getValueOperand()});
          RawStores.push_back({Dest, S->getValueOperand()});
        } else if (auto *P = dyn_cast<PHINode>(&I)) {
          for (Value *In : P->incoming_values())
            if (Base B = base(In, DL); B.Off == 0 && pointerRoot(B.Root))
              Same.push_back({P, B.Root});
        } else if (auto *Sel = dyn_cast<SelectInst>(&I)) {
          for (Value *In : {Sel->getTrueValue(), Sel->getFalseValue()})
            if (Base B = base(In, DL); B.Off == 0 && pointerRoot(B.Root))
              Same.push_back({Sel, B.Root});
        } else if (auto *R = dyn_cast<ReturnInst>(&I)) {
          if (R->getNumOperands())
            RetBases[&F].push_back(base(R->getOperand(0), DL));
        } else if (auto *CB = dyn_cast<CallBase>(&I)) {
          Function *Callee = CB->getCalledFunction();
          if (!Callee || Callee->isDeclaration())
            continue;
          for (unsigned K = 0; K < CB->arg_size() && K < Callee->arg_size(); ++K) {
            ArgPasses.push_back({CB->getArgOperand(K), Callee->getArg(K)});
            CallArgs.push_back({base(CB->getArgOperand(K), DL), Callee->getArg(K), CB});
          }
          // Per-site result users: values derived from this site's result
          // (phi/select inputs are united locally as before; here we
          // record loads/stores/calls/returns that consume the result so
          // the result's facts instantiate at this site only).
          if (pointerRoot(CB))
            for (User *U : CB->users())
              if (auto *UI = dyn_cast<Instruction>(U))
                CallRets.push_back({CB, UI});
        }
      }
    }

    // Frame slots that only ever hold one frame address (spills at -O0):
    // a load from one is that address, for typing.
    std::map<std::pair<const Value *, int64_t>, std::optional<Base>> Holds;
    for (auto &[Dest, V] : RawStores) {
      if (!Dest.Root || !isa<AllocaInst>(Dest.Root))
        continue;
      Base VB = base(V, DL);
      auto [It, New] = Holds.try_emplace({Dest.Root, Dest.Off}, VB);
      if (!New && (!It->second || It->second->Root != VB.Root || It->second->Off != VB.Off))
        It->second.reset();
    }
    auto typeBase = [&](Value *V) {
      Base B = base(V, DL);
      if (auto *L = dyn_cast_or_null<LoadInst>(B.Root)) {
        Base P = base(L->getPointerOperand(), DL);
        auto It = Holds.find({P.Root, P.Off});
        if (B.Off == 0 && It != Holds.end() && It->second && It->second->Root &&
            isa<AllocaInst>(It->second->Root))
          return *It->second;
      }
      return B;
    };
    for (auto &[Dest, V] : RawStores)
      if (Base VB = typeBase(V); VB.Root && isa<AllocaInst>(VB.Root))
        FrameStores.push_back({Dest, VB});
    for (auto &[Arg, Param] : ArgPasses)
      if (Base B = typeBase(Arg); B.Root && isa<AllocaInst>(B.Root))
        FramePasses.push_back({B.Root, B.Off, Param});

    // Classes: roots accessed through, and what they are unified with.
    // Call actuals/formals get classes too, so offset-shifted facts have
    // somewhere to land even when the actual itself is never accessed
    // directly (e.g. an object only touched through two callees).
    for (auto &[R, Off, Bytes] : Accesses)
      if (R && !isa<AllocaInst>(R) && !isa<GlobalVariable>(R) &&
          (R->getType()->isIntegerTy(64) || R->getType()->isPointerTy()))
        var(R);
    for (auto &[AB, Param, CB] : CallArgs) {
      (void)CB;
      if (AB.Root && pointerRoot(AB.Root))
        var(AB.Root);
      if (pointerRoot(Param))
        var(Param);
    }
    for (auto &[CB, UI] : CallRets) {
      (void)UI;
      if (pointerRoot(CB))
        var(CB);
    }
    // Stored/loaded value roots get classes too: a child stored into a
    // container slot (or loaded from one) must have somewhere for
    // pointee facts to land even when it is never addressed directly.
    for (auto &[B, V] : Loaded) {
      (void)B;
      Base VB = base(V, DL);
      if (VB.Off == 0 && VB.Root && pointerRoot(VB.Root))
        var(VB.Root);
    }
    for (auto &[B, V] : Stored) {
      (void)B;
      Base VB = base(V, DL);
      if (VB.Off == 0 && VB.Root && pointerRoot(VB.Root))
        var(VB.Root);
    }
    for (auto &[A, B] : Same)
      unite(var(A), var(B));
    // Pointer fields: loaded or stored values that are pointer variables.
    bool Changed = true;
    while (Changed) {
      Changed = false;
      FieldPtr.clear();
      auto link = [&](Base B, Value *V) {
        if (!B.Root || !VarOf.count(B.Root))
          return;
        Base VB = base(V, DL);
        if (VB.Off != 0 || !VB.Root || !VarOf.count(VB.Root))
          return;
        int C = classOf(B.Root), P = classOf(VB.Root);
        auto [It, New] = FieldPtr.try_emplace({C, B.Off}, P);
        if (!New && find(It->second) != P) {
          unite(It->second, P);
          Changed = true;
        }
      };
      for (auto &[B, V] : Loaded)
        link(B, V);
      for (auto &[B, V] : Stored)
        link(B, V);
    }

    std::map<const Value *, std::map<int64_t, unsigned>> FrameAcc;
    for (auto &[R, Off, Bytes] : Accesses) {
      if (R && !isa<AllocaInst>(R) && !isa<GlobalVariable>(R) &&
          (R->getType()->isIntegerTy(64) || R->getType()->isPointerTy())) {
        // Far offsets index arrays (or are absolute addresses), not fields.
        if (Off < 0 || Off >= kMaxField) {
          ++Dropped.CappedOffsets;
          continue;
        }
        int C = classOf(R);
        unsigned &W = Acc[C][Off];
        W = std::max(W, Bytes);
        AccSizes[C].insert(Bytes);
        NonZeroAccess[C] |= Off != 0;
        Observed[C][Off].insert(Bytes);
      } else if (R && (isa<AllocaInst>(R) || isa<GlobalVariable>(R))) {
        unsigned &W = FrameAcc[R][Off];
        W = std::max(W, Bytes);
      } else if (!R) {
        // Absolute addresses: not fields, but not silently dropped either.
        ++Dropped.UnsupportedBases;
      } else if (!isa<AllocaInst>(R) && !isa<GlobalVariable>(R) && !pointerRoot(R)) {
        // Nonconstant, non-rooted address relationships (computed indices,
        // unreduced operators): recorded for the status, not as fields.
        ++Dropped.UnsupportedBases;
      }
    }

    // Cross-call constraint propagation over the seeded access sets:
    // offset-aware actual->formal facts for arguments, returns, and
    // pointer fields. Directional only: actuals are never united with
    // formals, so unrelated objects passed to one generic callee keep
    // separate layouts. Bounded: at most kPropagateRounds passes;
    // leftovers are reported, never asserted.
    propagate(CallArgs, CallRets, RetBases, Loaded, Stored);

    int N = 0;
    for (auto &[C, Offs] : Acc) {
      Layout L;
      L.Fields = fieldsOf(Offs, 0, INT64_MAX);
      if (L.Fields.empty())
        continue;
      L.Scalar = !NonZeroAccess[C] && AccSizes[C].size() == 1;
      L.Name = "struct s" + std::to_string(++N);
      for (Field &F : L.Fields) {
        F.Name = "f_" + hex(F.Off).substr(2);
        if (auto It = FieldPtr.find({C, F.Off}); It != FieldPtr.end() && F.Bytes == 8)
          F.Pointee = find(It->second);
        L.Size = F.Off + F.Bytes;
      }
      Layouts[C] = L;
    }
    // Classes do not meet across calls (a function taking any pointer
    // would merge every struct passed to it); instead, layouts that come
    // out the same (fields, and what they point to, recursively) share one
    // struct.
    share();

    // Pointees without layouts of their own stay integers.
    for (auto &[C, L] : Layouts)
      for (Field &F : L.Fields)
        if (F.Pointee >= 0 && !Layouts.count(F.Pointee))
          F.Pointee = -1;

    for (auto &[R, Offs] : FrameAcc) {
      Layout L;
      if (auto *A = dyn_cast<AllocaInst>(R)) {
        uint64_t Size = DL.getTypeAllocSize(A->getAllocatedType());
        StringRef Name = A->getName();
        int64_t Below = 0;
        bool IsFrame = Name.consume_front("frame.") && !Name.getAsInteger(10, Below);
        L.Fields = fieldsOf(Offs, 0, Size);
        L.Size = Size;
        const Function *F = A->getFunction();
        L.Name = "struct " + ident(F->getName()) + "_" + ident(A->getName());
        L.Below = IsFrame ? Below : -1;
        for (Field &Fd : L.Fields)
          Fd.Name = slotName(L, Fd.Off);
      } else {
        auto *G = cast<GlobalVariable>(R);
        L.Size = DL.getTypeAllocSize(G->getValueType());
        std::map<int64_t, unsigned> All = Offs;
        std::map<int64_t, std::string> Names;
        for (const BiaraCField &F : Cpu)
          if (All.count(F.off))
            Names[F.off] = F.name;
        L.Fields = fieldsOf(All, 0, L.Size);
        L.Name = "struct cpu_state";
        std::set<std::string> Used;
        for (Field &Fd : L.Fields) {
          auto It = Names.find(Fd.Off);
          Fd.Name = It != Names.end() ? ident(It->second) : "f_" + hex(Fd.Off).substr(2);
          // Globals can share a name (AArch64's two views of the pc).
          if (!Used.insert(Fd.Name).second)
            Fd.Name += "_" + hex(Fd.Off).substr(2);
        }
      }
      Frames[R] = L;
    }
    // A frame slot handed to a parameter whose pointees are a struct holds
    // that struct; so does one whose address is stored in a field that
    // points to a struct (until no more such slots turn up).
    for (auto &[R, Off, Param] : FramePasses)
      embed(R, Off, classOf(Param));
    for (bool Changed = true; Changed;) {
      Changed = false;
      for (auto &[Dest, Val] : FrameStores) {
        int P = pointeeAt(Dest);
        if (P >= 0)
          Changed |= embed(Val.Root, Val.Off, P);
      }
    }
}

void Types::propagate(const std::vector<std::tuple<Base, Value *, CallBase *>> &CallArgs,
                 const std::vector<std::pair<CallBase *, Value *>> &CallRets,
                 const std::map<Function *, std::vector<Base>> &RetBases,
                 const std::vector<std::pair<Base, Value *>> &Loaded,
                 const std::vector<std::pair<Base, Value *>> &Stored) {
  // Directional, context-sensitive cross-call constraints.
  //
  // Each call site keeps its own facts; classes are never united across a
  // call, so unrelated actuals at one generic callee keep separate layouts.
  // Four fact families, all offset-aware:
  // - Arguments: accesses through the formal at `Off` describe the actual
  //   root at `Off + delta`, where `delta` is the actual's own base offset
  //   (an offset pointer shifts). Facts are keyed per call site: the same
  //   formal reached from two sites contributes to each actual separately,
  //   never merged through the formal's class. Pure formals (never stored
  //   to a caller-visible root) still propagate to their own actuals only.
  // - Returns: a call result aliases the callee's return at the same
  //   offset, but only within that call site's context (see below).
  // - Pointer fields, per call site: a field the callee reads or writes
  //   at `(formal + FO)` instantiates at the caller's actual: the actual
  //   `(root + delta + FO)` is a pointer, and the formal child parameter
  //   the callee passes onward maps to the caller's corresponding actual.
  //   Pointee accesses flow into the mapped actual's class only. The
  //   container's own field offsets are never copied into the child, and
  //   two sites sharing one getter never meet through the formal child:
  //   each site maps the formal child to its own actual.
  // Widths propagate as conflict evidence: when a propagated (offset,
  // bytes) pair overlaps an incompatible width already present, both
  // widths are retained (widest wins for rendering, casts cover the
  // overlap) and the pair is reported through `LayoutConflict`, never
  // silently narrowed.
  // Bounded: at most kPropagateRounds passes over new facts; the fixpoint
  // compares full (offset, bytes) pairs per class, so a width widening at
  // a known offset counts as progress. Leftovers set FixpointTruncated.
  std::map<int, std::map<int64_t, unsigned>> XAcc;
  auto snapshot = [&]() {
    std::map<int, std::map<int64_t, unsigned>> S;
    for (auto &[C, Offs] : XAcc)
      S[C] = Offs;
    return S;
  };
  bool WidthsChanged = false;
  auto note = [&](int C, int64_t Off, unsigned Bytes) {
    if (C < 0 || Off < 0 || Off >= kMaxField) {
      if (Off < 0 || Off >= kMaxField)
        ++Dropped.CappedOffsets;
      else
        ++Dropped.UnsupportedBases;
      return;
    }
    unsigned &W = XAcc[C][Off];
    WidthsChanged |= Observed[C][Off].insert(Bytes).second;
    W = std::max(W, Bytes);
  };
  // Per-site return instantiation: call result -> the classes observed at
  // that site only. Keyed by the CallBase, never by the callee.
  auto resultFacts = [&](CallBase *CB, std::map<int64_t, unsigned> &Out) {
    auto It = Acc.find(classOf(CB));
    if (It != Acc.end())
      Out = It->second;
    auto Jt = XAcc.find(classOf(CB));
    if (Jt != XAcc.end())
      for (auto [Off, Bytes] : Jt->second) {
        unsigned &W = Out[Off];
        W = std::max(W, Bytes);
      }
  };
  for (Dropped.Iterations = 0; Dropped.Iterations < kPropagateRounds; ++Dropped.Iterations) {
    WidthsChanged = false;
    auto Before = snapshot();
    // Arguments, per call site: formal facts flow to this site's actual.
    for (auto &CA : CallArgs) {
      Base AB = std::get<0>(CA);
      Value *Param = std::get<1>(CA);
      (void)std::get<2>(CA);
      if (!AB.Root || !pointerRoot(AB.Root) || !pointerRoot(Param))
        continue;
      if (!VarOf.count(AB.Root) || !VarOf.count(Param))
        continue;
      int AC = classOf(AB.Root), FC = classOf(Param);
      if (AC == FC)
        continue;
      auto shift = [&](const std::map<int64_t, unsigned> &Offs) {
        for (auto [Off, Bytes] : Offs) {
          __int128 T = (__int128)Off + AB.Off;
          if (T < 0 || T > INT64_MAX) {
            ++Dropped.OverflowedOffsets;
            continue;
          }
          note(AC, (int64_t)T, Bytes);
          auto Widths = Observed.find(FC);
          if (Widths != Observed.end())
            if (auto At = Widths->second.find(Off); At != Widths->second.end())
              for (unsigned Width : At->second)
                WidthsChanged |= Observed[AC][(int64_t)T].insert(Width).second;
        }
      };
      auto It = Acc.find(FC);
      if (It != Acc.end())
        shift(It->second);
      auto Jt = XAcc.find(FC);
      // A formal's own propagated facts flow onward, except facts that
      // this same site just contributed (no self-amplification): skip
      // entries already present at the actual with equal-or-wider width.
      if (Jt != XAcc.end() && Jt->first != AC) {
        auto Kt = XAcc.find(AC);
        std::map<int64_t, unsigned> Novel;
        for (auto [Off, Bytes] : Jt->second) {
          __int128 T = (__int128)Off + AB.Off;
          if (T < 0 || T > INT64_MAX) {
            ++Dropped.OverflowedOffsets;
            continue;
          }
          int64_t D = (int64_t)T;
          unsigned Have = 0;
          if (Kt != XAcc.end()) {
            auto H = Kt->second.find(D);
            if (H != Kt->second.end())
              Have = H->second;
          }
          if (Bytes > Have)
            Novel[D] = Bytes;
        }
        for (auto [D, Bytes] : Novel)
          note(AC, D, Bytes);
      }
    }
    // Returns, per call site: the callee's returned roots instantiate
    // at this site's actuals. For each `return V` of the callee with
    // `base(V)` rooted at formal `Param` (offset `ROff`), the site's result
    // aliases the actual passed for `Param`, shifted by `AB.Off + ROff`:
    // result facts at `Off` describe the actual at `Off + delta`. The flow
    // is result -> actual only, keyed by site: two sites calling `id`
    // with unrelated objects never share facts, because each site's
    // result class holds only facts derived from that site's own actuals
    // (via the argument path) plus the callee's direct result accesses.
    // Callee returns not rooted at a formal (globals, constants) are
    // skipped: there is no per-site actual to attach them to.
    {
      // Group actuals by call site for return instantiation.
      std::map<CallBase *, std::vector<std::pair<Base, Value *>>> BySite;
      for (auto &CA : CallArgs)
        BySite[std::get<2>(CA)].push_back({std::get<0>(CA), std::get<1>(CA)});
      for (auto &[CB, UI] : CallRets) {
        (void)UI;
        Function *Callee = CB->getCalledFunction();
        if (!Callee)
          continue;
        auto RB = RetBases.find(Callee);
        if (RB == RetBases.end() || !VarOf.count(CB))
          continue;
        int CC = classOf(CB);
        auto SA = BySite.find(CB);
        if (SA == BySite.end())
          continue;
        for (Base Ret : RB->second) {
          if (!Ret.Root || !isa<Argument>(Ret.Root))
            continue;
          // Find this site's actual for the returned formal.
          for (auto &[AB, Param] : SA->second) {
            if (Param != Ret.Root || !AB.Root || !VarOf.count(AB.Root))
              continue;
            if (!pointerRoot(AB.Root))
              continue;
            int AC = classOf(AB.Root);
            __int128 Delta = (__int128)AB.Off + Ret.Off;
            std::map<int64_t, unsigned> RF;
            resultFacts(CB, RF);
            for (auto [Off, Bytes] : RF) {
              __int128 T = (__int128)Off + Delta;
              if (T < 0 || T > INT64_MAX) {
                ++Dropped.OverflowedOffsets;
                continue;
              }
              // Never flow a class into itself through its own call.
              if (AC == CC && Delta == 0)
                continue;
              note(AC, (int64_t)T, Bytes);
            }
          }
        }
      }
    }
    // Derived values: a load whose value is a pointer root aliases this
    // site's result (the loaded pointer's class learns the site's result
    // facts), and likewise a phi/select rooted at the result. Stores,
    // returns, and calls through the result already flow through the
    // Stored/CallArgs paths and the return bindings; nothing flows back
    // into the result class, so sites stay separate.
    for (auto &[CB, UI] : CallRets) {
      if (!VarOf.count(CB))
        continue;
      int CC = classOf(CB);
      std::map<int64_t, unsigned> RF;
      resultFacts(CB, RF);
      if (RF.empty())
        continue;
      if (auto *L = dyn_cast<LoadInst>(UI)) {
        if (pointerRoot(L) && VarOf.count(L) && classOf(L) != CC)
          for (auto [Off, Bytes] : RF)
            note(classOf(L), Off, Bytes);
      } else if (pointerRoot(UI) && VarOf.count(UI) && classOf(UI) != CC &&
                 (isa<PHINode>(UI) || isa<SelectInst>(UI))) {
        for (auto [Off, Bytes] : RF)
          note(classOf(UI), Off, Bytes);
      }
    }
    // Pointer fields, per call site: a load/store the callee performs at
    // `(formal + FO)` instantiates at the caller's actual `(root + delta
    // + FO)`. The actual slot is a pointer; the formal child the callee
    // passes onward (a call argument base rooted at a formal) maps to the
    // caller's corresponding actual, and the child's accesses flow into
    // the mapped actual's class only. Sites sharing one callee never meet
    // through the formal child: each site maps it to its own actual.
    // Intra-function loads/stores keep the existing FieldPtr flow below.
    {
      // Group actuals by call site for field instantiation.
      std::map<CallBase *, std::vector<std::pair<Base, Value *>>> BySite;
      for (auto &CA : CallArgs)
        BySite[std::get<2>(CA)].push_back({std::get<0>(CA), std::get<1>(CA)});
      // Callee loads/stores with formal roots, grouped by function.
      std::map<Function *, std::vector<std::pair<Base, Value *>>> CalleeMems;
      for (auto &[B, V] : Loaded)
        if (B.Root)
          if (auto *A = dyn_cast<Argument>(B.Root))
            CalleeMems[A->getParent()].push_back({B, V});
      for (auto &[B, V] : Stored)
        if (B.Root)
          if (auto *A = dyn_cast<Argument>(B.Root))
            CalleeMems[A->getParent()].push_back({B, V});
      for (auto &[CB, Sites] : BySite) {
        Function *Callee = CB->getCalledFunction();
        if (!Callee)
          continue;
        auto CM = CalleeMems.find(Callee);
        if (CM == CalleeMems.end())
          continue;
        // This site's actual per formal.
        std::map<Value *, Base> ActualFor;
        for (auto &[AB, Param] : Sites)
          ActualFor[Param] = AB;
        for (auto &[B, V] : CM->second) {
          auto AF = ActualFor.find(B.Root);
          if (AF == ActualFor.end() || !AF->second.Root)
            continue;
          if (!VarOf.count(AF->second.Root))
            continue;
          __int128 Slot = (__int128)AF->second.Off + B.Off;
          if (Slot < 0 || Slot > INT64_MAX) {
            ++Dropped.OverflowedOffsets;
            continue;
          }
          int AC = classOf(AF->second.Root);
          // The value side maps like the address side: a value rooted at
          // a formal of the same callee resolves to this site's actual
          // for that formal (offset-aware); a value rooted outside the
          // callee keeps its own class.
          auto mapValue = [&](Value *W) -> std::pair<int, int64_t> {
            Base WB = base(W, DL);
            auto *WA = WB.Root ? dyn_cast<Argument>(WB.Root) : nullptr;
            if (WA && WA->getParent() == Callee) {
              auto WF = ActualFor.find(WB.Root);
              if (WF == ActualFor.end() || !WF->second.Root)
                return {-1, 0};
              __int128 T = (__int128)WF->second.Off + WB.Off;
              if (T < 0 || T > INT64_MAX) {
                ++Dropped.OverflowedOffsets;
                return {-1, 0};
              }
              if (!VarOf.count(WF->second.Root))
                return {-1, 0};
              return {classOf(WF->second.Root), (int64_t)T};
            }
            if (WB.Off == 0 && WB.Root && VarOf.count(WB.Root))
              return {classOf(WB.Root), 0};
            return {-1, 0};
          };
          // Is the value side rooted inside the callee (a callee-side
          // child such as a loaded pointer), rather than mapped to one
          // of this site's actuals?
          Base VBraw = base(V, DL);
          auto *VA = VBraw.Root ? dyn_cast<Argument>(VBraw.Root) : nullptr;
          bool CalleeSide = VBraw.Root && (!VA || VA->getParent() != Callee) &&
                            !(VBraw.Off == 0 && VBraw.Root && VarOf.count(VBraw.Root) &&
                              ActualFor.count(VBraw.Root));
          // Caller-side children stored at this slot: the caller's own
          // Stored entries through the actual root at this slot. Their
          // classes alias the callee child at this site: the child's
          // established facts flow into them (directional, callee ->
          // caller only, so sites sharing one callee never meet).
          std::vector<int> SlotOwners;
          for (auto &[SB, SV] : Stored) {
            if (!SB.Root || SB.Off != (int64_t)Slot)
              continue;
            if (find(classOf(SB.Root)) != find(AC))
              continue;
            Base SVB = base(SV, DL);
            if (SVB.Off == 0 && SVB.Root && VarOf.count(SVB.Root))
              SlotOwners.push_back(classOf(SVB.Root));
          }
          auto [VC, VOff] = mapValue(V);
          (void)VOff;
          if (CalleeSide && VBraw.Root && VarOf.count(VBraw.Root) && !SlotOwners.empty()) {
            int CC = classOf(VBraw.Root);
            auto flowAlias = [&](const std::map<int64_t, unsigned> &Offs) {
              for (auto [Off, Bytes] : Offs)
                for (int O : SlotOwners)
                  if (O != CC)
                    note(O, Off, Bytes);
            };
            auto It = Acc.find(CC);
            if (It != Acc.end())
              flowAlias(It->second);
            auto Jt = XAcc.find(CC);
            if (Jt != XAcc.end())
              flowAlias(Jt->second);
            // The slot's field fact names the caller's owner (first one,
            // deterministic): export pointees bind the caller child.
            int Owner = *std::min_element(SlotOwners.begin(), SlotOwners.end());
            auto [It2, New2] = FieldPtr.try_emplace({AC, (int64_t)Slot}, Owner);
            if (!New2 && find(It2->second) != Owner)
              ++Dropped.UnsupportedBases;
            continue;
          }
          if (VC < 0)
            continue;
          // Formal-mapped value side (store through a formal, or a value
          // the caller passed): the actual slot holds the mapped value
          // class. The caller's own stores/loads through the slot then
          // resolve through it in fieldLink below.
          auto [It, New] = FieldPtr.try_emplace({AC, (int64_t)Slot}, VC);
          if (!New && find(It->second) != VC) {
            // Conflicting children at one slot stay explicit: keep the
            // first, count the disagreement instead of merging
            // unrelated objects.
            ++Dropped.UnsupportedBases;
          }
        }
      }
    }
    // Intra-function pointer flow: only the pointee's established
    // accesses flow into the loaded/stored value's class. The
    // container's own offsets are never copied into the child.
    auto fieldLink = [&](Base B, Value *V) {
      if (!B.Root || !VarOf.count(B.Root))
        return;
      Base VB = base(V, DL);
      if (VB.Off != 0 || !VB.Root || !VarOf.count(VB.Root))
        return;
      int P = classOf(VB.Root);
      // The pointee class is whatever FieldPtr established for
      // (container, B.Off); without that evidence there is nothing
      // directional to say (no blind container->child copy).
      auto FP = FieldPtr.find({classOf(B.Root), B.Off});
      if (FP == FieldPtr.end())
        return;
      int PC = find(FP->second);
      auto flow = [&](const std::map<int64_t, unsigned> &Offs) {
        for (auto [Off, Bytes] : Offs)
          note(P, Off, Bytes);
      };
      auto It = Acc.find(PC);
      if (It != Acc.end())
        flow(It->second);
      auto Jt = XAcc.find(PC);
      if (Jt != XAcc.end() && Jt->first != P)
        flow(Jt->second);
    };
    for (auto &[B, V] : Loaded)
      fieldLink(B, V);
    for (auto &[B, V] : Stored)
      fieldLink(B, V);
    if (snapshot() == Before && !WidthsChanged)
      return;
    // Merge into Acc so the next round sees the new facts through
    // the same widest-wins rule (sizes, nonzero flags, and observed
    // widths follow, so the scalar test and conflict evidence account
    // for propagated accesses too).
    for (auto &[C, Offs] : XAcc)
      for (auto [Off, Bytes] : Offs) {
        unsigned &W = Acc[C][Off];
        W = std::max(W, Bytes);
        AccSizes[C].insert(Bytes);
        NonZeroAccess[C] |= Off != 0;
        Observed[C][Off].insert(Bytes);
      }
  }
  Dropped.FixpointTruncated = true;
}

void Types::share() {
    std::map<int, int> Block;
    for (auto &[C, L] : Layouts)
      Block[C] = 0;
    for (size_t Count = 1;;) {
      std::map<std::vector<int64_t>, int> Keys;
      std::map<int, int> Next;
      for (auto &[C, L] : Layouts) {
        std::vector<int64_t> K{Block[C], L.Scalar};
        for (const Field &F : L.Fields) {
          auto P = Block.find(F.Pointee);
          K.insert(K.end(), {F.Off, F.Bytes, P == Block.end() ? -1 : P->second});
        }
        Next[C] = Keys.try_emplace(K, (int)Keys.size()).first->second;
      }
      Block = std::move(Next);
      if (Keys.size() == Count)
        break;
      Count = Keys.size();
    }
    std::map<int, std::string> Names;
    for (auto &[C, L] : Layouts)
      L.Name = Names.try_emplace(Block[C], "struct s" + std::to_string(Names.size() + 1))
                   .first->second;
}

int Types::pointeeAt(Base B) {
    if (pointerRoot(B.Root)) {
      auto L = Layouts.find(classOf(B.Root));
      if (L == Layouts.end() || L->second.Scalar)
        return -1;
      const Field *F = L->second.at(B.Off, 8);
      return F ? F->Pointee : -1;
    }
    auto Fr = Frames.find(B.Root);
    if (Fr == Frames.end())
      return -1;
    for (const Field &E : Fr->second.Fields)
      if (E.Embed >= 0 && E.Off <= B.Off && B.Off < E.Off + (int64_t)E.Bytes) {
        const Field *F = Layouts.at(E.Embed).at(B.Off - E.Off, 8);
        return F ? F->Pointee : -1;
      }
    return -1;
}

bool Types::embed(const Value *R, int64_t Off, int C) {
    auto Fr = Frames.find(R);
    auto Lt = Layouts.find(C);
    if (Fr == Frames.end() || Lt == Layouts.end() || Lt->second.Scalar)
      return false;
    Layout &L = Fr->second;
    int64_t End = Off + (int64_t)Lt->second.Size;
    if (Off < 0 || End > (int64_t)L.Size)
      return false;
    for (const Field &F : L.Fields)
      if (F.Embed >= 0 && F.Off < End && Off < F.Off + (int64_t)F.Bytes)
        return false;
    L.Fields.erase(std::remove_if(L.Fields.begin(), L.Fields.end(),
                                  [&](const Field &F) {
                                    return F.Off < End && Off < F.Off + (int64_t)F.Bytes;
                                  }),
                   L.Fields.end());
    Field E{Off, (unsigned)Lt->second.Size, -1, C, slotName(L, Off)};
    L.Fields.insert(std::lower_bound(L.Fields.begin(), L.Fields.end(), E,
                                     [](const Field &A, const Field &B) { return A.Off < B.Off; }),
                    E);
    return true;
}

std::string Types::slotName(const Layout &L, int64_t Off) {
    if (L.Below < 0)
      return "f_" + hex(Off).substr(2);
    int64_t Rel = Off - L.Below;
    return Rel < 0 ? "var_" + hex(-Rel).substr(2) : "arg_" + hex(Rel).substr(2);
}

std::string Types::ptrTy(int C) {
    const Layout &L = Layouts.at(C);
    if (!L.Scalar)
      return L.Name + " *";
    return fieldTy(L.Fields[0]) + " *";
}

static std::string canonInt(unsigned Bytes, const std::string &Asserted) {
    // Canonicalize a declared integer alias to its width/signedness-stable
    // spelling: `long` is 8 bytes on the host but may be 4 on the guest
    // (Win64 LLP64), so printing the alias literally would move offsets.
    // Width-implied `intN_t`/`uintN_t` spell the same bytes everywhere;
    // non-integer spellings (float/double/bool/pointers/structs/enums)
    // pass through verbatim.
    std::string Flat;
    Flat.reserve(Asserted.size());
    for (char C : Asserted) Flat += (char)tolower((unsigned char)C);
    std::vector<std::string> words;
    {
      std::string W;
      for (size_t I = 0; I <= Flat.size(); ++I) {
        bool End = I == Flat.size() || Flat[I] == ' ' || Flat[I] == '\t';
        if (!End) W += Flat[I];
        else if (!W.empty()) {
          if (W != "const" && W != "volatile" && W != "signed") words.push_back(W);
          W.clear();
        }
      }
    }
    auto has = [&](const char *W) {
      return std::find(words.begin(), words.end(), W) != words.end();
    };
    bool Unsigned = has("unsigned");
    bool NonInt = has("bool") || has("_bool") || has("float") || has("double") ||
                  Asserted.find('*') != std::string::npos ||
                  Asserted.find("struct") != std::string::npos ||
                  Asserted.find("union") != std::string::npos ||
                  Asserted.find("enum") != std::string::npos;
    if (NonInt) return Asserted;
    bool IsInt = has("char") || has("short") || has("int") || has("long") ||
                 has("int8_t") || has("int16_t") || has("int32_t") || has("int64_t") ||
                 has("uint8_t") || has("uint16_t") || has("uint32_t") || has("uint64_t") ||
                 has("u8") || has("u16") || has("u32") || has("u64") ||
                 has("i8") || has("i16") || has("i32") || has("i64");
    if (!IsInt) return Asserted;
    std::string Prefix = Unsigned ? "uint" : "int";
    switch (Bytes) {
    case 1: return Prefix + "8_t";
    case 2: return Prefix + "16_t";
    case 4: return Prefix + "32_t";
    case 8: return Prefix + "64_t";
    case 16: return std::string(Unsigned ? "biara_u128" : "biara_i128");
    default: return Asserted;
    }
}
std::string Types::fieldTy(const Field &F) {
    if (!F.Asserted.empty())
        return canonInt(F.Bytes, F.Asserted);
    if (F.Embed >= 0)
      return Layouts.at(F.Embed).Name;
    if (F.Pointee >= 0) {
      const Layout &P = Layouts.at(F.Pointee);
      // Scalar pointees of scalar pointers are kept out of recursion.
      if (!P.Scalar || P.Fields[0].Pointee < 0)
        return ptrTy(F.Pointee);
    }

    return uintTy(F.Bytes * 8);
}
size_t Types::debugFrames(Module &M) {
    size_t Renamed = 0;
    for (auto &[Root, L] : Frames) {
      auto *A = dyn_cast<AllocaInst>(Root);
      if (!A || L.Below < 0)
        continue;
      const Function &Fn = *A->getFunction();
      const Value *FrameRoot = Root;
      auto Objects = debugObjectsOf(Fn, M.getContext());
      std::set<std::string> Taken;
      for (auto &Fd : L.Fields)
        Taken.insert(Fd.Name);
      for (auto &Fd : L.Fields) {
        int64_t Rel = Fd.Off - L.Below;
        const DebugObj *Chosen = nullptr;
        bool Conflict = false, Accessed = false;
        for (const DebugObj &O : Objects)
          if (O.Rel == Rel && O.Size == Fd.Bytes) {
            if (Chosen && (O.Name != Chosen->Name || O.Type != Chosen->Type))
              Conflict = true;
            Chosen = &O;
          }
        if (!Chosen || Conflict || Chosen->Name.empty())
          continue;
        for (const Instruction &I : instructions(Fn)) {
          auto check = [&](const Value *Ptr, uint64_t Bytes) {
            Base B = base(const_cast<Value *>(Ptr), DL);
            if (B.Root != FrameRoot || (__int128)B.Off + Bytes <= Fd.Off ||
                B.Off >= (__int128)Fd.Off + Fd.Bytes)
              return;
            Accessed = true;
            auto PCs = pcsOf(I, M.getContext());
            if (PCs.empty())
              Conflict = true;
            for (uint64_t PC : PCs) {
              bool Covered = false;
              for (const DebugObj &O : Objects)
                Covered |= O.Rel == Rel && O.Size == Fd.Bytes && O.Name == Chosen->Name &&
                           O.Type == Chosen->Type && O.Start <= PC && PC < O.End;
              Conflict |= !Covered;
            }
          };
          if (auto *Load = dyn_cast<LoadInst>(&I))
            check(Load->getPointerOperand(), DL.getTypeStoreSize(Load->getType()));
          else if (auto *Store = dyn_cast<StoreInst>(&I))
            check(Store->getPointerOperand(), DL.getTypeStoreSize(Store->getValueOperand()->getType()));
          else if (auto *Call = dyn_cast<CallBase>(&I))
            for (Value *Arg : Call->args())
              if (Arg->getType()->isIntegerTy(64) || Arg->getType()->isPointerTy())
                check(Arg, 1);
        }
        std::string Name = ident(Chosen->Name);
        if (Accessed && !Conflict && (Name == Fd.Name || !Taken.count(Name))) {
          Taken.erase(Fd.Name);
          Fd.Name = Name;
          Fd.Debug = true;
          Taken.insert(Name);
          ++Renamed;
        }
      }
    }
    return Renamed;
}

// User-declared struct bindings over shared layouts, applied per bound
// lane only (never by shape matching across unrelated layouts). Each
// request names one layout class plus the declared fields; the class
// takes the declared struct name, covered fields take declared names
// and asserted types, declared padding gaps are preserved, and extra
// declared fields beyond the recovered extent ride along as asserted
// members. Width mismatches on covered fields leave the layout
// untouched (the caller validates them first).
int Types::bindStructs(const std::vector<std::tuple<int, std::string, std::vector<Field>>> &Binds) {
    int Renamed = 0;
    for (auto &[Class, Name, Fields] : Binds) {
        auto It = Layouts.find(Class);
        if (It == Layouts.end() || It->second.Scalar)
            continue;
        Layout &L = It->second;
        bool Covers = !L.Fields.empty();
        for (const Field &F : L.Fields) {
            bool Hit = false;
            for (const Field &D : Fields)
                if (D.Off == F.Off && D.Bytes == F.Bytes) {
                    Hit = true;
                    break;
                }
            if (!Hit) {
                Covers = false;
                break;
            }
        }
        if (!Covers)
            continue;
        L.Name = "struct " + Name;
        std::map<int64_t, Field> Merged;
        for (const Field &F : L.Fields)
            Merged[F.Off] = F;
        for (const Field &D : Fields) {
            auto F = Merged.find(D.Off);
            if (F != Merged.end() && F->second.Bytes == D.Bytes) {
                F->second.Name = D.Name;
                F->second.Asserted = D.Asserted;
                F->second.Debug = true;
            } else if (F == Merged.end()) {
                Field Extra;
                Extra.Off = D.Off;
                Extra.Bytes = D.Bytes;
                Extra.Name = D.Name;
                Extra.Asserted = D.Asserted;
                Extra.Debug = true;
                Merged[D.Off] = Extra;
                if (D.Off + (int64_t)D.Bytes > (int64_t)L.Size)
                    L.Size = D.Off + D.Bytes;
            }
        }
        L.Fields.clear();
        for (auto &[Off, F] : Merged)
            L.Fields.push_back(F);
        ++Renamed;
    }
    return Renamed;
}

struct BiaraLayouts {
  Types T;
  // Export state, computed once from T (module/function/IR order).
  struct Export {
    // Shared layouts in emission order; id = index.
    struct Shared {
      int Class;
      std::string Name;
    };
    std::vector<Shared> Order;
    std::map<int, uint32_t> IdOf; // class representative -> id
    struct Binding {
      uint64_t Function; // guest entry
      uint32_t Index;    // LLVM parameter index, or UINT32_MAX for return
      int64_t Offset;
      int Class; // -1 when the slot carries no layout
    };
    std::vector<Binding> Args, Rets;
    struct FrameOut {
      uint64_t Function;
      std::string FuncName, LayoutName;
      uint64_t Size;
      struct FieldOut {
        int64_t Off;
        unsigned Bytes;
        int32_t Pointee; // shared id, or -1
        int32_t Embed;   // shared id, or -1
        std::string Name;
        bool Debug;
      };
      std::vector<FieldOut> Fields;
    };
    std::vector<FrameOut> Frames;
  };
  Export E;

  explicit BiaraLayouts(const DataLayout &DL) : T(DL) {}
};

void computeExport(BiaraLayouts &L, Module &M) {
  L.E.Order.clear();
  L.E.IdOf.clear();
  L.E.Args.clear();
  L.E.Rets.clear();
  L.E.Frames.clear();
  // Shared layouts in deterministic order: one id per printed structure.
  // `share()` gives every structurally equal class the same `Name`; the id
  // is assigned per unique name (first class in deterministic order wins),
  // so two classes sharing `struct s1` export one layout id, and bindings
  // referencing either class resolve to it.
  std::vector<std::pair<int, const Layout *>> Sorted;
  for (auto &[C, Lt] : L.T.Layouts)
    Sorted.push_back({C, &Lt});
  std::sort(Sorted.begin(), Sorted.end(), [](auto &A, auto &B) {
    if (A.second->Name != B.second->Name)
      return A.second->Name < B.second->Name;
    return A.first < B.first;
  });
  std::map<std::string, uint32_t> IdByName;
  for (auto &[C, Lt] : Sorted) {
    (void)Lt;
    auto [It, New] = IdByName.try_emplace(L.T.Layouts.at(C).Name, (uint32_t)L.E.Order.size());
    if (New)
      L.E.Order.push_back({C, L.T.Layouts.at(C).Name});
    L.E.IdOf[C] = It->second;
  }
  auto sharedId = [&](int C) -> int32_t {
    if (C < 0)
      return -1;
    auto It = L.E.IdOf.find(L.T.rep(C));
    return It == L.E.IdOf.end() ? -1 : (int32_t)It->second;
  };
  // Argument/return bindings in module/function/parameter order. `arg` is
  // the LLVM parameter index (position i describes LLVM parameter i,
  // including any hidden-sret pointer and stack slots); `function` is the
  // guest entry address. Offsets are the base offsets of the bound roots
  // (0 for direct parameters; retained so offset-pointer facts stay
  // visible rather than silently normalized).
  for (Function &Fn : M) {
    if (Fn.isDeclaration())
      continue;
    auto Entry = entryOf(Fn, M.getContext());
    if (!Entry)
      continue;
    unsigned K = 0;
    for (Argument &A : Fn.args()) {
      int C = L.T.classOf(&A);
      int64_t Off = 0;
      L.E.Args.push_back({*Entry, K++, Off, C >= 0 && L.T.Layouts.count(C) ? C : -1});
    }
    Type *RT = Fn.getReturnType();
    if (!RT->isVoidTy()) {
      // A shared return layout requires agreement on every return path.
      int C = -1;
      bool Seen = false, Consistent = true;
      for (BasicBlock &BB : Fn)
        for (Instruction &I : BB)
          if (auto *R = dyn_cast<ReturnInst>(&I))
            if (R->getNumOperands()) {
              Base B = base(R->getOperand(0), L.T.DL);
              int CC = B.Off == 0 && pointerRoot(B.Root) ? L.T.classOf(B.Root) : -1;
              int32_t Id = sharedId(CC);
              if (Id < 0 || (Seen && Id != sharedId(C)))
                Consistent = false;
              if (!Seen)
                C = CC;
              Seen = true;
            }
      L.E.Rets.push_back({*Entry, UINT32_MAX, 0, Seen && Consistent ? C : -1});
    }
}
  // Frames in deterministic FrameOrder (module/global/instruction order).
  std::vector<std::pair<const Value *, const Layout *>> FSorted;
  for (auto &[R, Lt] : L.T.Frames)
    FSorted.push_back({R, &Lt});
  std::sort(FSorted.begin(), FSorted.end(), [&](auto &A, auto &B) {
    auto LA = L.T.FrameOrder.find(A.first), LB = L.T.FrameOrder.find(B.first);
    unsigned OA = LA == L.T.FrameOrder.end() ? UINT32_MAX : LA->second;
    unsigned OB = LB == L.T.FrameOrder.end() ? UINT32_MAX : LB->second;
    if (OA != OB)
      return OA < OB;
    return A.second->Name < B.second->Name;
  });
  for (auto &[R, Lt] : FSorted) {
    BiaraLayouts::Export::FrameOut F;
    if (auto *A = dyn_cast<AllocaInst>(R)) {
      const Function *Fn = A->getFunction();
      auto Entry = Fn ? entryOf(*Fn, M.getContext()) : std::nullopt;
      F.Function = Entry.value_or(0);
      F.FuncName = Fn ? Fn->getName().str() : "";
    } else if (auto *G = dyn_cast<GlobalVariable>(R)) {
      F.Function = 0;
      F.FuncName = G->getName().str();
    }
    F.LayoutName = Lt->Name;
    F.Size = Lt->Size;
    for (const Field &Fd : Lt->Fields)
      F.Fields.push_back({Fd.Off, Fd.Bytes, sharedId(Fd.Pointee), sharedId(Fd.Embed), Fd.Name,
                          Fd.Debug});
    L.E.Frames.push_back(std::move(F));
}
  (void)sharedId;
}

// Conflicts: overlapping incompatible accesses at one offset, including
// widths that arrived through cross-call propagation. Two sources feed
// this, both explicit (the renderer leaves overlaps to casts):
// - `Observed`: every width ever seen at (class, offset), including
//   widths that lost widest-wins. Two distinct widths at one offset are
//   a conflict even when one dominates the other.
// - overlapping ranges: an access starting strictly inside another access
//   with a different width, as the field builder resolved it by
//   first-come order rather than type assertion.
std::string conflictsJson(const BiaraLayouts &L) {
  std::string S = "[";
  bool First = true;
  // Classes that share a printed structure report under one layout id.
  auto layoutOfClass = [&](int C) -> std::string {
    auto Id = L.E.IdOf.find(C);
    return Id == L.E.IdOf.end() ? "null" : std::to_string(Id->second);
  };
  auto emit = [&](int C, int64_t Off, std::vector<unsigned> Widths) {
    std::sort(Widths.begin(), Widths.end());
    Widths.erase(std::unique(Widths.begin(), Widths.end()), Widths.end());
    if (Widths.size() < 2)
      return;
    S += (First ? "" : ",") + std::string("{\"layout\":") + layoutOfClass(C) + ",\"off\":" +
         std::to_string(Off) + ",\"widths\":[";
    for (size_t K = 0; K < Widths.size(); ++K)
      S += (K ? "," : "") + std::to_string(Widths[K]);
    S += std::string("],\"detail\":") +
         jsonStr("overlapping accesses at one offset; renderer uses casts") + "}";
    First = false;
  };
  std::set<std::pair<int, int64_t>> Done;
  for (auto &[C, Offs] : L.T.Observed)
    for (auto &[Off, Widths] : Offs)
      if (Widths.size() >= 2) {
        emit(C, Off, std::vector<unsigned>(Widths.begin(), Widths.end()));
        Done.insert({C, Off});
      }
  for (auto &[C, Offs] : L.T.Acc) {
    // Sorted (offset, bytes) pairs; any pair whose start lies strictly
    // inside the previous access is an overlap the field builder resolved
    // by first-come order rather than by type assertion.
    int64_t PrevEnd = INT64_MIN;
    int64_t PrevOff = INT64_MIN;
    unsigned PrevBytes = 0;
    for (auto [Off, Bytes] : Offs) {
      if (PrevEnd != INT64_MIN && Off < PrevEnd && Off != PrevOff &&
          !Done.count({C, Off}) && !Done.count({C, PrevOff})) {
        emit(C, Off, {PrevBytes, Bytes});
        Done.insert({C, Off});
      }
      if (PrevEnd == INT64_MIN || Off + (int64_t)Bytes > PrevEnd) {
        PrevOff = Off;
        PrevBytes = Bytes;
        PrevEnd = Off + (int64_t)Bytes;
      }
    }
  }
  return S + "]";
}

std::string exportJson(const BiaraLayouts &L) {
  const Limits &D = L.T.Dropped;
  bool Complete =
      !D.FixpointTruncated && D.CappedOffsets == 0 && D.UnsupportedBases == 0 &&
      D.OverflowedOffsets == 0;
  std::string S = "{\"status\":";
  if (Complete) {
    S += "\"complete\"";
  } else {
    S += "{\"truncated\":{\"iterations\":" + std::to_string(D.Iterations) + ",\"cap\":" +
         std::to_string(D.IterationCap) + "}}";
}
  S += ",\"layouts\":[";
  bool First = true;
  for (auto &Sh : L.E.Order) {
    const Layout &Lt = L.T.Layouts.at(Sh.Class);
    auto This = L.E.IdOf.find(Sh.Class);
    uint32_t ThisId = This == L.E.IdOf.end() ? UINT32_MAX : This->second;
    S += (First ? "" : ",") + std::string("{\"id\":") + std::to_string(ThisId) +
         ",\"name\":" + jsonStr(Lt.Name) + ",\"size\":" + std::to_string(Lt.Size) +
         ",\"scalar\":" + (Lt.Scalar ? "true" : "false") + ",\"fields\":[";
    bool FF = true;
    for (const Field &F : Lt.Fields) {
      auto P = L.E.IdOf.find(F.Pointee >= 0 ? L.T.rep(F.Pointee) : -1);
      S += (FF ? "" : ",") + std::string("{\"off\":") + std::to_string(F.Off) + ",\"bytes\":" +
           std::to_string(F.Bytes) + ",\"pointee\":" +
           (F.Pointee >= 0 && P != L.E.IdOf.end() ? std::to_string(P->second) : "null") +
           ",\"name\":" + jsonStr(F.Name) + ",\"asserted\":" + jsonStr(F.Asserted) + "}";
      FF = false;
    }
    S += "],\"functions\":[";
    bool GF = true;
    for (auto &B : L.E.Args) {
      if (B.Class < 0)
        continue;
      auto BI = L.E.IdOf.find(L.T.rep(B.Class));
      if (BI != L.E.IdOf.end() && BI->second == ThisId) {
        S += (GF ? "" : ",") + std::to_string(B.Function);
        GF = false;
      }
    }
    S += "]}";
    First = false;
  }
  S += "],\"frames\":[";
  First = true;
  for (auto &F : L.E.Frames) {
    S += (First ? "" : ",") + std::string("{\"function\":") + std::to_string(F.Function) +
         ",\"name\":" + jsonStr(F.FuncName) + ",\"layout\":" + jsonStr(F.LayoutName) + ",\"size\":" +
         std::to_string(F.Size) + ",\"fields\":[";
    bool FF = true;
    for (auto &Fd : F.Fields) {
      S += (FF ? "" : ",") + std::string("{\"off\":") + std::to_string(Fd.Off) + ",\"bytes\":" +
           std::to_string(Fd.Bytes) + ",\"pointee\":" +
           (Fd.Pointee >= 0 ? std::to_string(Fd.Pointee) : "null") + ",\"name\":" +
           jsonStr(Fd.Name) + "}";
      FF = false;
    }
    S += "],\"embedded\":[";
    bool EF = true;
    for (auto &Fd : F.Fields)
      if (Fd.Embed >= 0) {
        S += (EF ? "" : ",") + std::string("{\"off\":") + std::to_string(Fd.Off) +
             ",\"layout\":" + std::to_string(Fd.Embed) + "}";
        EF = false;
      }
    S += "]}";
    First = false;
}
  S += "],\"args\":[";
  First = true;
  for (auto &B : L.E.Args) {
    auto Id = B.Class >= 0 ? L.E.IdOf.find(L.T.rep(B.Class)) : L.E.IdOf.end();
    S += (First ? "" : ",") + std::string("{\"function\":") + std::to_string(B.Function) +
         ",\"arg\":" + std::to_string(B.Index) + ",\"layout\":" +
         (Id == L.E.IdOf.end() ? "null" : std::to_string(Id->second)) +
         ",\"offset\":" + std::to_string(B.Offset) + "}";
    First = false;
}
  S += "],\"returns\":[";
  First = true;
  for (auto &B : L.E.Rets) {
    auto Id = B.Class >= 0 ? L.E.IdOf.find(L.T.rep(B.Class)) : L.E.IdOf.end();
    S += (First ? "" : ",") + std::string("{\"function\":") + std::to_string(B.Function) +
         ",\"layout\":" + (Id == L.E.IdOf.end() ? "null" : std::to_string(Id->second)) + "}";
    First = false;
}
  S += std::string("],\"conflicts\":") + conflictsJson(L);
  S += ",\"limits\":{\"iterations\":" + std::to_string(D.Iterations) +
       ",\"iteration_cap\":" + std::to_string(D.IterationCap) +
       ",\"max_field_offset\":" + std::to_string(kMaxField) +
       ",\"capped_offsets\":" + std::to_string(D.CappedOffsets) +
       ",\"unsupported_bases\":" + std::to_string(D.UnsupportedBases) +
       ",\"overflowed_offsets\":" + std::to_string(D.OverflowedOffsets) + "}}";
  return S;
}

} // namespace biara_layouts

struct BiaraLayouts : biara_layouts::BiaraLayouts {
  using biara_layouts::BiaraLayouts::BiaraLayouts;
};

biara_layouts::Types &biara_layouts::biara_layouts_types(::BiaraLayouts *L) {
  return L->T;
}

extern "C" {

int biara_layouts_entry(LLVMValueRef FnRef, uint64_t *Entry) {
  auto *Fn = unwrap<Function>(FnRef);
  auto Address = biara_layouts::entryOf(*Fn, Fn->getContext());
  if (!Address)
    return 0;
  *Entry = *Address;
  return 1;
}
int biara_layouts_u32_metadata(LLVMValueRef FnRef, const char *Key, uint32_t Index,
                               uint32_t *Value) {
  auto *MD = unwrap<Function>(FnRef)->getMetadata(Key);
  if (!MD || Index >= MD->getNumOperands())
    return 0;
  auto *C = mdconst::dyn_extract<ConstantInt>(MD->getOperand(Index));
  if (!C || C->getValue().getActiveBits() > 32)
    return 0;
  *Value = static_cast<uint32_t>(C->getZExtValue());
  return 1;
}


BiaraLayouts *biara_layouts_build(LLVMModuleRef MRef, const struct BiaraCField *Cpu, size_t NCpu) {
  Module &M = *unwrap(MRef);
  try {
    auto L = std::make_unique<BiaraLayouts>(M.getDataLayout());
    L->T.build(M, std::vector<BiaraCField>(Cpu, Cpu + NCpu));
    L->T.debugFrames(M);
    biara_layouts::computeExport(*L, M);
    return L.release();
  } catch (...) {
    return nullptr;
}
}

int biara_layouts_apply_debug(BiaraLayouts *L, LLVMModuleRef MRef) {
  if (!L)
    return 1;
  try {
    Module &M = *unwrap(MRef);
    L->T.debugFrames(M);
    biara_layouts::computeExport(*L, M);
    return 0;
  } catch (...) {
    return 1;
  }
}

int biara_layouts_bind_structs(BiaraLayouts *L, const int *Classes, const struct BiaraStruct *Structs, size_t NBinds) {
  if (!L)
    return -1;
  try {
    std::vector<std::tuple<int, std::string, std::vector<biara_layouts::Field>>> Binds;
    for (size_t I = 0; I < NBinds; ++I) {
      if (!Structs[I].name)
        return -1;
      std::vector<biara_layouts::Field> Fields;
      for (size_t K = 0; K < Structs[I].nfields; ++K) {
        if (!Structs[I].fields[K].name || !Structs[I].fields[K].type)
          return -1;
        biara_layouts::Field F;
        F.Off = Structs[I].fields[K].off;
        F.Bytes = Structs[I].fields[K].bytes;
        F.Name = Structs[I].fields[K].name;
        F.Asserted = Structs[I].fields[K].type;
        Fields.push_back(F);
      }
      Binds.push_back({Classes[I], Structs[I].name, Fields});
    }
    return L->T.bindStructs(Binds);
  } catch (...) {
    return -1;
  }
}

int biara_layouts_json(const BiaraLayouts *L, BiaraWrite Write, void *Ctx) {
  if (!L)
    return 1;
  try {
    std::string S = biara_layouts::exportJson(*L);
    return Write(Ctx, S.data(), S.size());
  } catch (...) {
    return 1;
}
}

void biara_layouts_free(BiaraLayouts *L) { delete L; }

} // extern "C"
