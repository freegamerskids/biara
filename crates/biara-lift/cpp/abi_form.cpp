// ABI form (see src/decompile.rs): rewrite a lifted module, whose functions
// are `void f(ptr %env)` over the whole guest state, into functions with
// the recovered calling conventions: register arguments and stack
// arguments as parameters, return registers as the result.
//
// Per function, every guest register lives in an alloca of its own and the
// stack frame is an alloca too, so that SROA turns registers and frame
// slots that never escape into SSA values. Calls become calls with
// arguments; the rest of the CPU state (vector and FPU registers, state
// that helpers read) is one global byte array, `biara_cpu`, that helpers
// receive as `env`. Uses the C++ API for splicing bodies between functions
// and RAUW across argument types.

#include "llvm-c/Types.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/ADT/SmallVector.h"

#include <algorithm>
#include <cstdint>
#include <cstring>


#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using namespace llvm;

extern "C" {
// A guest register (TCG global in env).
struct BiaraReg {
  int64_t home; // offset in env
  uint32_t bits;
  const char *name;
  // Thread state (segment bases): read from the CPU state on entry rather
  // than passed.
  uint32_t thread;
};

// ABI value kind per parameter/result slot: the native LLVM type the slot
// lowers to. Integer/pointer slots stay integers/pointers (never fp
// bitcasts, so layout recovery's integer/pointer roots keep working);
// unknown/conflict slots stay raw words.
enum {
  BIARA_KIND_I32 = 0,
  BIARA_KIND_I64 = 1,
  BIARA_KIND_F32 = 2,
  BIARA_KIND_F64 = 3,
  BIARA_KIND_VEC128 = 4,
  BIARA_KIND_PTR = 5,
  BIARA_KIND_SRET = 6,
  BIARA_KIND_RAW = 7,
  BIARA_KIND_CONFLICT = 8,
  BIARA_KIND_I8 = 9,
  BIARA_KIND_I16 = 10,
  BIARA_KIND_BOOL = 11,
  BIARA_KIND_I32DECL = 12
};

// How a return value travels: direct value, two-element aggregate, or
// hidden-`sret` pointer parameter. `Memory` records the
// store-through-pointer fact, never a fabricated source struct type.
enum { BIARA_RET_DIRECT = 0, BIARA_RET_PAIR = 1, BIARA_RET_MEMORY = 2 };

enum { BIARA_CALL_DIRECT = 0, BIARA_CALL_IMPORT = 1, BIARA_CALL_INDIRECT = 2, BIARA_CALL_SYSCALL = 3 };

// The recovered signature of a lifted function.
struct BiaraSig {
  LLVMValueRef fn;
  const uint32_t *args; // register indices, in parameter order
  uint32_t nargs;
  const int64_t *stack_args; // offsets from the entry stack pointer
  uint32_t nstack;
  const uint32_t *rets; // register indices
  uint32_t nrets;
  uint64_t below; // frame bytes below the entry stack pointer
  uint64_t above; // frame bytes from the entry stack pointer up
  uint64_t entry; // guest address
  uint32_t balanced; // the frame restores the stack pointer on return
  const uint32_t *preserved; // registers kept, in the analysis's order
  uint32_t npreserved;
  // Per-parameter ABI kinds (`BIARA_KIND_*`, length `nargs + nstack`;
  // stack slots carry their declared scalar kind: `I64` by default,
  // `I8`/`I16`/`I32DECL`/`BOOL` for declared narrow/boolean spilled
  // scalars, coerced bit-exactly at the slot boundary). Null means
  // all-integer (the previous raw-word behavior).
  const uint32_t *arg_kinds;
  // Per-result ABI kinds (`BIARA_KIND_*`, length `nrets`; null means
  // all-integer). A single `F32`/`F64`/`VEC128` result is that LLVM type;
  // a `PAIR` return is a two-element struct of its member kinds.
  const uint32_t *ret_kinds;
  // Return shape (`BIARA_RET_*`).
  uint32_t ret_class;
  // Hidden-`sret` parameter position in the new function (`UINT32_MAX`
  // when `ret_class` is not `BIARA_RET_MEMORY`).
  uint32_t sret_param;
};


struct BiaraConv {
  uint32_t sp, pc; // register indices
  int64_t pop;     // what returning adds to the stack pointer at the call
  const uint32_t *args;
  uint32_t nargs;
  uint32_t ret;
  const uint32_t *sys_args;
  uint32_t nsys;
  uint32_t sys_ret;
  uint64_t env_size;
  uint64_t margin; // bytes of CPU state before env (negative offsets)
};

// What one `call` of the lifted module stands for.
struct BiaraCall {
  LLVMValueRef inst;
  uint32_t kind;
  const char *import; // BIARA_CALL_IMPORT
  uint32_t arity;     // arguments passed to unknown code; UINT32_MAX: infer
  uint64_t ret;       // return address; 0 for tail calls and escapes
};

// Helpers taking env and how they use the registers in it.
enum { BIARA_HELPER_READS = 1, BIARA_HELPER_WRITES = 2, BIARA_HELPER_PURE = 4 };
struct BiaraHelper {
  const char *symbol;
  uint32_t mode;
  // With `listed`, the registers it reads and writes through env (and no
  // others); otherwise any.
  uint32_t listed;
  const uint32_t *reads;
  uint32_t nreads;
  const uint32_t *writes;
  uint32_t nwrites;
};
} // extern "C"

namespace {

struct Former {
  Module &M;
  LLVMContext &Cx;
  const BiaraConv &Cv;
  std::vector<BiaraReg> Regs;
  std::unordered_map<int64_t, uint32_t> RegAt; // home -> register
  std::unordered_map<Function *, const BiaraSig *> Sigs;
  std::unordered_map<Function *, Function *> NewOf;
  std::set<uint32_t> DispatchReads, DispatchWrites;
  std::unordered_map<Instruction *, const BiaraCall *> Calls;
  std::unordered_map<std::string, const BiaraHelper *> HelperMode;
  GlobalVariable *Cpu = nullptr;
  Constant *Env = nullptr;
  // The env parameter of the function being rewritten.
  Argument *EnvArg = nullptr;
  // The lowering's promote alloca per register (its slot before ABI form);
  // sync stores load from these, so they set nothing either.
  std::vector<AllocaInst *> Promote;
  // One shared dispatcher: no per-call-site expansion of all functions.
  Function *Dispatch = nullptr;

  void dispatcher(const BiaraSig *Sigs, size_t N) {
    auto *Entry = BasicBlock::Create(Cx, "entry", Dispatch);
    auto *Other = BasicBlock::Create(Cx, "other", Dispatch);
    IRBuilder<> B(Entry);
    Value *Addr = Dispatch->getArg(0);
    SwitchInst *Sw = B.CreateSwitch(Addr, Other, N);
    for (size_t I = 0; I < N; ++I) {
      auto *Case = BasicBlock::Create(Cx, "", Dispatch);
      const BiaraSig &S = Sigs[I];
      Function *Fn = NewOf[unwrap<Function>(S.fn)];
      IRBuilder<> CallB(Case);
      std::vector<Value *> Args;
      Args.reserve(S.nargs + S.nstack);
      for (uint32_t A = 0; A < S.nargs; ++A)
        Args.push_back(readCpu(CallB, S.args[A], Fn->getFunctionType()->getParamType(A)));
      for (uint32_t A = 0; A < S.nstack; ++A) {
        Value *Sp = readCpu(CallB, Cv.sp, i64());
        Value *Address = CallB.CreateAdd(Sp, CallB.getInt64(S.stack_args[A]));
        Value *V = CallB.CreateLoad(i64(), CallB.CreateIntToPtr(Address, CallB.getPtrTy()));
        Type *Want = Fn->getFunctionType()->getParamType(S.nargs + A);
        if (Want->isIntegerTy() && Want->getIntegerBitWidth() < 64)
          V = CallB.CreateTrunc(V, Want);
        Args.push_back(V);
      }
      Value *Result = CallB.CreateCall(Fn, Args);
      for (uint32_t R = 0; R < S.nrets; ++R)
        writeCpu(CallB, S.rets[R], S.nrets == 1 ? Result : CallB.CreateExtractValue(Result, R));
      CallB.CreateRet(CallB.getTrue());
      Sw->addCase(ConstantInt::get(cast<IntegerType>(i64()), Sigs[I].entry), Case);
    }
    IRBuilder<> O(Other);
    O.CreateRet(O.getFalse());
  }

  Former(Module &M, const BiaraConv &Cv) : M(M), Cx(M.getContext()), Cv(Cv) {}
  Type *regTy(uint32_t R) { return IntegerType::get(Cx, Regs[R].bits); }
  bool fp(uint32_t R) const { return Regs[R].bits == 128; }
  Type *i64() { return Type::getInt64Ty(Cx); }
  Type *f32() { return Type::getFloatTy(Cx); }
  Type *f64() { return Type::getDoubleTy(Cx); }
  Type *vec128() { return FixedVectorType::get(Type::getFloatTy(Cx), 4); }

  // Native LLVM type of ABI slot `kind` over register `R`: bool/i8/i16/
  // i32-declared/float/double/vector spell the IR directly; pointers stay
  // pointers (never fp bitcasts); raw/conflict/integer slots stay the
  // register integer type. `readSlot`/`invoke`/`readCpu` extend narrow
  // slots back out, so guest bits never change.
  Type *slotTy(uint32_t R, uint32_t Kind) {
    switch (Kind) {
    case BIARA_KIND_BOOL:
      return Type::getInt1Ty(Cx);
    case BIARA_KIND_I8:
      return Type::getInt8Ty(Cx);
    case BIARA_KIND_I16:
      return Type::getInt16Ty(Cx);
    case BIARA_KIND_I32DECL:
      return Type::getInt32Ty(Cx);
    case BIARA_KIND_F32:
      return f32();
    case BIARA_KIND_F64:
      return f64();
    case BIARA_KIND_VEC128:
      return vec128();
    case BIARA_KIND_PTR:
    case BIARA_KIND_SRET:
      return PointerType::get(Cx, 0);
    default:
      return regTy(R);
    }
  }
  uint32_t argKind(const BiaraSig &S, uint32_t I) {
    return S.arg_kinds ? S.arg_kinds[I] : BIARA_KIND_I64;
  }

  uint32_t stackKind(const BiaraSig &S, uint32_t I) {
    return S.arg_kinds ? S.arg_kinds[S.nargs + I] : BIARA_KIND_I64;
  }

  uint32_t retKind(const BiaraSig &S, uint32_t I) {
    return S.ret_kinds ? S.ret_kinds[I] : BIARA_KIND_I64;
  }

  Type *retTy(const BiaraSig &S) {
    if (S.nrets == 0)
      return Type::getVoidTy(Cx);
    if (S.nrets == 1)
      return slotTy(S.rets[0], retKind(S, 0));
    std::vector<Type *> Fields;
    for (uint32_t I = 0; I < S.nrets; ++I)
      Fields.push_back(slotTy(S.rets[I], retKind(S, I)));
    return StructType::get(Cx, Fields);
  }

  // LLVM type of stack formal `I` (declared scalar kind or `i64`).
  Type *stackTy(const BiaraSig &S, uint32_t I) {
    uint32_t K = S.arg_kinds ? S.arg_kinds[S.nargs + I] : BIARA_KIND_I64;
    switch (K) {
    case BIARA_KIND_BOOL:
      return Type::getInt1Ty(Cx);
    case BIARA_KIND_I8:
      return Type::getInt8Ty(Cx);
    case BIARA_KIND_I16:
      return Type::getInt16Ty(Cx);
    case BIARA_KIND_I32DECL:
      return Type::getInt32Ty(Cx);
    default:
      return i64();
    }
  }

  void declare(const BiaraSig &S) {
    Function *Old = unwrap<Function>(S.fn);
    std::vector<Type *> Params;
    for (uint32_t I = 0; I < S.nargs; ++I)
      Params.push_back(slotTy(S.args[I], argKind(S, I)));
    for (uint32_t I = 0; I < S.nstack; ++I)
      Params.push_back(stackTy(S, I));
    auto *FTy = FunctionType::get(retTy(S), Params, false);
    std::string Name = Old->getName().str();
    Old->setName(Name + ".lifted");
    Function *New = Function::Create(FTy, GlobalValue::ExternalLinkage, Name, M);
    for (uint32_t I = 0; I < S.nargs; ++I)
      New->getArg(I)->setName(Regs[S.args[I]].name);
    for (uint32_t I = 0; I < S.nstack; ++I) {
      int64_t Off = S.stack_args[I];
      New->getArg(S.nargs + I)->setName("stack_" + std::to_string(Off));
    }
    // Preserve per-parameter/return ABI kinds through optimizer cloning:
    // `!biara.abi.args` holds one i32 kind per new-function parameter
    // (register slots then stack slots with declared scalar kinds),
    // `!biara.abi.rets` one per result slot, `!biara.abi.ret_class` the
    // return shape scalar. The summary reads these instead of re-deriving
    // types from bitcasts. Uses the C++ MDNode API directly (the file
    // otherwise avoids the C API here).
    {
      SmallVector<Metadata *, 8> Args;
      for (uint32_t I = 0; I < S.nargs + S.nstack; ++I) {
        uint32_t K = I < S.nargs ? argKind(S, I) : stackKind(S, I - S.nargs);
        Args.push_back(ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(Cx), K)));
      }
      New->setMetadata(Cx.getMDKindID("biara.abi.args"), MDNode::get(Cx, Args));
      SmallVector<Metadata *, 4> Rets;
      for (uint32_t I = 0; I < S.nrets; ++I)
        Rets.push_back(ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(Cx), retKind(S, I))));
      New->setMetadata(Cx.getMDKindID("biara.abi.rets"), MDNode::get(Cx, Rets));
      Metadata *RC = ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(Cx), S.ret_class));
      New->setMetadata(Cx.getMDKindID("biara.abi.ret_class"), MDNode::get(Cx, RC));
    }
    Sigs[Old] = &S;
    NewOf[Old] = New;
    for (uint32_t I = 0; I < S.nargs; ++I)
      if (!fp(S.args[I])) DispatchReads.insert(S.args[I]);
    if (S.nstack) DispatchReads.insert(Cv.sp);
    for (uint32_t I = 0; I < S.nrets; ++I)
      if (!fp(S.rets[I])) DispatchWrites.insert(S.rets[I]);
  }

  Value *cpuAt(IRBuilder<> &B, int64_t Off) {
    return B.CreateConstGEP1_64(B.getInt8Ty(), Env, Off);
  }

  Value *readCpu(IRBuilder<> &B, uint32_t R, Type *Want) {
    if (fp(R)) return B.CreateLoad(Want, cpuAt(B, Regs[R].home));
    Value *V = B.CreateLoad(regTy(R), cpuAt(B, Regs[R].home));
    if (V->getType() == Want) return V;
    if (Want->isPointerTy()) return B.CreateIntToPtr(V, Want);
    if (Want->isIntegerTy()) return B.CreateZExtOrTrunc(V, Want);
    return B.CreateBitCast(V, Want);
  }

  void writeCpu(IRBuilder<> &B, uint32_t R, Value *V) {
    if (!fp(R) && V->getType() != regTy(R)) {
      if (V->getType()->isPointerTy()) V = B.CreatePtrToInt(V, regTy(R));
      else if (V->getType()->isIntegerTy()) V = B.CreateZExtOrTrunc(V, regTy(R));
      else V = B.CreateBitCast(V, regTy(R));
    }
    B.CreateStore(V, cpuAt(B, Regs[R].home));
  }


  // Load register `R` from `Slot`, as integer `Ty` (zero-extended or
  // truncated). Integer-only: float/vector/pointer slots convert at their
  // own sites with bit-exact casts, never here.
  Value *loadAs(IRBuilder<> &B, AllocaInst *Slot, uint32_t R, Type *Ty) {
    Value *V = B.CreateLoad(regTy(R), Slot, Regs[R].name);
    assert(Ty->isIntegerTy() && V->getType()->isIntegerTy() &&
           "loadAs is integer-only; use bitcast/inttoptr for FP/vector/ptr");
    return B.CreateZExtOrTrunc(V, Ty);
  }

  Value *readSlot(IRBuilder<> &B, const std::vector<AllocaInst *> &Slot,
                  uint32_t R, Type *Want) {
    if (fp(R))
      return B.CreateLoad(Want, cpuAt(B, Regs[R].home), Regs[R].name);
    Value *V = B.CreateLoad(regTy(R), Slot[R], Regs[R].name);
    if (V->getType() == Want) return V;
    if (Want->isPointerTy()) return B.CreateIntToPtr(V, Want);
    if (Want->isIntegerTy()) return B.CreateZExtOrTrunc(V, Want);
    return B.CreateBitCast(V, Want);
  }

  void writeSlot(IRBuilder<> &B, const std::vector<AllocaInst *> &Slot,
                 uint32_t R, Value *V) {
    if (fp(R)) {
      // Scalar stores leave the remaining physical lane bytes untouched.
      B.CreateStore(V, cpuAt(B, Regs[R].home));
      return;
    }
    Type *Want = regTy(R);
    if (V->getType() != Want) {
      if (V->getType()->isPointerTy()) V = B.CreatePtrToInt(V, Want);
      else if (V->getType()->isIntegerTy()) V = B.CreateZExtOrTrunc(V, Want);
      else V = B.CreateBitCast(V, Want);
    }
    B.CreateStore(V, Slot[R]);
  }

  // Registers a call may change: everything, unless it is an intrinsic
  // (none), a helper (its listed writes, or none), or a lifted callee
  // (what its ABI does not preserve).
  std::set<uint32_t> clobbered(CallBase *CB) {
    std::set<uint32_t> W;
    for (uint32_t R = 0; R < Regs.size(); ++R)
      W.insert(R);
    if (isa<IntrinsicInst>(CB))
      W.clear();
    else if (Function *CF = CB->getCalledFunction()) {
      if (Sigs.count(CF)) {
        W.clear();
        for (uint32_t R = 0; R < Regs.size(); ++R)
          if (Sigs[CF]->balanced) {
            std::set<uint32_t> P(Sigs[CF]->preserved, Sigs[CF]->preserved + Sigs[CF]->npreserved);
            if (!P.count(R))
              W.insert(R);
          }
      } else if (HelperMode.count(CF->getName().str())) {
        const BiaraHelper &H = *HelperMode[CF->getName().str()];
        W.clear();
        if (H.mode & BIARA_HELPER_WRITES) {
          W.insert(H.writes, H.writes + H.nwrites);
          if (!H.listed)
            for (uint32_t R = 0; R < Regs.size(); ++R)
              W.insert(R);
        }
      }
    }
    return W;
  }

  // Arguments passed to unknown code: the convention's registers up to the
  // last one set on the way here (single predecessors, back through calls
  // that preserve them, to the entry), or that the function itself received
  // and no call clobbered.
  uint32_t inferArity(CallBase &Call, const std::vector<AllocaInst *> &Slot,
                      const std::vector<uint32_t> &Conv, const BiaraSig &S) {
    std::vector<bool> Set(Conv.size(), false), Live(Conv.size(), true);
    BasicBlock *BB = Call.getParent();
    Instruction *I = Call.getPrevNode();
    bool AtEntry = false;
    std::vector<BasicBlock *> Seen;
    for (;;) {
      for (; I; I = I->getPrevNode()) {
        if (auto *St = dyn_cast<StoreInst>(I)) {
          for (size_t K = 0; K < Conv.size(); ++K) {
            if (!Live[K])
              continue;
            if (St->getPointerOperand() == Slot[Conv[K]] ||
                (Promote[Conv[K]] && St->getPointerOperand() == Promote[Conv[K]])) {
              // A copy of the register's own value (entry loads, syncs,
              // reloads) sets nothing; anything else does, and ends the
              // search for this register.
              auto *V = dyn_cast<LoadInst>(St->getValueOperand());
              if (!V || (V->getPointerOperand() != Slot[Conv[K]] &&
                         V->getPointerOperand() != Promote[Conv[K]])) {
                Set[K] = true;
                Live[K] = false;
              }
            }
          }
        } else if (auto *CB = dyn_cast<CallBase>(I)) {
          for (uint32_t R : clobbered(CB))
            for (size_t K = 0; K < Conv.size(); ++K)
              if (Conv[K] == R)
                Live[K] = false;
        }
      }
      if (BB == &BB->getParent()->getEntryBlock()) {
        AtEntry = true;
        break;
      }
      BasicBlock *P = BB->getSinglePredecessor();
      if (!P || std::find(Seen.begin(), Seen.end(), P) != Seen.end())
        break;
      Seen.push_back(P);
      BB = P;
      I = &P->back();
    }
    uint32_t N = 0;
    for (size_t K = 0; K < Conv.size(); ++K) {
      bool Param = false;
      if (AtEntry && Live[K])
        for (uint32_t A = 0; A < S.nargs; ++A)
          Param |= S.args[A] == Conv[K];
      if (Set[K] || Param)
        N = K + 1;
    }
    return N;
  }

  bool form(const BiaraSig &S, std::string &Err) {
    Function *Old = unwrap<Function>(S.fn);
    Function *New = NewOf[Old];
    // A selected module carries native prototypes for known callees whose
    // bodies belong to other jobs. Only definitions have register/frame IR.
    if (Old->isDeclaration())
      return true;
    EnvArg = Old->getArg(0);
    New->splice(New->end(), Old);
    BasicBlock &Entry = New->getEntryBlock();
    IRBuilder<> B(&Entry, Entry.begin());

    std::vector<AllocaInst *> Slot(Regs.size());
    for (size_t R = 0; R < Regs.size(); ++R)
      if (!fp(R))
        Slot[R] = B.CreateAlloca(regTy(R), nullptr, std::string(Regs[R].name) + ".reg");
    auto *FrameTy = ArrayType::get(B.getInt8Ty(), S.below + S.above);
    AllocaInst *Frame = B.CreateAlloca(FrameTy, nullptr, "frame." + std::to_string(S.below));
    Frame->setAlignment(Align(16));
    Value *SpIn = B.CreateAdd(B.CreatePtrToInt(Frame, i64()), B.getInt64(S.below), "sp.in");
    B.CreateStore(B.CreateZExtOrTrunc(SpIn, regTy(Cv.sp)), Slot[Cv.sp]);
    B.CreateStore(ConstantInt::get(regTy(Cv.pc), S.entry), Slot[Cv.pc]);
    for (size_t R = 0; R < Regs.size(); ++R)
      if (Regs[R].thread)
        B.CreateStore(B.CreateLoad(regTy(R), cpuAt(B, Regs[R].home), Regs[R].name), Slot[R]);
    for (uint32_t I = 0; I < S.nargs; ++I)
      writeSlot(B, Slot, S.args[I], New->getArg(I));
    // Incoming stack parameters arrive in the caller's frame; copy them
    // into ours at the entry-stack-pointer-relative offsets, so guest
    // loads from those slots see the passed values. Without this the
    // slots read as undef and the optimizer folds the body away.
    // Declared narrow/boolean stack formals (`i8`/`i16`/`i32`/`i1`)
    // zero-extend into the 64-bit slot, bit-exactly.
    for (uint32_t I = 0; I < S.nstack; ++I) {
      Value *Addr = B.CreateAdd(SpIn, B.getInt64(S.stack_args[I]));
      Value *V = New->getArg(S.nargs + I);
      if (V->getType()->isIntegerTy() && V->getType()->getIntegerBitWidth() < 64)
        V = B.CreateZExt(V, i64());
      B.CreateStore(V, B.CreateIntToPtr(Addr, B.getPtrTy()));
    }
    Promote.assign(Regs.size(), nullptr);
    for (Instruction &I : Entry) {
      auto *St = dyn_cast<StoreInst>(&I);
      auto *V = St ? dyn_cast<LoadInst>(St->getValueOperand()) : nullptr;
      auto *G = V ? dyn_cast<GetElementPtrInst>(V->getPointerOperand()) : nullptr;
      auto *Off = G && G->getNumIndices() == 1 ? dyn_cast<ConstantInt>(G->getOperand(1)) : nullptr;
      auto *P = St ? dyn_cast<AllocaInst>(St->getPointerOperand()) : nullptr;
      if (!Off || !G->getSourceElementType()->isIntegerTy(8) || !P)
        continue;
      if (auto It = RegAt.find(Off->getSExtValue()); It != RegAt.end())
        Promote[It->second] = P;
    }
    // Register homes become the register's slot; stores to the state
    // before env (icount and I/O flags) go.
    std::vector<User *> Users(EnvArg->user_begin(), EnvArg->user_end());
    for (User *U : Users) {
      if (auto *G = dyn_cast<GetElementPtrInst>(U)) {
        auto *Off = G->getNumIndices() == 1 ? dyn_cast<ConstantInt>(G->getOperand(1)) : nullptr;
        if (!Off || !G->getSourceElementType()->isIntegerTy(8))
          continue;
        int64_t O = Off->getSExtValue();
        if (auto It = RegAt.find(O); It != RegAt.end()) {
          G->replaceAllUsesWith(Slot[It->second]);
          G->eraseFromParent();
        } else if (O < 0) {
          std::vector<User *> GU(G->user_begin(), G->user_end());
          for (User *X : GU)
            if (auto *St = dyn_cast<StoreInst>(X); St && St->getPointerOperand() == G)
              St->eraseFromParent();
        }
      } else if (auto *L = dyn_cast<LoadInst>(U)) {
        if (auto It = RegAt.find(0); It != RegAt.end())
          L->setOperand(0, Slot[It->second]);
      } else if (auto *St = dyn_cast<StoreInst>(U); St && St->getPointerOperand() == EnvArg) {
        if (auto It = RegAt.find(0); It != RegAt.end())
          St->setOperand(1, Slot[It->second]);
      }
    }

    std::vector<CallBase *> CallSites;
    std::vector<ReturnInst *> Rets;
    for (Instruction &I : instructions(*New)) {
      if (auto *CB = dyn_cast<CallBase>(&I); CB && !isa<IntrinsicInst>(CB))
        CallSites.push_back(CB);
      else if (auto *R = dyn_cast<ReturnInst>(&I))
        Rets.push_back(R);
    }
    std::vector<uint32_t> ConvArgs(Cv.args, Cv.args + Cv.nargs);
    std::vector<uint32_t> SysArgs(Cv.sys_args, Cv.sys_args + Cv.nsys);
    for (CallBase *CB : CallSites)
      if (!call(*CB, Slot, ConvArgs, SysArgs, S, Err))
        return false;
    for (ReturnInst *R : Rets) {
      IRBuilder<> RB(R);
      if (S.nrets == 0) {
        RB.CreateRetVoid();
      } else if (S.nrets == 1) {
        RB.CreateRet(readSlot(RB, Slot, S.rets[0], slotTy(S.rets[0], retKind(S, 0))));
      } else {
        Value *Agg = PoisonValue::get(retTy(S));
        for (uint32_t I = 0; I < S.nrets; ++I) {
          Value *V = readSlot(RB, Slot, S.rets[I], slotTy(S.rets[I], retKind(S, I)));
          Agg = RB.CreateInsertValue(Agg, V, I);
        }
        RB.CreateRet(Agg);
      }
      R->eraseFromParent();
    }
    EnvArg->replaceAllUsesWith(Env);
    return true;
  }

  // After a call returns to `Ret`: the stack pointer as the return leaves
  void resumed(IRBuilder<> &B, const std::vector<AllocaInst *> &Slot, Value *SpAtCall,
               uint64_t Ret) {
    B.CreateStore(B.CreateAdd(SpAtCall, ConstantInt::get(regTy(Cv.sp), Cv.pop)), Slot[Cv.sp]);
    if (Ret)
      B.CreateStore(ConstantInt::get(regTy(Cv.pc), Ret), Slot[Cv.pc]);
  }

  // Call unknown code (an import, a pointer) with the convention's
  // registers up to `Arity`.
  Value *callUnknown(IRBuilder<> &B, FunctionCallee Callee, const std::vector<AllocaInst *> &Slot,
                     const std::vector<uint32_t> &Conv, uint32_t Arity) {
    std::vector<Value *> Args;
    for (uint32_t K = 0; K < Arity && K < Conv.size(); ++K)
      Args.push_back(loadAs(B, Slot[Conv[K]], Conv[K], i64()));
    return B.CreateCall(Callee, Args);
  }

  FunctionCallee importDecl(StringRef Name) {
    auto *FTy = FunctionType::get(i64(), {}, /*isVarArg=*/true);
    if (Function *F = M.getFunction(Name); F && F->getFunctionType() == FTy)
      return {FTy, F};
    // A name taken by a lifted function: the import keeps its own.
    std::string N = M.getFunction(Name) ? (Name + ".import").str() : Name.str();
    return M.getOrInsertFunction(N, FTy);
  }

  // An x86 division helper (`idivq_EAX` etc.): a call to a prelude
  // function with QEMU's semantics (quotient of the RDX:RAX pair, or the
  // low half for widths below 64; a zero divisor or an overflowing quotient
  // raises, so a kept result is the plain C one). The caller already guards
  // a zero divisor.
  bool divOp(Function &Callee, CallBase &CB, IRBuilder<> &B,
             const std::vector<AllocaInst *> &Slot, std::string &Err) {
    static const struct { const char *N; const char *F; } Ops[] = {
        {"divb_AL", "biara_div8"},   {"idivb_AL", "biara_sdiv8"},
        {"divw_AX", "biara_div16"},  {"idivw_AX", "biara_sdiv16"},
        {"divl_EAX", "biara_div32"}, {"idivl_EAX", "biara_sdiv32"},
        {"divq_EAX", "biara_div64"}, {"idivq_EAX", "biara_sdiv64"},
    };
    StringRef N = Callee.getName();
    N.consume_front("helper_");
    const char *F = nullptr;
    for (const auto &O : Ops)
      if (N == O.N)
        F = O.F;
    if (!F)
      return false;
    auto reg = [&](const char *Want) -> uint32_t {
      for (size_t R = 0; R < Regs.size(); ++R)
        if (Regs[R].name == std::string(Want))
          return R;
      Err = std::string("div without ") + Want;
      return 0;
    };
    uint32_t Rax = reg("rax"), Rdx = reg("rdx");
    if (!Err.empty())
      return true;
    Type *QR = StructType::get(Cx, {i64(), i64()});
    FunctionCallee Fn =
        M.getOrInsertFunction(F, FunctionType::get(QR, {i64(), i64(), i64()}, false));
    Value *Lo = B.CreateLoad(regTy(Rax), Slot[Rax], "div.lo");
    Value *Hi = B.CreateLoad(regTy(Rdx), Slot[Rdx], "div.hi");
    Value *D = B.CreateZExtOrTrunc(CB.getArgOperand(1), i64());
    Value *QRv = B.CreateCall(
        Fn, {B.CreateZExtOrTrunc(Lo, i64()), B.CreateZExtOrTrunc(Hi, i64()), D}, "div.qr");
    B.CreateStore(B.CreateZExtOrTrunc(B.CreateExtractValue(QRv, 0), regTy(Rax)), Slot[Rax]);
    B.CreateStore(B.CreateZExtOrTrunc(B.CreateExtractValue(QRv, 1), regTy(Rdx)), Slot[Rdx]);
    CB.eraseFromParent();
    return true;
  }

  void invoke(IRBuilder<> &B, const BiaraSig &T,
              const std::vector<AllocaInst *> &Slot, Value *Sp, uint64_t Ret) {
    Function *Fn = NewOf[unwrap<Function>(T.fn)];
    std::vector<Value *> Args;
    Args.reserve(T.nargs + T.nstack);
    for (uint32_t I = 0; I < T.nargs; ++I)
      Args.push_back(readSlot(B, Slot, T.args[I], Fn->getFunctionType()->getParamType(I)));
    for (uint32_t I = 0; I < T.nstack; ++I) {
      Value *A = B.CreateAdd(B.CreateZExtOrTrunc(Sp, i64()), B.getInt64(T.stack_args[I]));
      Value *V = B.CreateLoad(i64(), B.CreateIntToPtr(A, B.getPtrTy()));
      Type *Want = Fn->getFunctionType()->getParamType(T.nargs + I);
      if (Want->isIntegerTy() && Want->getIntegerBitWidth() < 64)
        V = B.CreateTrunc(V, Want);
      Args.push_back(V);
    }
    CallInst *R = B.CreateCall(Fn, Args);
    for (uint32_t I = 0; I < T.nrets; ++I)
      writeSlot(B, Slot, T.rets[I], T.nrets == 1 ? (Value *)R : B.CreateExtractValue(R, I));
    resumed(B, Slot, Sp, Ret);
  }

  bool call(CallBase &CB, const std::vector<AllocaInst *> &Slot, const std::vector<uint32_t> &Conv,
            const std::vector<uint32_t> &Sys, const BiaraSig &S, std::string &Err) {
    IRBuilder<> B(&CB);
    Function *Callee = CB.getCalledFunction();
    auto Rec = Calls.find(&CB);
    const BiaraCall *C = Rec == Calls.end() ? nullptr : Rec->second;
    uint64_t Ret = C ? C->ret : 0;
    // The return address a call pushes is only read by the callee's
    // return, which ABI form replaces.
    if (Ret && Cv.pop > 0)
      for (Instruction *I = CB.getPrevNode(); I && !isa<CallBase>(I); I = I->getPrevNode())
        if (auto *St = dyn_cast<StoreInst>(I)) {
          auto *K = dyn_cast<ConstantInt>(St->getValueOperand());
          if (K && K->getBitWidth() == 64 && K->getZExtValue() == Ret) {
            St->eraseFromParent();
            break;
          }
        }
    Value *Sp = B.CreateLoad(regTy(Cv.sp), Slot[Cv.sp], "sp");
    if (Callee && Sigs.count(Callee) && (!C || C->kind == BIARA_CALL_DIRECT)) {
      invoke(B, *Sigs[Callee], Slot, Sp, Ret);
      CB.eraseFromParent();
      return true;
    }
    if (C && (C->kind == BIARA_CALL_IMPORT || C->kind == BIARA_CALL_INDIRECT)) {
      // Known guest targets are called through their exact native types;
      // only external addresses use the unresolved raw-register ABI.
      uint32_t Arity = C->arity == UINT32_MAX ? inferArity(CB, Slot, Conv, S) : C->arity;
      if (C->kind == BIARA_CALL_INDIRECT) {
        Value *Target = B.CreateZExtOrTrunc(
            B.CreateLoad(regTy(Cv.pc), Slot[Cv.pc], "target"), i64());
        for (uint32_t R : DispatchReads)
          writeCpu(B, R, B.CreateLoad(regTy(R), Slot[R]));
        Value *Known = B.CreateCall(Dispatch, {Target});
        BasicBlock *Before = CB.getParent();
        BasicBlock *Continue = Before->splitBasicBlock(CB.getIterator(), "indirect.resume");
        Before->getTerminator()->eraseFromParent();
        Function *Owner = Before->getParent();
        BasicBlock *Other = BasicBlock::Create(Cx, "indirect.external", Owner, Continue);
        IRBuilder<> Branch(Before);
        BasicBlock *Lifted = BasicBlock::Create(Cx, "indirect.lifted", Owner, Continue);
        Branch.CreateCondBr(Known, Lifted, Other);
        IRBuilder<> CallB(Lifted);
        for (uint32_t R : DispatchWrites)
          writeSlot(CallB, Slot, R, readCpu(CallB, R, regTy(R)));
        resumed(CallB, Slot, Sp, Ret);
        CallB.CreateBr(Continue);
        IRBuilder<> External(Other);
        std::vector<Type *> Params(std::min<size_t>(Arity, Conv.size()), i64());
        FunctionCallee Fn(FunctionType::get(i64(), Params, false),
                          External.CreateIntToPtr(Target, External.getPtrTy()));
        Value *Result = callUnknown(External, Fn, Slot, Conv, Arity);
        writeSlot(External, Slot, Cv.ret, Result);
        resumed(External, Slot, Sp, Ret);
        External.CreateBr(Continue);
        CB.eraseFromParent();
        return true;
      }
      FunctionCallee F = importDecl(C->import);
      Value *R = callUnknown(B, F, Slot, Conv, Arity);
      B.CreateStore(B.CreateZExtOrTrunc(R, regTy(Cv.ret)), Slot[Cv.ret]);
      resumed(B, Slot, Sp, Ret);
      CB.eraseFromParent();
      return true;
    }
    if (C && C->kind == BIARA_CALL_SYSCALL) {
      std::vector<Type *> Ps(Sys.size(), i64());
      FunctionCallee F = M.getOrInsertFunction("biara_syscall", FunctionType::get(i64(), Ps, false));
      Value *R = callUnknown(B, F, Slot, Sys, Sys.size());
      B.CreateStore(B.CreateZExtOrTrunc(R, regTy(Cv.sys_ret)), Slot[Cv.sys_ret]);
      CB.eraseFromParent();
      return true;
    }

    if (Callee && divOp(*Callee, CB, B, Slot, Err))
      return Err.empty();
    if (!Callee) {
      Err = "call through a pointer in lifted code";
      return false;
    }
    // A helper: registers travel through the CPU state, for helpers that
    // receive it.
    auto Mode = HelperMode.find(Callee->getName().str());
    if (Mode == HelperMode.end()) {
      Err = ("call to " + Callee->getName() + " without a role").str();
      return false;
    }
    bool SeesEnv = false;
    for (Value *A : CB.args()) {
      auto *G = dyn_cast<GetElementPtrInst>(A);
      SeesEnv |= A == EnvArg || (G && G->getPointerOperand() == EnvArg);
    }
    const BiaraHelper &H = *Mode->second;
    std::vector<uint32_t> All(Regs.size());
    for (size_t R = 0; R < Regs.size(); ++R)
      All[R] = R;
    std::vector<uint32_t> Reads = H.listed ? std::vector<uint32_t>(H.reads, H.reads + H.nreads) : All;
    std::vector<uint32_t> Writes =
        H.listed ? std::vector<uint32_t>(H.writes, H.writes + H.nwrites) : All;
    if (SeesEnv && (H.mode & BIARA_HELPER_READS))
      for (uint32_t R : Reads)
        if (!fp(R))
          B.CreateStore(B.CreateLoad(regTy(R), Slot[R]), cpuAt(B, Regs[R].home));
    if (SeesEnv && (H.mode & BIARA_HELPER_WRITES)) {
      IRBuilder<> A(CB.getNextNode());
      for (uint32_t R : Writes)
        if (!fp(R))
          A.CreateStore(A.CreateLoad(regTy(R), cpuAt(A, Regs[R].home)), Slot[R]);
    }
    return true;
  }
};
} // namespace

// Rewrite `M` into ABI form; the old functions in `Drop` (and the bodies of
// the rewritten ones) are deleted. Returns 0, or 1 with `*Err` set
// (malloc'ed).
extern "C" int biara_abi_form(LLVMModuleRef MRef, const BiaraConv *Cv, const BiaraReg *Regs,
                              size_t NRegs, const BiaraSig *Sigs, size_t NSigs,
                              const BiaraCall *Calls, size_t NCalls, const BiaraHelper *Helpers,
                              size_t NHelpers, const LLVMValueRef *Drop, size_t NDrop,
                              char **Err) {
  Module &M = *unwrap(MRef);
  Former F(M, *Cv);
  F.Regs.assign(Regs, Regs + NRegs);
  for (size_t R = 0; R < NRegs; ++R)
    if (!F.fp(R))
      F.RegAt[Regs[R].home] = R;
  for (size_t I = 0; I < NCalls; ++I)
    F.Calls[unwrap<Instruction>(Calls[I].inst)] = &Calls[I];
  for (size_t I = 0; I < NHelpers; ++I) {
    F.HelperMode[Helpers[I].symbol] = &Helpers[I];
    // Helpers without side effects go when their result is unused.
    if (Function *H = M.getFunction(Helpers[I].symbol); H && (Helpers[I].mode & BIARA_HELPER_PURE)) {
      H->setOnlyReadsMemory();
      H->setDoesNotThrow();
      H->setWillReturn();
    }
  }
  auto *CpuTy = ArrayType::get(Type::getInt8Ty(M.getContext()), Cv->margin + Cv->env_size);
  F.Cpu = new GlobalVariable(M, CpuTy, false, GlobalValue::ExternalLinkage, nullptr, "biara_cpu");
  F.Cpu->setAlignment(Align(16));
  F.Env = ConstantExpr::getGetElementPtr(
      Type::getInt8Ty(M.getContext()), F.Cpu,
      ConstantInt::get(Type::getInt64Ty(M.getContext()), Cv->margin));

  F.Dispatch = Function::Create(
      FunctionType::get(Type::getInt1Ty(M.getContext()),
                        {Type::getInt64Ty(M.getContext())}, false),
      GlobalValue::ExternalLinkage, "biara_call_at", M);
  F.Dispatch->getArg(0)->setName("addr");
  // Kept a plain switch on the address (no range tricks) for the C.
  F.Dispatch->addFnAttr(Attribute::OptimizeNone);
  F.Dispatch->addFnAttr(Attribute::NoInline);
  for (size_t I = 0; I < NSigs; ++I)
    F.declare(Sigs[I]);
  F.dispatcher(Sigs, NSigs);
  std::string E;
  for (size_t I = 0; I < NSigs; ++I)
    if (!F.form(Sigs[I], E)) {
      *Err = strdup((unwrap<Function>(Sigs[I].fn)->getName() + ": " + E).str().c_str());
      return 1;
    }
  for (size_t I = 0; I < NDrop; ++I) {
    Function *D = unwrap<Function>(Drop[I]);
    D->deleteBody();
  }
  for (size_t I = 0; I < NSigs; ++I) {
    Function *Old = unwrap<Function>(Sigs[I].fn);
    Old->replaceAllUsesWith(PoisonValue::get(Old->getType()));
    Old->eraseFromParent();
  }
  for (size_t I = 0; I < NDrop; ++I) {
    Function *D = unwrap<Function>(Drop[I]);
    D->replaceAllUsesWith(PoisonValue::get(D->getType()));
    D->eraseFromParent();
  }
  return 0;
}

// Turn `inttoptr (ptrtoint %frame + C)` into `getelementptr i8, %frame, C`
// for the frame allocas of every function, so that SROA sees the slots.
// Returns the number of rewrites.
extern "C" size_t biara_fold_frames(LLVMModuleRef MRef) {
  Module &M = *unwrap(MRef);
  size_t N = 0;
  for (Function &F : M) {
    std::vector<IntToPtrInst *> Casts;
    for (Instruction &I : instructions(F))
      if (auto *C = dyn_cast<IntToPtrInst>(&I))
        Casts.push_back(C);
    for (IntToPtrInst *C : Casts) {
      int64_t Off = 0;
      Value *V = C->getOperand(0);
      for (unsigned Depth = 0; Depth < 16; ++Depth) {
        auto *Bin = dyn_cast<BinaryOperator>(V);
        ConstantInt *K = Bin ? dyn_cast<ConstantInt>(Bin->getOperand(1)) : nullptr;
        if (!K)
          break;
        if (Bin->getOpcode() == Instruction::Add)
          Off += K->getSExtValue();
        else if (Bin->getOpcode() == Instruction::Sub)
          Off -= K->getSExtValue();
        else
          break;
        V = Bin->getOperand(0);
      }
      auto *P = dyn_cast<PtrToIntInst>(V);
      if (!P || !isa<AllocaInst>(P->getPointerOperand()))
        continue;
      IRBuilder<> B(C);
      Value *G = B.CreateConstGEP1_64(B.getInt8Ty(), P->getPointerOperand(), Off);
      C->replaceAllUsesWith(G);
      C->eraseFromParent();
      ++N;
    }
  }
  return N;
}

// Duplicate a return-only block into its predecessors that end in an
// unconditional branch to it (`v = ...; goto ret; return v;` becomes
// `return ...` in place), so the C prints one return per arm instead of a
// join with a `common_ret_op` phi. Only predecessors with no other
// successor are rewritten; the join dies when nothing reaches it.
// Returns the number of edges rewritten.
extern "C" size_t biara_dup_returns(LLVMModuleRef MRef) {
  Module &M = *unwrap(MRef);
  size_t N = 0;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::vector<ReturnInst *> Rets;
    for (BasicBlock &B : F)
      if (auto *R = dyn_cast<ReturnInst>(B.getTerminator()))
        Rets.push_back(R);
    for (ReturnInst *R : Rets) {
      BasicBlock *J = R->getParent();
      if (&*J->getFirstNonPHIOrDbg() != R)
        continue;
      // The returned value is a constant or this block's own phi.
      Value *V = R->getReturnValue();
      PHINode *Phi = nullptr;
      if (V && !isa<Constant>(V)) {
        Phi = dyn_cast<PHINode>(V);
        if (!Phi || Phi->getParent() != J)
          continue;
      }
      std::vector<BasicBlock *> Preds;
      for (BasicBlock *P : predecessors(J)) {
        if (P == J)
          continue;
        auto *B = dyn_cast<UncondBrInst>(P->getTerminator());
        if (!B || B->getSuccessor(0) != J)
          continue;
        Preds.push_back(P);
      }
      std::vector<Value *> Ins;
      for (BasicBlock *P : Preds)
        Ins.push_back(Phi ? Phi->getIncomingValueForBlock(P) : V);
      for (size_t K = 0; K < Preds.size(); ++K) {
        BasicBlock *P = Preds[K];
        Instruction *Old = P->getTerminator();
        J->removePredecessor(P);
        IRBuilder<> B(Old);
        B.CreateRet(Ins[K]);
        Old->eraseFromParent();
        ++N;
      }
    }
  }
  return N;
}

// A division prelude call `biara_sdiv64(lo, hi, d)` whose high half only
// extends the low (the compiler's plain N-bit division: `ashr lo, N - 1`,
// `sext lo`, or zero) back into `sdiv`/`srem` (or `udiv`/`urem`), so the C
// prints `a / b` rather than a helper call and a tuple. QEMU's raise on a
// zero divisor or an overflowing quotient is the caller's guard (and, on the
// host, the trapping division itself).
// Returns the number of calls rewritten.
extern "C" size_t biara_div_sugar(LLVMModuleRef MRef) {
  Module &M = *unwrap(MRef);
  size_t N = 0;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::vector<CallInst *> Calls;
    for (Instruction &I : instructions(F))
      if (auto *C = dyn_cast<CallInst>(&I))
        Calls.push_back(C);
    for (CallInst *C : Calls) {
      Function *CF = C->getCalledFunction();
      if (!CF || C->arg_size() != 3)
        continue;
      StringRef Nn = CF->getName();
      unsigned W = 0;
      bool Sg = false;
      if (Nn.consume_front("biara_")) {
        Sg = Nn.consume_front("sdiv");
        if (!Sg && !Nn.consume_front("div"))
          continue;
        if (Nn == "8")
          W = 8;
        else if (Nn == "16")
          W = 16;
        else if (Nn == "32")
          W = 32;
        else if (Nn == "64")
          W = 64;
        else
          continue;
      } else
        continue;
      Value *Lo = C->getArgOperand(0), *Hi = C->getArgOperand(1), *D = C->getArgOperand(2);
      bool Ext = false;
      if (Sg) {
        if (auto *A = dyn_cast<BinaryOperator>(Hi))
          Ext = A->getOpcode() == Instruction::AShr && A->getOperand(0) == Lo &&
                isa<ConstantInt>(A->getOperand(1)) &&
                cast<ConstantInt>(A->getOperand(1))->getZExtValue() == W - 1;
        if (!Ext)
          if (auto *S = dyn_cast<SExtInst>(Hi))
            Ext = S->getOperand(0) == Lo;
      } else
        Ext = isa<ConstantInt>(Hi) && cast<ConstantInt>(Hi)->isZero();
      if (!Ext)
        continue;
      // Only whole-struct extracts; anything else keeps the helper.
      for (User *U : C->users())
        if (!isa<ExtractValueInst>(U))
          Ext = false;
      if (!Ext || C->users().empty())
        continue;
      LLVMContext &Cx = M.getContext();
      Type *T = W == 64 ? Type::getInt64Ty(Cx) : Type::getIntNTy(Cx, W);
      IRBuilder<> B(C);
      auto narrow = [&](Value *V) -> Value * {
        return W == 64 ? V : B.CreateTrunc(V, T);
      };
      auto widen = [&](Value *V) -> Value * {
        return B.CreateZExt(V, B.getInt64Ty());
      };
      Value *Ln = narrow(Lo), *Dn = narrow(D);
      Value *Q = Sg ? B.CreateSDiv(Ln, Dn) : B.CreateUDiv(Ln, Dn);
      Value *Rr = Sg ? B.CreateSRem(Ln, Dn) : B.CreateURem(Ln, Dn);
      std::vector<ExtractValueInst *> Ex;
      for (User *U : C->users())
        Ex.push_back(cast<ExtractValueInst>(U));
      for (ExtractValueInst *E : Ex) {
        Value *V = *E->idx_begin() == 0 ? Q : Rr;
        E->replaceAllUsesWith(widen(V));
        E->eraseFromParent();
      }
      C->eraseFromParent();
      ++N;
    }
  }
  return N;
}
