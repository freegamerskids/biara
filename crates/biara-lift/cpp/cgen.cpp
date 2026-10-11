// C from a module in ABI form (src/decompile.rs, cpp/abi_form.cpp).
//
// Mode 0 (executable C): whole-module source streamed in bounded chunks,
// dependencies before first use. Compilable by construction: casts, wrapping
// (`wrap`), and side effects are preserved; only names/folding/structure are
// simplified, never semantics.
//
// Mode 1 (function packages): one complete UTF-8 JSON object per guest
// function carrying `!biara.entry !{i64 entry}`, emitted with a single
// `write` call per object. Dispatcher/runtime helpers (`biara.run`,
// `biara.dispatch`, `biara.syscall`, `biara_function_at`, `biara_div*`,
// `biara_sdiv*`, declarations without `!biara.entry`, intrinsics) are
// excluded. When any function carries `!biara.present !{i64 ordinal}`, only
// those are emitted in ordinal order; otherwise every `!biara.entry` carrier
// in module order. Each package is self-contained: `body` is the full
// definition from the same renderer as Mode 0, `dependencies` holds only what
// the function uses (types recursively, strings, globals, imports, helpers),
// captured independently per function (no cross-function dedup).
//
// Provenance: `statements[].addresses` are surviving `!biara.pc` contributors
// captured BEFORE folding/inlining (including inline expressions, edge phi
// copies, and return-merge RHS), unioned on merges. They are NOT exhaustive
// original coverage: LLVM may erase metadata, and structural lines
// (braces/labels/gotos/breaks) never guess a PC. `provenance` is `exact`
// only when every contributor had surviving metadata, `inferred` on partial
// loss, `unknown` when none survives. Lost metadata is reported, never
// fabricated.
//
// Names: arguments default to neutral `arg0...` (original architectural name
// kept in `names[].original`), values to neutral `vN` except justified
// producer names (`<callee>_result`, evidence `inferred`). `!biara.debug_name`
// entries `"<original>=<name>"` (or two-string tuples) rename only proven
// unique argument bindings (evidence `debug`); everything else is `unknown`
// (or `symbol` when the final name preserves a non-architectural symbol).
// Frame fields renamed from `!biara.debug_objects` only on whole-object
// exact offset/size match with full PC coverage (half-open `[start,end)`,
// identical repeats union, conflicts/missing decline); scalar C types never
// change on DWARF signedness conflict.
//
// Types: every address is reduced to a root plus a constant offset (through
// getelementptr, inttoptr/ptrtoint and constant adds). Roots are function
// parameters, loaded values, call results, phis and selects (pointer
// variables), the stack frame allocas, the CPU state global, or nothing (an
// absolute address). Pointer variables are unified through phis, selects,
// call arguments and returns, and the fields they are loaded from or stored
// to; each class with accesses becomes a struct (fields at the offsets
// accessed, widest access wins, overlaps are left to casts) or a pointer to
// a scalar. Constant strided offsets into a scalar layout read as indexed
// `p[i]` (same bytes, readable form only). Frames become one struct per
// function, the CPU state a struct with the registers' names.
//
// Code: one C statement per instruction that is not folded into its single
// user (folding bounded by a size budget so output stays readable),
// gotos between basic blocks, phis as assignments on the edges. Natural
// loops with a proven pure-header single-exit condition read as `while`;
// a unique constant-step induction phi permits `for`. A unique conditional
// latch without loop/exit phi copies permits `do/while`, preserving effects
// before the test. Other loops retain `for (;;)` and explicit transfers.

#include "llvm-c/Types.h"
#include "layouts.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Constants.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace llvm;

// JSON string escaping for package output (exact C text, UTF-8 passthrough).
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
// compact summaries. Only carriers are packaged in Mode 1.
std::optional<uint64_t> entryOf(const Function &Fn, LLVMContext &Cx) {
  MDNode *N = Fn.getMetadata(Cx.getMDKindID("biara.entry"));
  if (!N || !N->getNumOperands())
    return std::nullopt;
  if (auto *C = mdconst::dyn_extract<ConstantInt>(N->getOperand(0)))
    return C->getZExtValue();
  return std::nullopt;
}

// Selection ordinal: `!biara.present !{i64 ordinal}`. When any function in the
// module carries it, Mode 1 emits only carriers in ordinal order.
std::optional<int64_t> presentOf(const Function &Fn, LLVMContext &Cx) {
  MDNode *N = Fn.getMetadata(Cx.getMDKindID("biara.present"));
  if (!N || !N->getNumOperands())
    return std::nullopt;
  if (auto *C = mdconst::dyn_extract<ConstantInt>(N->getOperand(0)))
    return C->getSExtValue();
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

extern "C" {
// `BiaraWrite` and `BiaraCField` come from cpp/layouts.h (shared analysis
// header); the renderer consumes the cached analysis, not a second one.
// Copied data (`R_*_COPY`): address and size in the image, host-linked name.
struct BiaraData {
  uint64_t addr;
  uint64_t size;
  const char *name;
};
// A guest string literal at a call argument: address and C-escaped text.
struct BiaraStr {
  uint64_t addr;
  const char *text;
};
// A called import's declaration: parameter count, which take strings,
// and whether calls vary in count (then `, ...`).
struct BiaraProto {
  const char *name;
  uint32_t nargs;
  uint64_t strmask;
  uint32_t ellipsis;
};
}

namespace {

// Append-only, bounded output with newline normalization across every section
// and function boundary. A failed sink stops both writing and code generation.
class COutput {
  BiaraWrite Write;
  void *Ctx;
  char Buffer[65536];
  size_t Used = 0;
  unsigned Newlines = 0;
  int Error = 0;

  bool flush() {
    if (Used && !Error) {
      Error = Write(Ctx, Buffer, Used);
      Used = 0;
    }
    return Error == 0;
  }

  bool append(StringRef Text) {
    while (!Text.empty()) {
      size_t N = std::min(Text.size(), sizeof(Buffer) - Used);
      memcpy(Buffer + Used, Text.data(), N);
      Used += N;
      Text = Text.drop_front(N);
      if (Used == sizeof(Buffer) && !flush())
        return false;
    }
    return true;
  }

  bool newlines() {
    unsigned N = Newlines;
    Newlines = 0;
    return append(StringRef("\n\n", N));
  }

public:
  COutput(BiaraWrite Write, void *Ctx) : Write(Write), Ctx(Ctx) {}

  bool write(StringRef Text) {
    if (Error)
      return false;
    while (!Text.empty()) {
      if (Text.front() == '\n') {
        Newlines = std::min(Newlines + 1, 2u);
        Text = Text.drop_front();
        continue;
      }
      if (!newlines())
        return false;
      StringRef Line = Text.take_front(Text.find('\n'));
      if (!append(Line))
        return false;
      Text = Text.drop_front(Line.size());
    }
    return true;
  }

  int status() const { return Error; }

  int finish() {
    if (!Error && newlines())
      flush();
    return Error;
  }
};

// A byte offset: decimal while small, hex beyond.
std::string num(int64_t V) {
  if (V < 0)
    return "-" + num(-V);
  char B[32];
  snprintf(B, sizeof B, V < 10 ? "%lld" : "0x%llx", (long long)V);
  return B;
}

std::string hex(uint64_t V) {
  char B[32];
  snprintf(B, sizeof B, "0x%llx", (unsigned long long)V);
  return B;
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

std::string intTy(unsigned Bits) {
  switch (container(Bits)) {
  case 8:
    return "int8_t";
  case 16:
    return "int16_t";
  case 32:
    return "int32_t";
  case 64:
    return "int64_t";
  case 128:
    return "biara_i128";
  }
  return "";
}

bool standard(unsigned Bits) { return container(Bits) == Bits; }

// Layout analysis lives in cpp/layouts.h (extracted `Types`); the renderer
// consumes the cached analysis and establishes no second convention.
using biara_layouts::Base;
using biara_layouts::Field;
using biara_layouts::Layout;
using biara_layouts::base;

// One C statement and the values it reads. `Pcs` are surviving `!biara.pc`
// contributors captured BEFORE folding/inlining into this statement:
// `Direct` from instructions emitted here, `Folded` from values folded into
// it (inline expressions, edge phi inputs, return-merge RHS). `LostFold`
// marks a folded value with no surviving PC (partial metadata loss).
// Provenance is exact only when every contributor survived, unknown when none
// did; structural lines (labels/braces/gotos) carry none and never guess.
struct Stmt {
  std::string Text;
  Instruction *Def = nullptr; // a pure assignment to this value
  Instruction *Assigns = nullptr; // the variable it writes, if any
  std::string Rhs; // for a pure `v = RHS`, the RHS (mergeable into `return RHS`)
  bool Staged = false; // writes `<phi>_next`
  std::vector<Instruction *> Refs;
  unsigned Depth = 0;
  BasicBlock *Label = nullptr; // a label statement for this block
  std::set<uint64_t> Pcs; // surviving contributors (direct + folded, unioned)
  bool LostFold = false; // a folded contributor had no surviving PC
  bool Structural = false; // braces/labels/jumps: addresses always empty
};

Stmt plain(std::string Text) {
  Stmt S;
  S.Text = std::move(Text);
  return S;
}

class Emitter {
  Module &M;
  const DataLayout &DL;
  biara_layouts::Types &T;
  const unsigned PcKind;
  std::map<std::string, bool> Helpers; // helper name -> already emitted
  std::map<std::string, std::string> SupportDefs;
  std::map<StructType *, std::string> Aggregates;
  std::map<const Value *, std::string> CallbackTypes;
  std::map<std::string, std::vector<std::string>, std::less<>> CallbackArguments;
  std::string Prelude; // newly discovered aggregate/helper definitions
  std::set<std::string> GlobalNames;
  size_t &Unsupported;
  std::vector<std::string> ConvArgs; // the convention's argument registers
  uint64_t Margin;                   // offset of env in `biara_cpu`
  std::vector<BiaraData> Data;       // copied data, by image address
  std::map<std::string, bool> DataUsed; // copied data name -> declared
  std::map<uint64_t, bool> StrsUsed; // guest string address -> declared
  bool AtolUsed = false, AtolDeclared = false;
  std::map<uint64_t, std::string> Strings; // guest string literals, by address
  std::map<uint64_t, unsigned> StringUses; // module references, saturated at two
  std::map<uint64_t, std::string> Syms;    // function names, by entry address
  bool Posix = false;
  std::map<std::string, BiaraProto> Protos; // typed import declarations, by name

  // Per function.
  Function *F = nullptr;
  std::map<const Value *, std::string> Names;
  std::map<const Value *, std::string> Originals; // architectural/register hint kept
  std::set<std::string> Taken;
  // Reservations only grow within a function: collision suffixes never
  // become available again, so don't rescan them for every call result.
  std::map<std::string, unsigned> NextSuffix;
  std::set<Instruction *> Inline;
  std::vector<Instruction *> *Refs = nullptr;
  std::set<uint64_t> *PcsOut = nullptr; // surviving PCs of the current Stmt
  bool *LostOut = nullptr; // folded contributor without surviving PC
  std::map<BasicBlock *, unsigned> Order;
  std::set<BasicBlock *> Targeted;
  std::map<const Value *, std::string> NameEvidence;
  std::string StatementJson;
  uint64_t StatementCount = 0, MappedCount = 0, MaxDepth = 0, TempCount = 0;
  bool Packaging = false;

public:
  Emitter(Module &M, biara_layouts::Types &T, size_t &Unsupported, std::vector<std::string> ConvArgs,
          uint64_t Margin, std::vector<BiaraData> Data, std::vector<BiaraStr> Strings,
          std::vector<BiaraProto> Protos, std::vector<BiaraStr> Syms)
      : M(M), DL(M.getDataLayout()), T(T), PcKind(M.getContext().getMDKindID("biara.pc")),
        Unsupported(Unsupported),
        ConvArgs(std::move(ConvArgs)), Margin(Margin), Data(std::move(Data)) {
    for (const BiaraStr &S : Strings)
      this->Strings[S.addr] = S.text;
    for (const BiaraProto &P : Protos)
      this->Protos[P.name] = P;
    for (const BiaraStr &S : Syms)
      this->Syms[S.addr] = S.text;
    for (StringRef Name : {"uint8_t","uint16_t","uint32_t","uint64_t","int8_t","int16_t",
                          "int32_t","int64_t","uintptr_t","biara_u128","biara_i128"})
      GlobalNames.insert(Name.str());
    for (Function &Fn : M)
      if (auto *Node = Fn.getMetadata("biara.os"); Node && Node->getNumOperands())
        if (auto *OS = mdconst::dyn_extract<ConstantInt>(Node->getOperand(0))) {
          Posix = OS->getZExtValue() == 1 || OS->getZExtValue() == 2;
          break;
        }
    inferCallbacks();
    if (!this->Strings.empty()) {
      for (Function &Fn : M)
        for (Instruction &I : instructions(Fn))
          for (Value *Operand : I.operands())
            if (auto *C = dyn_cast<Constant>(Operand))
              countStringUses(C, true);
      for (GlobalVariable &G : M.globals())
        if (G.hasInitializer())
          countStringUses(G.getInitializer(), false);
    }
  }

  void countStringUses(Constant *C, bool Direct) {
    if (auto *I = dyn_cast<ConstantInt>(C)) {
      if (I->getBitWidth() <= 64 && Strings.count(I->getZExtValue())) {
        unsigned &Uses = StringUses[I->getZExtValue()];
        Uses = Direct ? std::min(2u, Uses + 1) : 2;
      }
      return;
    }
    // A nested constant or initializer exposes the address, not merely its
    // text. Keep its named storage; globals are visited separately above.
    if (isa<GlobalValue>(C)) return;
    for (Value *Operand : C->operands())
      if (auto *Child = dyn_cast<Constant>(Operand))
        countStringUses(Child, false);
  }

  std::string aggregate(StructType *S) {
    auto It = Aggregates.find(S);
    if (It != Aggregates.end())
      return It->second;
    std::string Name = "struct biara_tuple" + std::to_string(Aggregates.size() + 1);
    std::string Def = Name + " {";
    for (unsigned I = 0; I < S->getNumElements(); ++I)
      Def += " " + cty(S->getElementType(I)) + " f" + std::to_string(I) + ";";
    Def += " };\n";
    Prelude += Def;
    SupportDefs[Name.substr(7)] = Def;
    return Aggregates[S] = Name;
  }

  void inferCallbacks() {
    struct Shape { std::string Signature; bool Conflict; CallBase *Call; };
    std::map<const Value *, Shape> Shapes;
    for (Function &Fn : M) {
      if (Fn.isDeclaration()) continue;
      for (Instruction &I : instructions(Fn)) {
        auto *CB=dyn_cast<CallBase>(&I);
        if (!CB || CB->getCalledFunction()) continue;
        std::string Sig=cty(CB->getType()) + " (*)(";
        for (unsigned K=0;K<CB->arg_size();++K)
          Sig += (K ? ", " : "") + ctyOf(CB->getArgOperand(K));
        if (!CB->arg_size()) Sig += "void";
        Sig += ")";
        auto bind = [&](Value *V) {
          auto [It,New]=Shapes.try_emplace(V,Shape{Sig,false,CB});
          if (!New && It->second.Signature!=Sig) It->second.Conflict=true;
        };
        Value *Called=CB->getCalledOperand();
        bind(Called);
        if (auto *Lookup=dyn_cast<CallBase>(Called))
          if (auto *Target=Lookup->getCalledFunction(); Target && Target->getName()=="biara_function_at" && Lookup->arg_size()==1) {
            Base B=base(Lookup->getArgOperand(0),DL);
            if (B.Root && !B.Off) bind(B.Root);
          }
      }
    }
    std::map<std::string,std::pair<std::string,CallBase *>> Aliases;
    for (auto &[V,S] : Shapes)
      if (!S.Conflict) Aliases.try_emplace(S.Signature,"",S.Call);
    unsigned N=0;
    for (auto &[Sig,Alias] : Aliases) {
      auto &Name=Alias.first;
      Name="biara_callback_" + std::to_string(N++) + "_t";
      auto &Args=CallbackArguments[Name];
      Args.reserve(Alias.second->arg_size());
      for (Value *Arg : Alias.second->args()) Args.push_back(ctyOf(Arg));
      std::string Def=Sig;
      Def.insert(Def.find("(*)")+2,Name);
      Def="/* inferred from agreeing call uses; targets may remain open */\ntypedef " + Def + ";\n";
      GlobalNames.insert(Name);
      SupportDefs[Name]=Def;
      Prelude+=Def;
    }
    for (auto &[V,S] : Shapes)
      if (!S.Conflict) CallbackTypes[V]=Aliases.at(S.Signature).first;
  }

  struct ImportPrototype {
    const char *Name, *Result;
    std::array<const char *, 4> Args;
    unsigned Count;
    bool Variadic = false, PosixOnly = false;
  };
  const ImportPrototype *prototype(const Function *Fn) {
    if (!Fn || !Fn->isDeclaration()) return nullptr;
    static const ImportPrototype Known[] = {
      {"malloc","uint8_t *",{"uint64_t"},1},
      {"calloc","uint8_t *",{"uint64_t","uint64_t"},2},
      {"realloc","uint8_t *",{"uint8_t *","uint64_t"},2},
      {"aligned_alloc","uint8_t *",{"uint64_t","uint64_t"},2},
      {"free","void",{"uint8_t *"},1},
      {"memcpy","uint8_t *",{"uint8_t *","const uint8_t *","uint64_t"},3},
      {"memmove","uint8_t *",{"uint8_t *","const uint8_t *","uint64_t"},3},
      {"memset","uint8_t *",{"uint8_t *","int32_t","uint64_t"},3},
      {"strlen","uint64_t",{"const char *"},1},
      {"strcmp","int32_t",{"const char *","const char *"},2},
      {"strncmp","int32_t",{"const char *","const char *","uint64_t"},3},
      {"puts","int32_t",{"const char *"},1},
      {"putchar","int32_t",{"int32_t"},1},
      {"putc","int32_t",{"int32_t","uint8_t *"},2},
      {"printf","int32_t",{"const char *"},1,true},
      {"fprintf","int32_t",{"uint8_t *","const char *"},2,true},
      {"snprintf","int32_t",{"char *","uint64_t","const char *"},3,true},
      {"read","int64_t",{"int32_t","uint8_t *","uint64_t"},3,false,true},
      {"write","int64_t",{"int32_t","const uint8_t *","uint64_t"},3,false,true},
      {"atol","int64_t",{"const char *"},1,false,true},
      {"strtol","int64_t",{"const char *","char **","int32_t"},3,false,true},
      {"strtoll","int64_t",{"const char *","char **","int32_t"},3,false,true},
      {"__isoc23_strtol","int64_t",{"const char *","char **","int32_t"},3,false,true},
      {"__isoc23_strtoll","int64_t",{"const char *","char **","int32_t"},3,false,true},
    };
    for (const auto &P : Known)
      if (Fn->getName() == P.Name && (!P.PosixOnly || Posix)) return &P;
    return nullptr;
  }

  std::string importResult(Function &Fn, const ImportPrototype &P) {
    if (StringRef(P.Result) == "void" && !Fn.getReturnType()->isVoidTy())
      return cty(Fn.getReturnType());
    if (StringRef(P.Result) == "int32_t" && Fn.getReturnType()->isIntegerTy(64)) {
      // Narrow only when every live consumer truncates the result.
      // Otherwise retain the ABI-width result: its upper bits are unknown.
      for (const User *U : Fn.users()) {
        auto *CB = dyn_cast<CallBase>(U);
        if (!CB || CB->getCalledFunction()!=&Fn) return cty(Fn.getReturnType());
        for (const User *Use : CB->users()) {
          auto *Trunc=dyn_cast<TruncInst>(Use);
          if (!Trunc || Trunc->getDestTy()->getIntegerBitWidth()>32)
            return cty(Fn.getReturnType());
        }
      }
    }
    return P.Result;
  }

  std::string callType(CallBase &CB) {
    if (auto *Fn=CB.getCalledFunction())
      if (auto *P=prototype(Fn)) {
        auto Ret=importResult(*Fn,*P);
        return Ret=="int32_t" ? "uint32_t" : Ret;
      }
    return cty(CB.getType());
  }

  std::string cty(Type *Ty) {
    if (Ty->isVoidTy())
      return "void";
    if (Ty->isIntegerTy())
      return uintTy(Ty->getIntegerBitWidth());
    if (Ty->isPointerTy())
      return "uint8_t *";
    if (auto *S = dyn_cast<StructType>(Ty))
      return aggregate(S);
    if (Ty->isDoubleTy())
      return "double";
    if (Ty->isFloatTy())
      return "float";
    // Preserve LLVM's lane representation, including integer vector views
    // introduced when optimization extracts words from an FP/vector slot.
    if (auto *V = dyn_cast<FixedVectorType>(Ty)) {
      Type *Element = V->getElementType();
      unsigned Bits = Element->isIntegerTy() ? Element->getIntegerBitWidth()
                      : Element->isFloatTy() ? 32 : Element->isDoubleTy() ? 64 : 0;
      unsigned Bytes = Bits * V->getNumElements() / 8;
      if ((Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64) &&
          Bytes && Bytes <= 16 && (Bytes & (Bytes - 1)) == 0) {
        std::string Name = "biara_v" + std::to_string(V->getNumElements()) +
                          (Element->isFloatTy() ? "f" : Element->isDoubleTy() ? "d"
                           : "u" + std::to_string(Bits));
        if (!SupportDefs.count(Name)) {
          std::string Def = "typedef " + cty(Element) + " " + Name +
                            " __attribute__((vector_size(" + std::to_string(Bytes) + ")));\n";
          SupportDefs[Name] = Def;
          Prelude += Def;
        }
        return Name;
      }
    }
    ++Unsupported;
    return "uint64_t /* unsupported type */";
  }

  // C type of a value: pointer variables are typed by their class.
  std::string ctyOf(Value *V) {
    if (auto It=CallbackTypes.find(V); It!=CallbackTypes.end()) return It->second;
    if (V->getType()->isIntegerTy(64) || V->getType()->isPointerTy()) {
      int C = T.classOf(V);
      if (C >= 0 && T.Layouts.count(C) && (isa<Argument>(V) || isa<LoadInst>(V) ||
                                          isa<CallBase>(V) || isa<PHINode>(V) ||
                                          isa<SelectInst>(V)))
        return T.ptrTy(C);
    }
    return cty(V->getType());
  }

  static bool isPtrTy(const std::string &S) {
    return (!S.empty() && S.back()=='*') || StringRef(S).starts_with("biara_callback_");
  }

  // `E` (of C type `From`) as C type `To`.
  static std::string conv(const std::string &E, const std::string &From, const std::string &To) {
    if (From == To)
      return E;
    // A pointer to `uint64_t` is one cast; narrower integers go through
    // `uintptr_t` (a truncating pointer cast may warn).
    if (isPtrTy(From) && !isPtrTy(To) && To == "uint64_t")
      return "(" + To + ")" + E;
    if (isPtrTy(From) && !isPtrTy(To))
      return "(" + To + ")(uintptr_t)" + E;
    // Same-size integers convert to pointers directly (`(uint8_t *)x`, where
    // `x` is 64 bits, not `(uint8_t *)(uintptr_t)x`).
    if (!isPtrTy(From) && isPtrTy(To) && From == "uint64_t")
      return "(" + To + ")" + E;
    if (!isPtrTy(From) && isPtrTy(To))
      return "(" + To + ")(uintptr_t)" + E;
    return "(" + To + ")" + E;
  }

  std::string lit(const APInt &V) {
    unsigned Bits = V.getBitWidth();
    if (Bits == 1)
      return V.isOne() ? "true" : "false";
    if (Bits > 64) {
      APInt Hi = V.lshr(64).trunc(64), Lo = V.trunc(64);
      return "(((biara_u128)" + hex(Hi.getZExtValue()) + "ull << 64) | " + hex(Lo.getZExtValue()) +
             "ull)";
    }
    uint64_t X = V.getZExtValue();
    if (V.isAllOnes())
      return std::string("-1") + (container(Bits) == 64 ? "ull" : "u");
    std::string S = X <= 1000 ? std::to_string(X) : hex(X);
    return S + (container(Bits) == 64 ? "ull" : "u");
  }

  // `lit`, but for a signed C type (`2`, not `2u`; `-1ll`, not `-1ull`).
  std::string slit(const APInt &V) {
    unsigned Bits = V.getBitWidth();
    if (Bits > 64)
      return lit(V);
    if (V.isAllOnes())
      return std::string("-1") + (container(Bits) == 64 ? "ll" : "");
    int64_t X = V.getSExtValue();
    std::string S = X < 0 ? std::to_string(X)
                    : (uint64_t)X <= 1000 ? std::to_string(X)
                                       : hex((uint64_t)X);
    return S + (container(Bits) == 64 ? "ll" : "");
  }

  std::string name(const Value *V) { return Names.at(V); }

  void declareName(const Value *V, StringRef Hint) {
    std::string Base = Hint.empty() ? "value" : ident(Hint);
    std::string N = Base;
    if (Taken.count(N) || GlobalNames.count(N)) {
      auto [It, New] = NextSuffix.try_emplace(Base, 1);
      do {
        N = Base + "_" + std::to_string(It->second++);
      } while (Taken.count(N) || GlobalNames.count(N));
    }
    Taken.insert(N);
    Names[V] = N;
    Originals[V] = V->getName().str();
    NameEvidence[V] = "unknown";
  }

  void argumentNames(Function &Fn) {
    auto Debug = debugNamesOf(Fn, M.getContext());
    for (Argument &A : Fn.args()) {
      auto It = Debug.find(A.getName().str());
      declareName(&A, It == Debug.end() ? "arg" + std::to_string(A.getArgNo()) : It->second);
      if (It != Debug.end())
        NameEvidence[&A] = "debug";
    }
  }

  void capturePC(const Value *V) {
    if (!Packaging || !PcsOut)
      return;
    auto *I = dyn_cast<Instruction>(V);
    if (!I)
      return;
    bool Mapped = false;
    if (MDNode *N = I->getMetadata(PcKind))
      for (const MDOperand &Op : N->operands())
        if (auto *C = mdconst::dyn_extract<ConstantInt>(Op)) {
          PcsOut->insert(C->getZExtValue());
          Mapped = true;
        }
    if (!Mapped)
      *LostOut = true;
  }

  void beginStmt(Stmt &S, const Instruction *Source = nullptr) {
    Refs = &S.Refs;
    PcsOut = &S.Pcs;
    LostOut = &S.LostFold;
    if (Source)
      capturePC(Source);
  }
  void endStmt() { Refs = nullptr; PcsOut = nullptr; LostOut = nullptr; }

  // Cap pure expression expansion. A statement with multiple uses, memory
  // effects, or more than sixteen pure nodes remains named.
  bool smallExpression(Value *V, unsigned &Budget) {
    auto *I = dyn_cast<Instruction>(V);
    if (!I || !pure(*I) || !I->hasOneUse())
      return true;
    if (!Budget--)
      return false;
    for (Value *Op : I->operands())
      if (!smallExpression(Op, Budget))
        return false;
    return true;
  }

  // Address `Off` bytes into frame/CPU root `R`, as a pointer.
  std::string frameAddr(Value *R, int64_t Off) {
    std::string Var = isa<AllocaInst>(R) ? name(R) : "biara_cpu";
    if (!isa<AllocaInst>(R) && Off == (int64_t)Margin)
      return "BIARA_ENV";
    if (auto It = T.Frames.find(R); It != T.Frames.end())
      if (const Field *Fd = It->second.startsAt(Off))
        return "(uint8_t *)&" + Var + "." + Fd->Name;
    if (Off == 0)
      return "(uint8_t *)&" + Var;
    return "((uint8_t *)&" + Var + " + " + num(Off) + ")";
  }

  bool isFrameRoot(Value *R) {
    return R && (isa<AllocaInst>(R) || (isa<GlobalVariable>(R) && R->getName() == "biara_cpu"));
  }

  // Copied data holding `Off` (whole access inside one symbol), if any.
  const BiaraData *dataAt(uint64_t Off, unsigned Bytes) {
    if (Bytes == 0)
      return nullptr;
    for (const BiaraData &D : Data)
      if (D.addr <= Off && Off - D.addr + Bytes <= D.size && D.size != 0)
        return &D;
    return nullptr;
  }

  // The lvalue for data `Name` at `Delta` bytes in: a bare symbol for a whole
  // pointer-sized symbol (its address holds the pointer), bytes otherwise.
  // Marks it used for the `extern` declarations.
  std::pair<std::string, std::string> deref(const std::string &Name, uint64_t Delta,
                                            const BiaraData &D, unsigned Bytes, const std::string &Raw) {
    DataUsed.try_emplace(Name, false);
    std::string Sym = ident(Name);
    if (Delta == 0 && Bytes == 8 && D.size == 8)
      return {Sym, "uint8_t *"};
    std::string P = "((uint8_t *)&" + Sym;
    P += Delta ? " + " + hex(Delta) + ")" : ")";
    return {"*(" + Raw + " *)" + P, Raw};
  }

  // The lvalue `Ty` at address `Ptr`, and its C type.
  std::pair<std::string, std::string> resolve(Value *Ptr, Type *Ty) {
    Base B = base(Ptr, DL);
    unsigned Bytes = DL.getTypeStoreSize(Ty);
    std::string Raw = cty(Ty);
    auto off = [](int64_t O) {
      return O == 0 ? std::string() : O < 0 ? " - " + hex(-O) : " + " + hex(O);
    };
    if (isFrameRoot(B.Root)) {
      std::string Var = isa<AllocaInst>(B.Root) ? name(B.Root) : "biara_cpu";
      auto L = T.Frames.find(B.Root);
      const Field *Fd = L == T.Frames.end() ? nullptr : L->second.at(B.Off, Bytes);
      if (Fd && Fd->Embed < 0 && uintTy(Fd->Bytes * 8) == Raw)
        return {Var + "." + Fd->Name, Raw};
      if (L != T.Frames.end())
        for (const Field &E : L->second.Fields)
          if (E.Embed >= 0 && E.Off <= B.Off && B.Off < E.Off + (int64_t)E.Bytes) {
            const Layout &In = T.Layouts.at(E.Embed);
            if (const Field *G = In.at(B.Off - E.Off, Bytes); G && G->Embed < 0)
              return {Var + "." + E.Name + "." + G->Name, T.fieldTy(*G)};
          }
      return {"*(" + Raw + " *)" + frameAddr(B.Root, B.Off), Raw};
    }
    if (!B.Root) {
      if (auto D = dataAt((uint64_t)B.Off, Bytes))
        return deref(D->name, (uint64_t)B.Off - D->addr, *D, Bytes, Raw);
      return {"*(" + Raw + " *)" + hex((uint64_t)B.Off) + "ull", Raw};
    }
    if (const Layout *L = T.layoutOf(B.Root)) {
      // Layout evidence may belong to an integer address expression. Its
      // C value is not necessarily a pointer until converted to the layout.
      std::string To = T.ptrTy(T.classOf(B.Root));
      std::string P = valAs(B.Root, To);
      if (ctyOf(B.Root) != To)
        P = "(" + P + ")";
      if (L->Scalar && L->Fields[0].Bytes == Bytes && B.Off % (int64_t)Bytes == 0) {
        if (!B.Off) return {"*" + P, T.fieldTy(L->Fields[0])};
        return {P+"["+num(B.Off/(int64_t)Bytes)+"]",T.fieldTy(L->Fields[0])};
      }
      if (!L->Scalar)
        if (const Field *Fd = L->at(B.Off, Bytes))
          return {P + "->" + Fd->Name, T.fieldTy(*Fd)};
      return {"*(" + Raw + " *)((uint8_t *)" + P + off(B.Off) + ")", Raw};
    }
    std::string P = val(B.Root);
    if (B.Root->getType()->isPointerTy())
      return {"*(" + Raw + " *)(" + P + off(B.Off) + ")", Raw};
    return {"*(" + Raw + " *)(uintptr_t)" + (B.Off ? "(" + P + off(B.Off) + ")" : P), Raw};
  }
  std::string mem(Value *Ptr, Type *Ty) { return resolve(Ptr, Ty).first; }
  std::string memTy(Value *Ptr, Type *Ty) {
    // `resolve` without recording references.
    auto *Saved = Refs;
    Refs = nullptr;
    std::string S = resolve(Ptr, Ty).second;
    Refs = Saved;
    return S;
  }

  std::string sval(Value *V) {
    unsigned Bits = V->getType()->getIntegerBitWidth();
    // A folded truncation is one signed cast (`(int32_t)rdi`, not
    // `(int32_t)((uint32_t)rdi)`); of a constant, its value (`2`, not
    // `(int32_t)2u`).
    if (auto *T = dyn_cast<TruncInst>(V); T && Inline.count(T)) {
      unsigned W = T->getDestTy()->getIntegerBitWidth();
      if (standard(W)) {
        if (auto *TC = dyn_cast<ConstantInt>(T->getOperand(0)))
          return slit(TC->getValue().trunc(W).sext(container(W)));
        return "(" + intTy(W) + ")" + ival(T->getOperand(0));
      }
    }
    // A constant is its signed value (`2`, not `(int32_t)2u`).
    if (Bits != 1)
      if (auto *C = dyn_cast<ConstantInt>(V))
        return slit(C->getValue());
    std::string E = ival(V);
    if (Bits == 1)
      return "(-(int64_t)" + E + ")";
    if (standard(Bits))
      return "(" + intTy(Bits) + ")" + E;
    Helpers.try_emplace("sext", false);
    return "biara_sext(" + E + ", " + std::to_string(Bits) + ")";
  }

  // `E` reduced to `Bits` (after arithmetic that may leave the width).
  std::string wrap(const std::string &E, unsigned Bits) {
    if (Bits == 1)
      return "((" + E + ") & 1)";
    if (standard(Bits))
      return Bits >= 32 ? E : "(" + uintTy(Bits) + ")(" + E + ")";
    APInt Mask = APInt::getLowBitsSet(container(Bits), Bits);
    return "((" + E + ") & " + lit(Mask) + ")";
  }

  // The value of `V` as an expression of type `ctyOf(V)`.
  std::string val(Value *V) {
    capturePC(V);
    if (auto *C = dyn_cast<ConstantInt>(V))
      return lit(C->getValue());
    if (auto *C = dyn_cast<ConstantFP>(V);
        C && (V->getType()->isFloatTy() || V->getType()->isDoubleTy())) {
      APInt Bits = C->getValueAPF().bitcastToAPInt();
      return "((union { " + uintTy(Bits.getBitWidth()) + " bits; " +
             cty(V->getType()) + " value; }){ .bits = " + lit(Bits) + " }).value";
    }
    if (auto *ST = dyn_cast<StructType>(V->getType()); ST && isa<Constant>(V)) {
      // An aggregate constant: a compound literal (undefined parts zero).
      auto *C = cast<Constant>(V);
      std::string S = "(" + aggregate(ST) + "){";
      for (unsigned K = 0; K < ST->getNumElements(); ++K)
        S += std::string(K ? ", " : "") + val(C->getAggregateElement(K));
      return S + "}";
    }
    if (isa<UndefValue>(V) || isa<PoisonValue>(V))
      return V->getType()->isPointerTy() ? "(uint8_t *)0" : "0";
    if (isa<ConstantPointerNull>(V))
      return "(uint8_t *)0";
    if (V->getType()->isIntegerTy(64) || V->getType()->isPointerTy()) {
      Base B = base(V, DL);
      if (isFrameRoot(B.Root)) {
        std::string P = frameAddr(B.Root, B.Off);
        return V->getType()->isPointerTy() ? P : "(uint64_t)" + P;
      }
    }
    if (auto *Fn = dyn_cast<Function>(V))
      return "(uint8_t *)&" + fnName(*Fn);
    if (auto *G = dyn_cast<GlobalValue>(V))
      return "(uint8_t *)&" + ident(G->getName());
    if (auto *A = dyn_cast<Argument>(V))
      return name(A);
    if (auto *CE = dyn_cast<ConstantExpr>(V)) {
      Instruction *I = CE->getAsInstruction();
      // Materializing a constant expression loses its inferred callback or
      // layout type; preserve the original value's C representation.
      std::string From = ctyOf(I), To = ctyOf(V);
      std::string S = conv("(" + expr(I) + ")", From, To);
      I->deleteValue();
      return From == To ? S : "(" + S + ")";
    }
    if (isa<Constant>(V)) {
      ++Unsupported;
      std::string Txt;
      raw_string_ostream OS(Txt);
      V->print(OS);
      return "0 /* unsupported constant " + OS.str() + " */";
    }
    auto *I = cast<Instruction>(V);
    if (Inline.count(I)) {
      // A whole cast is already atomic (`(uint32_t)x`, not `((uint32_t)x)`);
      // anything else keeps its parentheses.
      std::string E = expr(I);
      if (E.size() > 2 && E.front() == '(') {
        size_t D = 0, J = 0;
        for (; J < E.size(); ++J) {
          D += E[J] == '(' ? 1 : E[J] == ')' ? -1 : 0;
          if (D == 0)
            break;
        }
        static const char *const Ts[] = {
            "uint8_t",  "uint16_t", "uint32_t", "uint64_t", "int8_t",  "int16_t",
            "int32_t",  "int64_t",  "bool",     "uint8_t *", "int8_t *", "uint16_t *",
            "int16_t *", "uint32_t *", "int32_t *", "uint64_t *", "int64_t *",
            "const char *",
        };
        std::string In = E.substr(1, J - 1);
        // The operand after the type: present, and no top-level operator
        // (`(uint32_t)v | x` is a binary `|`, not a cast).
        std::string Rest = E.substr(J + 1);
        size_t RD = 0;
        bool Binary = Rest.empty();
        for (size_t K = (Rest[0] == '-' || Rest[0] == '!' || Rest[0] == '~') ? 1 : 0;
             !Binary && K < Rest.size(); ++K) {
          RD += Rest[K] == '(' || Rest[K] == '['
                    ? 1
                    : Rest[K] == ')' || Rest[K] == ']' ? -1 : 0;
          if (RD == 0 && std::string("+-*/%|&^?:<>=!").find(Rest[K]) != std::string::npos)
            Binary = true;
        }
        if (!Binary)
          for (const char *T : Ts)
            if (In == T)
              return E;
      }
      return "(" + E + ")";
    }
    if (Refs)
      Refs->push_back(I);
    return name(I);
  }

  // `val` converted to C type `To`.
  std::string valAs(Value *V, const std::string &To) {
    // Frame addresses as pointers directly.
    if (isPtrTy(To) && (V->getType()->isIntegerTy(64) || V->getType()->isPointerTy()))
      if (Base B = base(V, DL); isFrameRoot(B.Root)) {
        if (auto L = T.Frames.find(B.Root); L != T.Frames.end())
          if (const Field *E = L->second.startsAt(B.Off); E && E->Embed >= 0 &&
                                                         T.ptrTy(E->Embed) == To)
            return "&" + name(B.Root) + "." + E->Name;
        std::string P = frameAddr(B.Root, B.Off);
        return To == "uint8_t *" ? P : "(" + To + ")" + P;
      }
    if (auto *C = dyn_cast<ConstantInt>(V); C && C->isZero() && isPtrTy(To))
      return "0";
    return conv(val(V), ctyOf(V), To);
  }

  // `V` as an integer (pointer variables converted back).
  std::string ival(Value *V) { return valAs(V, cty(V->getType())); }

  std::string intrinsicFn(StringRef Base, unsigned Bits) {
    std::string N = ("biara_" + Base + std::to_string(Bits)).str();
    Helpers.try_emplace(N, false);
    return N;
  }

  // What a constant function address names: ` /* guest_main */`, else nothing.
  std::string symComment(Value *A) {
    if (auto *C = dyn_cast<ConstantInt>(A);
        C && C->getBitWidth() <= 64 && Syms.count(C->getZExtValue()))
      return " /* " + Syms[C->getZExtValue()] + " */";
    return "";
  }

  // What a constant address holds: ` /* "read ..." */`, else nothing.
  std::string strComment(Value *A) {
    if (auto *C = dyn_cast<ConstantInt>(A);
        C && C->getBitWidth() <= 64 && Strings.count(C->getZExtValue()))
      return " /* \"" + Strings[C->getZExtValue()] + "\" */";
    return "";
  }

  // Whether call `CB`'s argument `K` takes a string: the callee's
  // recovered prototype says so.
  bool strParam(CallBase &CB, Function *Callee, unsigned K) {
    if (!Callee || !Callee->isDeclaration() || K >= 64)
      return false;
    auto It = Protos.find(Callee->getName().str());
    return It != Protos.end() && ((It->second.strmask >> K) & 1);
  }

  std::string stringArg(Value *A, bool CanInline) {
    if (auto *C = dyn_cast<ConstantInt>(A); C && C->getBitWidth() <= 64) {
      uint64_t Address = C->getZExtValue();
      if (auto S = Strings.find(Address); S != Strings.end()) {
        if (CanInline && StringUses[Address] == 1)
          return "\"" + S->second + "\"";
        StrsUsed.try_emplace(Address, false);
        return "str_" + hex(Address).substr(2);
      }
    }
    return valAs(A, "const char *") + strComment(A);
  }

  bool inlineStringArg(CallBase &CB, Function *Callee) {
    // Known scalar-returning imports consume string text. Pointer-returning
    // and unknown imports may expose its identity; retain named storage.
    auto *P = prototype(Callee);
    if (!P || StringRef(P->Result).ends_with("*")) return false;
    if (Callee->getName().ends_with("strtol") || Callee->getName().ends_with("strtoll")) {
      auto *End = CB.arg_size() > 1 ? dyn_cast<ConstantInt>(CB.getArgOperand(1)) : nullptr;
      if (!End || !End->isZero()) return false;
    }
    return true;
  }

  std::string callArgs(CallBase &CB, Function *Callee) {
    std::string S;
    for (unsigned K = 0; K < CB.arg_size(); ++K) {
      if (K)
        S += ", ";
      Value *A = CB.getArgOperand(K);
      std::string To = Callee && !Callee->isDeclaration() && K < Callee->arg_size()
                           ? ctyOf(Callee->getArg(K))
                       : Callee && K < Callee->arg_size() ? cty(Callee->getArg(K)->getType())
                                                          : cty(A->getType());
      if (!Callee) {
        To=ctyOf(A);
        if (auto Alias=CallbackTypes.find(CB.getCalledOperand()); Alias!=CallbackTypes.end())
          To=CallbackArguments.at(Alias->second)[K];
      }
      if (auto *P = prototype(Callee); P && K < P->Count)
        To = P->Args[K];
      if (K==0 && Callee && Callee->isDeclaration() &&
          (Callee->getName()=="putc" || Callee->getName()=="putchar"))
        if (auto *C=dyn_cast<ConstantInt>(A); C && C->getBitWidth()<=64) {
          uint64_t Ch=C->getZExtValue();
          std::string Char;
          if (Ch=='\n') Char="'\\n'";
          else if (Ch=='\t') Char="'\\t'";
          else if (Ch=='\r') Char="'\\r'";
          else if (Ch=='\\') Char="'\\\\'";
          else if (Ch=='\'') Char="'\\''";
          else if (Ch>=32 && Ch<127) Char=std::string("'")+(char)Ch+"'";
          if (!Char.empty()) { S+=Char; continue; }
        }
      // A constant function address names itself.
      if (auto *C = dyn_cast<ConstantInt>(A);
          C && C->getBitWidth() <= 64 && Syms.count(C->getZExtValue())) {
        S += valAs(A, To);
        S += " /* " + Syms[C->getZExtValue()] + " */";
        continue;
      }
      if (strParam(CB, Callee, K)) {
        S += stringArg(A, inlineStringArg(CB, Callee));
        continue;
      }
      S += valAs(A, To);
      S += strComment(A);
    }
    return S;
  }

  // An integer comparison with an explicit predicate (for inverted `!`).
  std::string cmp(ICmpInst &C, CmpInst::Predicate Pred) {
    capturePC(&C);
    Value *A = C.getOperand(0), *B = C.getOperand(1);
    // `x >= 1` is `x > 0`.
    if ((Pred == CmpInst::ICMP_UGE || Pred == CmpInst::ICMP_SGE) && B->getType()->isIntegerTy())
      if (auto *K = dyn_cast<ConstantInt>(B); K && K->isOne()) {
        B = ConstantInt::get(B->getType(), 0);
        Pred = Pred == CmpInst::ICMP_UGE ? CmpInst::ICMP_UGT : CmpInst::ICMP_SGT;
      }
    std::string Op;
    switch (Pred) {
    case CmpInst::ICMP_EQ:
      Op = "==";
      break;
    case CmpInst::ICMP_NE:
      Op = "!=";
      break;
    case CmpInst::ICMP_UGT:
    case CmpInst::ICMP_SGT:
      Op = ">";
      break;
    case CmpInst::ICMP_UGE:
    case CmpInst::ICMP_SGE:
      Op = ">=";
      break;
    case CmpInst::ICMP_ULT:
    case CmpInst::ICMP_SLT:
      Op = "<";
      break;
    default:
      Op = "<=";
      break;
    }
    if (A->getType()->isPointerTy() || isPtrTy(ctyOf(A)) || isPtrTy(ctyOf(B))) {
      // Pointer variables against null read as pointers.
      auto *Z = dyn_cast<ConstantInt>(B);
      if (Z && Z->isZero() && isPtrTy(ctyOf(A)) && (Op == "==" || Op == "!="))
        return val(A) + " " + Op + " 0";
      return valAs(A, "uint64_t") + " " + Op + " " + valAs(B, "uint64_t");
    }
    // Signedness follows the predicate, so an inverted comparison keeps its
    // casts (`!(a < 1)` is `(int64)a >= 1`, not `a >= 1`).
    bool Sg = CmpInst::isSigned(Pred);
    return Sg ? sval(A) + " " + Op + " " + sval(B) : ival(A) + " " + Op + " " + ival(B);
  }

  // Expression of a pure instruction (or a call), without its assignment.
  std::string expr(Instruction *I) {
    capturePC(I);
    if (auto *Bin = dyn_cast<BinaryOperator>(I)) {
      unsigned Bits = I->getType()->getIntegerBitWidth();
      Value *A = Bin->getOperand(0), *B = Bin->getOperand(1);
      std::string X = ival(A), Y = ival(B);
      std::string Wide = Bits < 32 ? "(uint32_t)" : "";
      auto *K = dyn_cast<ConstantInt>(B);
      if ((Bin->getOpcode()==Instruction::And || Bin->getOpcode()==Instruction::Or ||
           Bin->getOpcode()==Instruction::Xor) && Bits!=1) {
        auto Mask=[](Value *V,std::string &Text) {
          if (auto *C=dyn_cast<ConstantInt>(V); C && C->getBitWidth()<=64)
            Text=hex(C->getZExtValue())+(container(C->getBitWidth())==64 ? "ull" : "u");
        };
        Mask(A,X);
        Mask(B,Y);
      }
      switch (Bin->getOpcode()) {
      case Instruction::Add:
        if (K && K->getValue().isNegative() && !K->getValue().isMinSignedValue() && Bits > 1)
          return wrap(X + " - " + lit(-K->getValue()), Bits);
        return wrap(X + " + " + Y, Bits);
      case Instruction::Sub:
        return wrap(X + " - " + Y, Bits);
      case Instruction::Mul:
        return wrap(Wide + X + " * " + Y, Bits);
      case Instruction::Shl:
        return wrap(Wide + X + " << " + Y, Bits);
      case Instruction::LShr:
        return X + " >> " + Y;
      case Instruction::AShr:
        return wrap("(" + uintTy(Bits) + ")(" + sval(A) + " >> " + Y + ")", Bits);
      case Instruction::UDiv:
        return X + " / " + Y;
      case Instruction::URem:
        return X + " % " + Y;
      case Instruction::SDiv:
        return wrap("(" + uintTy(Bits) + ")(" + sval(A) + " / " + sval(B) + ")", Bits);
      case Instruction::SRem:
        return wrap("(" + uintTy(Bits) + ")(" + sval(A) + " % " + sval(B) + ")", Bits);
      case Instruction::And: {
        // A low-bits mask is a narrowing cast (`(uint32_t)x`, not
        // `x & 0xffffffffull`).
        Value *O = nullptr;
        const ConstantInt *M = nullptr;
        if ((M = dyn_cast<ConstantInt>(B)))
          O = A;
        else if ((M = dyn_cast<ConstantInt>(A)))
          O = B;
        if (M && O) {
          unsigned N = M->getValue().popcount();
          if ((N == 8 || N == 16 || N == 32) && Bits > N && M->getValue().isMask(N))
            return wrap("(" + uintTy(N) + ")" + ival(O), Bits);
          // A one-mask is a modulo (`x % 4`, not `x & 3`).
          if (N >= 1 && N < Bits && M->getValue().isMask(N))
            return wrap(ival(O) + " % " + lit(APInt(Bits, 1) << N), Bits);
        }
        return X + " & " + Y;
      }
      case Instruction::Or:
        return X + " | " + Y;
      case Instruction::Xor:
        if (Bits == 1 && K && K->isOne()) {
          // `!(a < b)` reads as `a >= b`.
          Value *O = Bin->getOperand(0) == K ? Bin->getOperand(1) : Bin->getOperand(0);
          if (auto *C = dyn_cast<ICmpInst>(O))
            return cmp(*C, C->getInversePredicate());
          return "!" + X;
        }
        if (K && K->isAllOnesValue())
          return wrap("~" + X, Bits);
        return X + " ^ " + Y;
      default:
        break;
      }
    }
    if (auto *C = dyn_cast<ICmpInst>(I))
      return cmp(*C, C->getPredicate());
    if (auto *Cast = dyn_cast<CastInst>(I)) {
      Value *A = Cast->getOperand(0);
      Type *To = Cast->getType();
      // A cast of a constant is the folded value (`2`, not `(int32_t)2u`).
      if (auto *C = dyn_cast<ConstantInt>(A))
        if (auto *IT = dyn_cast<IntegerType>(To)) {
          unsigned W = IT->getBitWidth();
          bool Sg = cty(To).rfind("int", 0) == 0 || cty(To) == "biara_i128";
          switch (Cast->getOpcode()) {
          case Instruction::ZExt:
            return Sg ? slit(APInt(W, C->getZExtValue())) : lit(APInt(W, C->getZExtValue()));
          case Instruction::SExt:
            return Sg ? slit(C->getValue().sext(W)) : lit(C->getValue().sext(W));
          case Instruction::Trunc:
            if (W == 1)
              return C->getValue()[0] ? "true" : "false";
            return Sg ? slit(C->getValue().trunc(W)) : lit(C->getValue().trunc(W));
          default:
            break;
          }
        }
      switch (Cast->getOpcode()) {
      case Instruction::ZExt:
        return "(" + cty(To) + ")" + ival(A);
      case Instruction::SExt: {
        unsigned Bits = To->getIntegerBitWidth();
        // A sign extension of a truncation is one signed cast
        // (`(int32_t)rdi`, not `(int32_t)((uint32_t)rdi)`).
        if (auto *T = dyn_cast<TruncInst>(A)) {
          unsigned W = T->getDestTy()->getIntegerBitWidth();
          // ... and of a constant, its value (`2`, not `(int32_t)2u`).
          if (auto *TC = dyn_cast<ConstantInt>(T->getOperand(0)))
            return wrap(slit(TC->getValue().trunc(W).sext(Bits)), Bits);
          return wrap("(" + intTy(W) + ")" + ival(T->getOperand(0)), Bits);
        }
        return wrap("(" + cty(To) + ")" + sval(A), Bits);
      }
      case Instruction::Trunc: {
        unsigned Bits = To->getIntegerBitWidth();
        if (Bits == 1)
          return "(bool)(" + ival(A) + " & 1)";
        return wrap("(" + cty(To) + ")" + ival(A), Bits);
      }
      case Instruction::PtrToInt:
        return valAs(A, "uint64_t");
      case Instruction::IntToPtr:
        return valAs(A, ctyOf(Cast));
      case Instruction::BitCast:
        if (A->getType() == To || (A->getType()->isPointerTy() && To->isPointerTy()))
          return valAs(A, ctyOf(Cast));
        // C casts convert numerically; LLVM bitcasts preserve every bit,
        // including NaN payloads, signed zero, and whole vector lanes.
        return "((union { " + cty(A->getType()) + " from; " + cty(To) +
               " to; }){ .from = " + val(A) + " }).to";
      default:
        break;
      }
    }
    if (auto *F = dyn_cast<FreezeInst>(I))
      return valAs(F->getOperand(0), ctyOf(F));
    if (auto *S = dyn_cast<SelectInst>(I)) {
      // Short-circuit forms of boolean selects.
      if (S->getType()->isIntegerTy(1)) {
        auto *T = dyn_cast<ConstantInt>(S->getTrueValue());
        auto *F = dyn_cast<ConstantInt>(S->getFalseValue());
        if (T && T->isOne())
          return ival(S->getCondition()) + " || " + ival(S->getFalseValue());
        if (F && F->isZero())
          return ival(S->getCondition()) + " && " + ival(S->getTrueValue());
      }
      std::string To = ctyOf(S);
      return ival(S->getCondition()) + " ? " + valAs(S->getTrueValue(), To) + " : " +
             valAs(S->getFalseValue(), To);
    }
    if (auto *G = dyn_cast<GetElementPtrInst>(I)) {
      std::string S = "(" + valAs(G->getPointerOperand(), "uint8_t *");
      for (auto It = gep_type_begin(G), E = gep_type_end(G); It != E; ++It) {
        Value *Idx = It.getOperand();
        if (StructType *ST = It.getStructTypeOrNull()) {
          uint64_t Off =
              DL.getStructLayout(ST)->getElementOffset(cast<ConstantInt>(Idx)->getZExtValue());
          if (Off)
            S += " + " + num(Off);
          continue;
        }
        uint64_t Size = It.getSequentialElementStride(DL).getFixedValue();
        if (auto *K = dyn_cast<ConstantInt>(Idx)) {
          int64_t Off = K->getSExtValue() * (int64_t)Size;
          if (Off)
            S += " + " + num(Off);
          continue;
        }
        S += " + (int64_t)" + sval(Idx) + (Size != 1 ? " * " + std::to_string(Size) : "");
      }
      return conv(S + ")", "uint8_t *", ctyOf(G));
    }
    if (auto *E = dyn_cast<ExtractValueInst>(I)) {
      std::string S = val(E->getAggregateOperand());
      for (unsigned Idx : E->indices())
        S += ".f" + std::to_string(Idx);
      return S;
    }
    if (auto *E = dyn_cast<ExtractElementInst>(I))
      return "(" + val(E->getVectorOperand()) + ")[" + ival(E->getIndexOperand()) + "]";
    if (auto *L = dyn_cast<LoadInst>(I))
      return conv(mem(L->getPointerOperand(), L->getType()),
                  memTy(L->getPointerOperand(), L->getType()), ctyOf(L));
    if (auto *CB = dyn_cast<CallBase>(I))
      return call(*CB);
    ++Unsupported;
    return "0 /* unsupported: " + std::string(I->getOpcodeName()) + " */";
  }

  std::string call(CallBase &CB) {
    Function *Callee = CB.getCalledFunction();
    // `strtol(s, 0, 10)` is `atol(s)` (likewise `strtoll`).
    if (Callee && CB.arg_size() == 3)
      if (StringRef N = Callee->getName(); N == "strtol" || N == "strtoll" ||
                                              N == "__isoc23_strtol" || N == "__isoc23_strtoll") {
        auto *End = dyn_cast<ConstantInt>(CB.getArgOperand(1));
        auto *Base = dyn_cast<ConstantInt>(CB.getArgOperand(2));
        if (End && End->isZero() && Base && Base->getZExtValue() == 10) {
          AtolUsed = true;
          Value *A = CB.getArgOperand(0);
          return "atol(" + stringArg(A, true) + ")";
        }
      }
    if (!Callee) {
      auto Alias=CallbackTypes.find(CB.getCalledOperand());
      if (Alias!=CallbackTypes.end())
        return val(CB.getCalledOperand()) + "(" + callArgs(CB,nullptr) + ")";
      std::string Sig = cty(CB.getType()) + " (*)(";
      for (unsigned K = 0; K < CB.arg_size(); ++K)
        Sig += std::string(K ? ", " : "") + ctyOf(CB.getArgOperand(K));
      if (!CB.arg_size())
        Sig += "void";
      Sig += ")";
      return "((" + Sig + ")" + valAs(CB.getCalledOperand(), "uint8_t *") + ")(" +
             callArgs(CB, nullptr) + ")";
    }
    if (Callee->isIntrinsic())
      return intrinsic(CB, Callee);
    // x86 division prelude (emitted by abi_form): register its definition
    // with the struct it returns.
    if (Callee->getName().starts_with("biara_div") ||
        Callee->getName().starts_with("biara_sdiv")) {
      auto *ST = cast<StructType>(CB.getType());
      Helpers.try_emplace(Callee->getName().str() + "|" + aggregate(ST), false);
    }
    // Calls to unknown code that set no argument still pass the first,
    // as its prototype has one.
    if (Callee->isVarArg() && Callee->arg_empty() && !CB.arg_size() && unknownArity(*Callee))
      return fnName(*Callee) + "(0)";
    std::string Result = fnName(*Callee) + "(" + callArgs(CB, Callee) + ")";
    if (auto *P=prototype(Callee); P && importResult(*Callee,*P)=="int32_t")
      Result = "(uint32_t)" + Result;
    return Result;
  }

  std::string intrinsic(CallBase &CB, Function *Callee) {
    auto arg = [&](unsigned K) { return ival(CB.getArgOperand(K)); };
    Type *Ty = CB.getType();
    unsigned Bits = Ty->isIntegerTy() ? Ty->getIntegerBitWidth() : 0;
    if (auto *S = dyn_cast<StructType>(Ty))
      Bits = S->getElementType(0)->getIntegerBitWidth();
    bool Std = standard(Bits) && Bits >= 8;
    switch (Callee->getIntrinsicID()) {
    case Intrinsic::fshl:
    case Intrinsic::fshr: {
      bool L = Callee->getIntrinsicID() == Intrinsic::fshl;
      if (!Std)
        break;
      if (CB.getArgOperand(0) == CB.getArgOperand(1))
        return intrinsicFn(L ? "rotl" : "rotr", Bits) + "(" + arg(0) + ", " + arg(2) + ")";
      return intrinsicFn(L ? "fshl" : "fshr", Bits) + "(" + arg(0) + ", " + arg(1) + ", " +
             arg(2) + ")";
    }
    case Intrinsic::ctlz:
    case Intrinsic::cttz:
    case Intrinsic::ctpop:
    case Intrinsic::bswap:
    case Intrinsic::bitreverse:
    case Intrinsic::abs: {
      if (!Std)
        break;
      const char *N = Callee->getIntrinsicID() == Intrinsic::ctlz    ? "clz"
                      : Callee->getIntrinsicID() == Intrinsic::cttz  ? "ctz"
                      : Callee->getIntrinsicID() == Intrinsic::ctpop ? "popcount"
                      : Callee->getIntrinsicID() == Intrinsic::bswap ? "bswap"
                      : Callee->getIntrinsicID() == Intrinsic::abs   ? "abs"
                                                                     : "bitreverse";
      return intrinsicFn(N, Bits) + "(" + arg(0) + ")";
    }
    case Intrinsic::umax:
    case Intrinsic::umin:
    case Intrinsic::smax:
    case Intrinsic::smin: {
      if (!Std)
        break;
      auto ID = Callee->getIntrinsicID();
      const char *N = ID == Intrinsic::umax   ? "umax"
                      : ID == Intrinsic::umin ? "umin"
                      : ID == Intrinsic::smax ? "smax"
                                              : "smin";
      return intrinsicFn(N, Bits) + "(" + arg(0) + ", " + arg(1) + ")";
    }
    case Intrinsic::uadd_with_overflow:
    case Intrinsic::usub_with_overflow:
    case Intrinsic::umul_with_overflow:
    case Intrinsic::sadd_with_overflow:
    case Intrinsic::ssub_with_overflow:
    case Intrinsic::smul_with_overflow: {
      if (!Std)
        break;
      auto ID = Callee->getIntrinsicID();
      const char *N = ID == Intrinsic::uadd_with_overflow   ? "uadd_ovf"
                      : ID == Intrinsic::usub_with_overflow ? "usub_ovf"
                      : ID == Intrinsic::umul_with_overflow ? "umul_ovf"
                      : ID == Intrinsic::sadd_with_overflow ? "sadd_ovf"
                      : ID == Intrinsic::ssub_with_overflow ? "ssub_ovf"
                                                            : "smul_ovf";
      std::string Agg = aggregate(cast<StructType>(Ty));
      Helpers.try_emplace("biara_" + std::string(N) + std::to_string(Bits) + "|" + Agg, false);
      return std::string("biara_") + N + std::to_string(Bits) + "(" + arg(0) + ", " + arg(1) +
             ")";
    }
    case Intrinsic::scmp:
    case Intrinsic::ucmp: {
      Value *A = CB.getArgOperand(0), *B = CB.getArgOperand(1);
      bool Signed = Callee->getIntrinsicID() == Intrinsic::scmp;
      std::string X = Signed ? sval(A) : ival(A), Y = Signed ? sval(B) : ival(B);
      return wrap("(" + cty(Ty) + ")((" + X + " > " + Y + ") - (" + X + " < " + Y + "))", Bits);
    }
    case Intrinsic::usub_sat:
      return "(" + ival(CB.getArgOperand(0)) + " > " + ival(CB.getArgOperand(1)) + " ? " +
             ival(CB.getArgOperand(0)) + " - " + ival(CB.getArgOperand(1)) + " : 0)";
    case Intrinsic::uadd_sat: {
      if (!Std)
        break;
      return intrinsicFn("uadd_sat", Bits) + "(" + arg(0) + ", " + arg(1) + ")";
    }
    case Intrinsic::memcpy:
    case Intrinsic::memmove:
      return std::string(Callee->getIntrinsicID() == Intrinsic::memcpy ? "__builtin_memcpy"
                                                                       : "__builtin_memmove") +
             "(" + valAs(CB.getArgOperand(0), "uint8_t *") + ", " +
             valAs(CB.getArgOperand(1), "uint8_t *") + ", " + arg(2) + ")";
    case Intrinsic::memset:
      return "__builtin_memset(" + valAs(CB.getArgOperand(0), "uint8_t *") + ", " + arg(1) +
             ", " + arg(2) + ")";
    default:
      break;
    }
    ++Unsupported;
    return "0 /* unsupported intrinsic " + Callee->getName().str() + " */";
  }

  static bool ignored(Instruction &I) {
    if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
      switch (II->getIntrinsicID()) {
      case Intrinsic::lifetime_start:
      case Intrinsic::lifetime_end:
      case Intrinsic::assume:
      case Intrinsic::experimental_noalias_scope_decl:
      case Intrinsic::donothing:
        return true;
      default:
        break;
      }
    }
    return isa<AllocaInst>(I) || I.isDebugOrPseudoInst();
  }

  bool pure(Instruction &I) {
    return isa<BinaryOperator>(I) || isa<ICmpInst>(I) || isa<CastInst>(I) || isa<SelectInst>(I) ||
           isa<GetElementPtrInst>(I) || isa<FreezeInst>(I) || isa<ExtractValueInst>(I);
  }

  // Whether `V`'s expression reads a phi of `BB` (which the copies on an
  // edge into `BB` may already have overwritten).
  static bool readsPhiOf(Value *V, BasicBlock *BB, unsigned Depth = 0) {
    auto *I = dyn_cast<Instruction>(V);
    if (!I || Depth > 8)
      return false;
    if (isa<PHINode>(I))
      return I->getParent() == BB;
    for (Value *Op : I->operands())
      if (readsPhiOf(Op, BB, Depth + 1))
        return true;
    return false;
  }

  bool foldable(Instruction &I) {
    if (!pure(I) || !I.hasOneUse())
      return false;
    unsigned Budget = 16;
    if (!smallExpression(&I, Budget))
      return false;
    auto *U = dyn_cast<Instruction>(*I.user_begin());
    // Into a phi's copy at the end of this block, unless the copies could
    // clobber what it reads.
    if (auto *P = dyn_cast_or_null<PHINode>(U)) {
      if (P->getIncomingBlock(*I.use_begin()) != I.getParent() || readsPhiOf(&I, P->getParent()))
        return false;
      return !isPtrTy(ctyOf(&I)) || cty(I.getType()) == ctyOf(&I);
    }
    if (!U || U->getParent() != I.getParent())
      return false;
    return !isPtrTy(ctyOf(&I)) || cty(I.getType()) == ctyOf(&I);
  }

  std::string label(BasicBlock *BB) { return "L" + std::to_string(Order[BB]); }

  // Assignments to the phis of `To` for the edge from `From`.
  void edge(BasicBlock *From, BasicBlock *To) {
    std::vector<PHINode *> Phis;
    for (PHINode &P : To->phis())
      if (Loops.empty() || Loops.back().L->getHeader()!=To || Loops.back().Induction!=&P)
        Phis.push_back(&P);
    if (Phis.empty())
      return;
    // Parallel copy: through temporaries when one phi reads another.
    bool Temps = false;
    for (PHINode *P : Phis) {
      Value *In = P->getIncomingValueForBlock(From);
      if (auto *IP = dyn_cast<PHINode>(In); IP && IP->getParent() == To && IP != P)
        Temps = true;
    }
    std::vector<Stmt> Tail;
    for (PHINode *P : Phis) {
      Stmt S;
      S.Def = P;
      S.Assigns = P;
      beginStmt(S, From->getTerminator());
      Value *In = P->getIncomingValueForBlock(From);
      std::string V = valAs(In, ctyOf(P));
      endStmt();
      // A constant string or function address names itself in a comment.
      std::string Note = strComment(In) + symComment(In);
      if (Temps) {
        S.Text = name(P) + "_next = " + V + Note + ";";
        S.Staged = true;
        put(S);
        Stmt S2;
        S2.Text = name(P) + " = " + name(P) + "_next;";
        S2.Def = P;
        S2.Assigns = P;
        S2.Pcs = S.Pcs;
        S2.LostFold = true;
        Tail.push_back(S2);
      } else if (V != name(P)) {
        S.Text = name(P) + " = " + bare(V) + Note + ";";
        put(S);
      }
    }
    for (Stmt &X : Tail)
      put(X);
  }

  // ---- structure -------------------------------------------------------
  //
  // Blocks are emitted along the dominator tree: a conditional branch
  // becomes `if`/`else` up to its immediate post-dominator (emitted after
  // it), a natural loop `for (;;)` with `continue` for its back edges and
  // `break` for edges to its single exit; edges nothing structured covers
  // stay gotos.

  std::vector<Stmt> Out;
  unsigned Depth = 1;
  std::set<BasicBlock *> Emitted;
  std::vector<BasicBlock *> Pending;
  DominatorTree *DT = nullptr;
  PostDominatorTree *PDT = nullptr;
  LoopInfo *LI = nullptr;
  struct LoopCx {
    Loop *L;
    BasicBlock *Follow; // its single exit, emitted after it
    unsigned Switches;  // switches opened inside it (`break` is theirs)
    PHINode *Induction = nullptr;
    BasicBlock *DoLatch = nullptr;
    Stmt Footer{};
  };
  std::vector<LoopCx> Loops;

  void put(Stmt S) {
    S.Depth = Depth;
    Out.push_back(std::move(S));
  }
  void put(const std::string &T) { put(plain(T)); }

  void jumpTo(BasicBlock *To) {
    Targeted.insert(To);
    put("goto " + label(To) + ";");
    if (!Emitted.count(To))
      Pending.push_back(To);
  }

  // Whether `BB` only returns (its phi, at most): edges to it return.
  static bool returnsOnly(BasicBlock *BB) {
    auto *R = dyn_cast<ReturnInst>(BB->getFirstNonPHIOrDbg());
    if (!R)
      return false;
    for (PHINode &P : BB->phis())
      if (&P != R->getReturnValue())
        return false;
    return true;
  }

  // Control from `From` to `To`, where `Next` follows naturally.
  // Returns whether control can fall through past this edge.
  bool transfer(BasicBlock *From, BasicBlock *To, BasicBlock *Next) {
    // A block that only returns (the merged return LLVM makes) returns
    // right here, with this edge's value; also when it IS `Next` (a switch
    // or if arm rejoining only to return), since nothing after needs it.
    if (returnsOnly(To)) {
      Value *V = cast<ReturnInst>(To->getTerminator())->getReturnValue();
      {
        Stmt S;
        beginStmt(S, To->getTerminator());
        if (!V)
          S.Text = "return;";
        else {
          Value *In = V;
          if (auto *P = dyn_cast<PHINode>(V); P && P->getParent() == To)
            In = P->getIncomingValueForBlock(From);
          S.Text = "return " + bare(valAs(In, cty(V->getType()))) + ";";
        }
        endStmt();
        put(S);
        return false;
      }
    }
    edge(From, To);
    if (To == Next)
      return true;
    if (!Loops.empty()) {
      LoopCx &C = Loops.back();
      if (To == C.L->getHeader()) {
        put("continue;");
        return false;
      }
      if (To == C.Follow && !C.Switches) {
        put("break;");
        return false;
      }
    }
    if (!Emitted.count(To) && onlyEntry(From, To))
      return emit(To, Next);
    jumpTo(To);
    return false;
  }

  // Whether `From` is the only way into `To` other than its back edges.
  bool onlyEntry(BasicBlock *From, BasicBlock *To) {
    for (BasicBlock *P : predecessors(To))
      if (P != From && !DT->dominates(To, P))
        return false;
    return true;
  }

  // Where the arms of `B`'s branch meet, if that can follow them.
  BasicBlock *join(BasicBlock *B) {
    DomTreeNode *N = PDT->getNode(B);
    DomTreeNode *I = N ? N->getIDom() : nullptr;
    BasicBlock *J = I ? I->getBlock() : nullptr;
    if (!J || Emitted.count(J) || !DT->dominates(B, J))
      return nullptr;
    if (!Loops.empty() && (!Loops.back().L->contains(J) || J == Loops.back().L->getHeader()))
      return nullptr;
    return J;
  }

  bool emit(BasicBlock *B, BasicBlock *Next) {
    if (B == Next)
      return true;
    if (Emitted.count(B)) {
      jumpTo(B);
      return false;
    }
    // A return-only join whose every incoming edge already returned
    // directly (and nothing jumps to it) is unreachable: skip it.
    if (returnsOnly(B) && !Targeted.count(B)) {
      bool AllIn = !predecessors(B).empty();
      for (BasicBlock *P : predecessors(B))
        AllIn &= Emitted.count(P) != 0;
      if (AllIn)
        return false;
    }
    Emitted.insert(B);
    Stmt Lb;
    Lb.Label = B;
    put(Lb);
    Loop *L = LI->getLoopFor(B);
    if (L && L->getHeader() == B) {
      // `break` goes to the single exit: emitted right after the loop, or
      // what follows it anyway.
      BasicBlock *Exit = L->getUniqueExitBlock();
      // (An exit that only returns is not needed after it: its edges return.)
      bool After = Exit && !Emitted.count(Exit) && DT->dominates(B, Exit) && !returnsOnly(Exit);
      // A pure header with one inside edge and no exit phi can be expressed
      // as a pre-test loop without moving effects or parallel copies.
      if (auto *Br=dyn_cast<CondBrInst>(B->getTerminator()); Br && Exit && Exit->phis().empty()) {
        bool Neg=Br->getSuccessor(0)==Exit;
        BasicBlock *Inside=Br->getSuccessor(Neg ? 1 : 0);
        bool Clean=Br->getSuccessor(Neg ? 0 : 1)==Exit && Inside!=B && L->contains(Inside);
        for (Instruction &I : *B)
          if (!isa<PHINode>(I) && !I.isTerminator() && !ignored(I) && !Inline.count(&I))
            Clean=false;
        if (Clean) {
          PHINode *Induction=nullptr;
          BinaryOperator *Update=nullptr;
          BasicBlock *Pre=L->getLoopPreheader(), *Latch=L->getLoopLatch();
          if (Pre && Latch && isa<UncondBrInst>(Latch->getTerminator()) &&
              std::distance(B->phis().begin(),B->phis().end())==1) {
            auto &P=*B->phis().begin();
            auto *U=dyn_cast<BinaryOperator>(P.getIncomingValueForBlock(Latch));
            if (P.getNumIncomingValues()==2 && U && U->getParent()==Latch && U->hasOneUse() && U->getOperand(0)==&P &&
                isa<ConstantInt>(U->getOperand(1)) &&
                (U->getOpcode()==Instruction::Add || U->getOpcode()==Instruction::Sub)) {
              Induction=&P;
              Update=U;
              Inline.insert(U);
            }
          }
          Stmt Header;
          beginStmt(Header,Br);
          std::string Cond=negCond(Br->getCondition(),Neg);
          if (Induction) {
            std::string Init;
            // Absorb only the immediately preceding proven phi assignment.
            if (Out.size()>=2 && Out.back().Label==B) {
              Stmt &InitStmt=Out[Out.size()-2];
              if (InitStmt.Assigns==Induction && !InitStmt.Staged) {
                Init=InitStmt.Text;
                if (!Init.empty() && Init.back()==';') Init.pop_back();
                Header.Pcs.insert(InitStmt.Pcs.begin(),InitStmt.Pcs.end());
                Header.LostFold|=InitStmt.LostFold;
                Header.Refs.insert(Header.Refs.end(),InitStmt.Refs.begin(),InitStmt.Refs.end());
                Out.erase(Out.end()-2);
              }
            }
            Header.Assigns=Induction;
            Header.Text="for (" + Init + "; " + Cond + "; " + name(Induction) +
                        " = " + bare(expr(Update)) + ") {";
          } else {
            Header.Text="while (" + Cond + ") {";
          }
          endStmt();
          put(Header);
          ++Depth;
          Loops.push_back({L,Exit,0,Induction});
          transfer(B,Inside,B);
          Loops.pop_back();
          --Depth;
          put("}");
          return transfer(B,Exit,Next);
        }
      }
      // Post-test loops require a unique conditional latch and no loop/exit
      // phi copies: evaluating the condition at the footer then preserves
      // the original value versions and every effect before the test.
      BasicBlock *Latch=L->getLoopLatch();
      auto *LatchBr=Latch ? dyn_cast<CondBrInst>(Latch->getTerminator()) : nullptr;
      bool Do=LatchBr && B->phis().empty() && Exit && Exit->phis().empty();
      if (Do) {
        Do=(LatchBr->getSuccessor(0)==B && LatchBr->getSuccessor(1)==Exit) ||
           (LatchBr->getSuccessor(1)==B && LatchBr->getSuccessor(0)==Exit);
        for (BasicBlock *Block : L->blocks()) {
          if (Block!=Latch && !isa<UncondBrInst>(Block->getTerminator())) Do=false;
          for (BasicBlock *To : successors(Block))
            if (!L->contains(To) && (Block!=Latch || To!=Exit)) Do=false;
        }
      }
      if (Do) {
        put("do {");
        ++Depth;
        Loops.push_back({L,Exit,0,nullptr,Latch});
        body(B,B);
        Stmt Footer=std::move(Loops.back().Footer);
        Loops.pop_back();
        --Depth;
        put(Footer);
        return transfer(Latch,Exit,Next);
      }
      put("for (;;) {");
      ++Depth;
      Loops.push_back({L, After || Exit == Next ? Exit : nullptr, 0});
      body(B, B);
      Loops.pop_back();
      --Depth;
      put("}");
      if (After)
        return emit(Exit, Next);
      return true;
    }
    return body(B, Next);
  }

  // A branch condition, negated when the arms swap: `!(a < b)` prints as
  // the inverted comparison.
  std::string negCond(Value *V, bool Neg) {
    if (Neg)
      if (auto *C = dyn_cast<ICmpInst>(V))
        return cmp(*C, C->getInversePredicate());
    std::string C = bare(ival(V));
    return Neg ? "!(" + C + ")" : C;
  }

  bool body(BasicBlock *B, BasicBlock *Next) {
    statements(*B);
    Instruction *Term = B->getTerminator();
    Stmt S;
    if (!Loops.empty() && Loops.back().DoLatch==B) {
      auto *Br=cast<CondBrInst>(Term);
      beginStmt(S,Term);
      S.Text="} while (" + negCond(Br->getCondition(),Br->getSuccessor(1)==Loops.back().L->getHeader()) + ");";
      endStmt();
      Loops.back().Footer=std::move(S);
      return true;
    }
    if (auto *Br = dyn_cast<UncondBrInst>(Term)) {
      return transfer(B, Br->getSuccessor(), Next);
    } else if (auto *Br = dyn_cast<CondBrInst>(Term)) {
      BasicBlock *J = join(B);
      BasicBlock *RN = J ? J : Next;
      BasicBlock *T = Br->getSuccessor(0), *F = Br->getSuccessor(1);
      auto empty = [&](BasicBlock *X) { return X == RN && X->phis().empty(); };
      bool Swap = empty(T) && !empty(F);
      beginStmt(S, Term);
      std::string C = negCond(Br->getCondition(), Swap);
      endStmt();
      if (Swap)
        std::swap(T, F);
      S.Text = "if (" + C + ") {";
      put(S);
      ++Depth;
      bool FT = transfer(B, T, RN);
      --Depth;
      // An arm that does not fall through needs no `else`.
      bool Leaves = ends(Out.back().Text) && !Out.back().Label;
      if (!empty(F)) {
        put(Leaves ? "}" : "} else {");
        Depth += !Leaves;
        FT |= transfer(B, F, RN);
        Depth -= !Leaves;
      }
      if (!Leaves || empty(F))
        put("}");
      if (J && (FT || J != RN))
        return emit(J, Next);
      return FT;
    } else if (auto *Sw = dyn_cast<SwitchInst>(Term)) {
      BasicBlock *J = join(B);
      BasicBlock *RN = J ? J : Next;
      beginStmt(S, Term);
      S.Text = "switch (" + bare(ival(Sw->getCondition())) + ") {";
      endStmt();
      put(S);
      if (!Loops.empty())
        ++Loops.back().Switches;
      bool Falls = false;
      auto arm = [&](const std::string &Case, BasicBlock *To) {
        put(Case);
        ++Depth;
        size_t Before = Out.size();
        bool F = transfer(B, To, RN);
        // Falling out of the arm continues after the switch.
        if (Out.size() == Before || !ends(Out.back().Text)) {
          put("break;");
          F = true;
        }
        Falls |= F;
        --Depth;
      };
      for (auto &Case : Sw->cases())
        arm("case " + lit(Case.getCaseValue()->getValue()) + ":", Case.getCaseSuccessor());
      arm("default:", Sw->getDefaultDest());
      if (!Loops.empty())
        --Loops.back().Switches;
      put("}");
      if (J && (Falls || J != RN))
        return emit(J, Next);
      return Falls;
    } else {
      beginStmt(S, Term);
      if (auto *R = dyn_cast<ReturnInst>(Term)) {
        Value *V = R->getReturnValue();
        S.Text = V ? "return " + bare(valAs(V, cty(V->getType()))) + ";" : "return;";
      } else {
        S.Text = "__builtin_unreachable();";
      }
      endStmt();
      put(S);
      return true;
    }
  }

  // Whether statement `T` leaves the code after it unreachable.
  static bool ends(const std::string &T) {
    return T.rfind("return", 0) == 0 || T.rfind("goto ", 0) == 0 || T == "continue;" ||
           T == "break;" || T == "__builtin_unreachable();";
  }

  void statements(BasicBlock &BB) {
    for (Instruction &I : BB) {
      if (isa<PHINode>(I) || ignored(I) || Inline.count(&I))
        continue;
      Stmt S;
      beginStmt(S, &I);
      if (auto *St = dyn_cast<StoreInst>(&I)) {
        Value *P = St->getPointerOperand(), *V = St->getValueOperand();
        S.Text = mem(P, V->getType()) + " = " + bare(valAs(V, memTy(P, V->getType()))) + ";";
      } else if (I.isTerminator()) {
        endStmt();
        continue;
      } else if (isa<FenceInst>(I)) {
        S.Text = "__atomic_thread_fence(__ATOMIC_SEQ_CST);";
      } else if (auto *X = dyn_cast<AtomicRMWInst>(&I)) {
        const char *Op = nullptr;
        switch (X->getOperation()) {
        case AtomicRMWInst::Xchg:
          Op = "__atomic_exchange_n";
          break;
        case AtomicRMWInst::Add:
          Op = "__atomic_fetch_add";
          break;
        case AtomicRMWInst::Sub:
          Op = "__atomic_fetch_sub";
          break;
        case AtomicRMWInst::And:
          Op = "__atomic_fetch_and";
          break;
        case AtomicRMWInst::Or:
          Op = "__atomic_fetch_or";
          break;
        case AtomicRMWInst::Xor:
          Op = "__atomic_fetch_xor";
          break;
        default:
          break;
        }
        std::string Call = Op ? std::string(Op) + "(&" + mem(X->getPointerOperand(), X->getType()) +
                                    ", " + ival(X->getValOperand()) + ", __ATOMIC_SEQ_CST)"
                              : "0 /* unsupported atomicrmw */";
        if (!Op)
          ++Unsupported;
        S.Text = name(&I) + " = " + Call + ";";
      } else if (auto *X = dyn_cast<AtomicCmpXchgInst>(&I)) {
        std::string N = name(&I);
        Type *VT = X->getCompareOperand()->getType();
        S.Text = N + ".f0 = " + ival(X->getCompareOperand()) + "; " + N +
                 ".f1 = __atomic_compare_exchange_n(&" + mem(X->getPointerOperand(), VT) + ", &" +
                 N + ".f0, " + ival(X->getNewValOperand()) +
                 ", false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);";
      } else if (auto *Ins = dyn_cast<InsertValueInst>(&I)) {
        std::string N = name(&I);
        Value *Agg = Ins->getAggregateOperand();
        std::string Field = N;
        for (unsigned Idx : Ins->indices())
          Field += ".f" + std::to_string(Idx);
        S.Text = (isa<UndefValue>(Agg) ? "" : N + " = " + val(Agg) + "; ") + Field + " = " +
                 ival(Ins->getInsertedValueOperand()) + ";";
      } else if (auto *CB = dyn_cast<CallBase>(&I)) {
        std::string E = call(*CB);
        S.Text = I.getType()->isVoidTy() || I.use_empty()
                     ? E + ";"
                     : name(&I) + " = " + conv(E, callType(*CB), ctyOf(&I)) + ";";
        if (!I.getType()->isVoidTy() && !I.use_empty())
          S.Rhs = bare(conv(E, callType(*CB), ctyOf(&I)));
      } else {
        S.Rhs = bare(expr(&I));
        S.Text = name(&I) + " = " + S.Rhs + ";";
        if (pure(I) || isa<LoadInst>(I))
          S.Def = &I;
      }
      if (!I.getType()->isVoidTy() && (!I.use_empty() || !isa<CallBase>(I)))
        S.Assigns = &I;
      endStmt();
      put(S);
    }
  }

  // C name of a function; the guest's `main` is not C's (see `run`).
  static std::string fnName(const Function &Fn) {
    return Fn.getName() == "main" && !Fn.isDeclaration() ? "guest_main" : ident(Fn.getName());
  }

  // Most arguments a call passes to unknown code `Fn` (an import).
  static unsigned unknownArity(const Function &Fn) {
    unsigned Max = 0;
    for (const User *U : Fn.users())
      if (auto *CB = dyn_cast<CallBase>(U))
        Max = std::max(Max, (unsigned)CB->arg_size());
    return Max;
  }

  // `E` without one pair of parentheses around all of it.
  static std::string bare(const std::string &E) {
    if (E.size() < 2 || E.front() != '(' || E.back() != ')')
      return E;
    int Depth = 0;
    for (size_t I = 0; I + 1 < E.size(); ++I) {
      Depth += E[I] == '(' ? 1 : E[I] == ')' ? -1 : 0;
      if (Depth == 0)
        return E;
    }
    return E.substr(1, E.size() - 2);
  }

  std::string signature(Function &Fn, bool WithNames = true) {
    if (auto *P=prototype(&Fn)) {
      std::string S=importResult(Fn,*P) + " " + fnName(Fn) + "(";
      for (unsigned K=0;K<P->Count;++K)
        S += (K ? ", " : "") + std::string(P->Args[K]);
      if (P->Variadic) S += ", ...";
      if (!P->Count) S += "void";
      return S + ")";
    }
    std::string S = cty(Fn.getReturnType()) + " " + fnName(Fn) + "(";
    // Imports with a recovered shape: `const char *` where strings go,
    // `uint64_t` elsewhere, `, ...` when calls vary in count.
    if (Fn.isDeclaration())
      if (auto It = Protos.find(Fn.getName().str()); It != Protos.end()) {
        const BiaraProto &P = It->second;
        for (uint32_t K = 0; K < P.nargs; ++K)
          S += (K ? ", " : "") + std::string((P.strmask >> K) & 1 ? "const char *" : "uint64_t");
        if (P.nargs == 0 && !P.ellipsis)
          S += "void";
        if (P.ellipsis)
          S += (P.nargs ? ", ..." : "uint64_t, ...");
        return S + ")";
      }
    // Unknown code: the arguments of the widest call, then any.
    if (Fn.isVarArg() && Fn.arg_empty())
      return S + (unknownArity(Fn) ? "uint64_t, ...)" : "void)");
    for (unsigned K = 0; K < Fn.arg_size(); ++K) {
      Argument *A = Fn.getArg(K);
      S += (K ? ", " : "") + (Fn.isDeclaration() ? cty(A->getType()) : ctyOf(A) + (WithNames ? " " + name(A) : ""));
    }
    if (Fn.isVarArg())
      S += ", ...";
    if (Fn.arg_empty())
      S += "void";
    return S + ")";
  }

  std::string function(Function &Fn) {
    F = &Fn;
    Names.clear();
    Originals.clear();
    NameEvidence.clear();
    StatementJson = "[";
    StatementCount = MappedCount = MaxDepth = TempCount = 0;
    Taken.clear();
    NextSuffix.clear();
    Inline.clear();
    Order.clear();
    Targeted.clear();
    argumentNames(Fn);
    unsigned N = 0;
    for (BasicBlock &BB : Fn)
      Order[&BB] = N++;
    for (Instruction &I : instructions(Fn)) {
      if (ignored(I) && !isa<AllocaInst>(I))
        continue;
      if (foldable(I)) {
        Inline.insert(&I);
        continue;
      }
      if (!I.getType()->isVoidTy()) {
        std::string Hint = isa<AllocaInst>(I) ? "frame" : "value" + std::to_string(Names.size() - Fn.arg_size());
        bool Producer = false;
        if (auto *Call = dyn_cast<CallBase>(&I))
          if (auto *Callee = Call->getCalledFunction(); Callee && !Callee->isIntrinsic()) {
            Hint = fnName(*Callee) + "_result";
            Producer = true;
          }
        declareName(&I, Hint);
        if (Producer)
          NameEvidence[&I] = "inferred";
      }
    }

    DominatorTree Dom(Fn);
    PostDominatorTree PostDom(Fn);
    LoopInfo Loopy(Dom);
    DT = &Dom;
    PDT = &PostDom;
    LI = &Loopy;
    Out.clear();
    Emitted.clear();
    Pending.clear();
    Loops.clear();
    Depth = 1;
    emit(&Fn.getEntryBlock(), nullptr);
    while (!Pending.empty()) {
      BasicBlock *B = Pending.back();
      Pending.pop_back();
      if (!Emitted.count(B))
        emit(B, nullptr);
    }

    // Drop pure assignments nothing reads.
    std::map<Instruction *, unsigned> Uses;
    std::map<Instruction *, std::vector<Stmt *>> ByDef;
    for (Stmt &S : Out) {
      for (Instruction *R : S.Refs)
        ++Uses[R];
      if (S.Def)
        ByDef[S.Def].push_back(&S);
    }
    std::vector<Stmt *> Work;
    std::set<Stmt *> Dead;
    for (auto &[Def, Ss] : ByDef)
      if (!Uses[Def])
        Work.insert(Work.end(), Ss.begin(), Ss.end());
    while (!Work.empty()) {
      Stmt *S = Work.back();
      Work.pop_back();
      if (!Dead.insert(S).second)
        continue;
      for (Instruction *R : S->Refs)
        if (--Uses[R] == 0)
          for (Stmt *X : ByDef[R])
            Work.push_back(X);
    }

    std::string Body;
        // `v = RHS; return v;` with v used nowhere else becomes `return RHS;`.
    // So does a dead `v = RHS` just before an identical `return RHS` (an arm
    // that returned directly while its assignment survived).
    for (size_t SI = 0; SI + 1 < Out.size(); ++SI) {
      Stmt &A = Out[SI], &B = Out[SI + 1];
      if (Dead.count(&A) || Dead.count(&B) || !A.Assigns || A.Rhs.empty())
        continue;
      if (B.Text != "return " + name(A.Assigns) + ";" && B.Text != "return " + A.Rhs + ";")
        continue;
      if (Uses[A.Assigns] != 1 && B.Text != "return " + A.Rhs + ";")
        continue;
      if (B.Text != "return " + A.Rhs + ";")
        B.Text = "return " + A.Rhs + ";";
      // The value now appears only as inlined text: its variable is dead,
      // only what the right-hand side reads stays live.
      B.Refs.erase(std::remove(B.Refs.begin(), B.Refs.end(), A.Assigns), B.Refs.end());
      for (Instruction *R : A.Refs)
        B.Refs.push_back(R);
      B.Pcs.insert(A.Pcs.begin(), A.Pcs.end());
      B.LostFold |= A.LostFold;
      Dead.insert(&A);
    }
    // Recompute live uses after the merge.
    Uses.clear();
    for (Stmt &S : Out)
      if (!Dead.count(&S))
        for (Instruction *R : S.Refs)
          ++Uses[R];
    std::set<Instruction *> Assigned, Staged;
    for (Stmt &S : Out)
      if (!Dead.count(&S) && S.Assigns)
        (S.Staged ? Staged : Assigned).insert(S.Assigns);
    std::string Locals;
    for (Instruction &I : instructions(Fn)) {
      if (!Names.count(&I))
        continue;
      if (auto *A = dyn_cast<AllocaInst>(&I)) {
        auto L = T.Frames.find(A);
        std::string Ty = L != T.Frames.end() ? L->second.Name : "uint8_t";
        uint64_t Size = DL.getTypeAllocSize(A->getAllocatedType());
        Locals += "    " + Ty + " " + name(A) +
                  (L == T.Frames.end() ? "[" + std::to_string(Size) + "]" : "") +
                  " __attribute__((aligned(16)));\n";
        continue;
      }
      if (Assigned.count(&I) || Uses[&I] > 0) {
        Locals += "    " + ctyOf(&I) + " " + name(&I) + ";\n";
        ++TempCount;
      }
      if (Staged.count(&I))
        Locals += "    " + ctyOf(&I) + " " + name(&I) + "_next;\n";
    }
    // A `return;` closing a void function returns to nothing: drop it.
    if (F && F->getReturnType()->isVoidTy())
      for (size_t SI = Out.size(); SI-- > 0;) {
        Stmt &S = Out[SI];
        if (S.Label)
          continue;
        if (S.Text == "return;" && S.Depth == 1)
          Dead.insert(&S);
        break;
      }
    std::string Prefix = "\n" + signature(Fn) + "\n{\n" + Locals + (Locals.empty() ? "" : "\n");
    uint64_t Line = std::count(Prefix.begin(), Prefix.end(), '\n') + 1;
    Body = std::move(Prefix);
    auto Entry = entryOf(Fn, M.getContext());
    for (Stmt &S : Out) {
      if (Dead.count(&S))
        continue;
      std::string Text;
      if (S.Label) {
        if (!Targeted.count(S.Label))
          continue;
        Text = label(S.Label) + ":;";
      } else {
        Text = S.Text;
      }
      if (Packaging) {
        if (StatementCount)
          StatementJson += ",";
        std::string Id = "function_" + hex(*Entry).substr(2) + "/s" + std::to_string(StatementCount++);
        StatementJson += "{\"id\":" + jsonStr(Id) + ",\"line\":" + std::to_string(Line) +
                         ",\"text\":" + jsonStr(Text) + ",\"addresses\":[";
        bool First = true;
        for (uint64_t Pc : S.Pcs) {
          StatementJson += (First ? "" : ",") + std::to_string(Pc);
          First = false;
        }
        StatementJson += "],\"provenance\":" +
                         jsonStr(S.Pcs.empty() ? "unknown" : S.LostFold ? "inferred" : "exact") + "}";
        MappedCount += !S.Pcs.empty();
        MaxDepth = std::max<uint64_t>(MaxDepth, S.Depth);
      }
      Body += std::string(4 * (S.Label ? S.Depth - 1 : S.Depth), ' ') + Text + "\n";
      ++Line;
    }
    StatementJson += "]";
    Body += "}\n";
    return Body;
  }

  // C's `main` over the guest's: argc, argv and envp go to the registers
  // that carry the first three arguments.
  std::string entryWrapper(Function &Main) {
    static const char *const C[] = {"argc", "argv", "envp"};
    std::string Args;
    for (Argument &A : Main.args()) {
      std::string V = "0";
      for (size_t K = 0; K < ConvArgs.size() && K < 3; ++K)
        if (A.getName() == ConvArgs[K])
          // `argv` (a pointer) converts once, in `conv` below.
          V = K == 0 ? "(uint64_t)(int64_t)argc" : std::string(C[K]);
      Names.clear();
      Args += std::string(Args.empty() ? "" : ", ") + conv(V, "uint64_t", ctyOf(&A));
    }
    std::string Call = "guest_main(" + Args + ")";
    Type *R = Main.getReturnType();
    return "\n/* The program's entry: the guest's main, with C's arguments. */\nint main(int "
           "argc, char **argv, char **envp)\n{\n" +
           (R->isIntegerTy() ? "    return (int)" + Call + ";\n"
                             : "    " + Call + ";\n    return 0;\n") +
           "}\n";
  }


  void helperDefs() {
    std::string Out;
    for (auto &[H, Emitted] : Helpers) {
      if (Emitted)
        continue;
      Emitted = true;
      if (H == "sext") {
        std::string Def = "static inline int64_t biara_sext(uint64_t x, unsigned n) { return (int64_t)(x << "
                          "(64 - n)) >> (64 - n); }\n";
        Out += Def;
        SupportDefs["biara_sext"] = Def;
        continue;
      }
      std::string Name = H, Agg;
      if (auto Bar = H.find('|'); Bar != std::string::npos) {
        Name = H.substr(0, Bar);
        Agg = H.substr(Bar + 1);
      }
      std::string Op = Name;
      unsigned Bits = 0;
      while (!Op.empty() && isdigit((unsigned char)Op.back())) {
        Op.pop_back();
      }
      Bits = std::stoi(Name.substr(Op.size()));
      if (Op.rfind("biara_", 0) == 0)
        Op = Op.substr(6);
      std::string U = uintTy(Bits), S = intTy(Bits), W = std::to_string(Bits);
      std::string Fn = "static inline ";
      if (Op == "div" || Op == "sdiv") {
        // x86 division of the RDX:RAX pair (or the low half below 64 bits),
        // with QEMU's defined semantics; the caller guards a zero divisor
        // and a kept quotient fits, so this is plain C division.
        bool Sg = Op == "sdiv";
        std::string T = Sg ? S : U;
        std::string I128 = Sg ? "biara_i128" : "biara_u128";
        std::string Pair =
            Bits == 64 ? "(" + I128 + ")(((" + I128 + ")(hi) << 64) | (" + I128 + ")(lo))" : "";
        if (Bits != 64)
          Pair = "(" + T + ")(lo)";
        std::string Dd = Bits == 64 ? "(" + T + ")(d)" : "(" + T + ")(d)";
        Fn += Agg + " " + Name + "(uint64_t lo, uint64_t hi, uint64_t d) { " + Agg +
              " r; r.f0 = (" + U + ")(" + Pair + " / (" + T + ")d); r.f1 = (" + U + ")(" + Pair +
              " % (" + T + ")d); return r; }";
      } else if (Op == "rotl" || Op == "rotr") {
        bool L = Op == "rotl";
        Fn += U + " " + Name + "(" + U + " x, " + U + " n) { n %= " + W + "; return n ? (" + U +
              ")((x " + (L ? "<<" : ">>") + " n) | (x " + (L ? ">>" : "<<") + " (" + W +
              " - n))) : x; }";
      } else if (Op == "fshl" || Op == "fshr") {
        bool L = Op == "fshl";
        Fn += U + " " + Name + "(" + U + " a, " + U + " b, " + U + " n) { n %= " + W +
              "; return n ? (" + U + ")(" +
              (L ? "(a << n) | (b >> (" + W + " - n))" : "(b >> n) | (a << (" + W + " - n))") +
              ") : " + (L ? "a" : "b") + "; }";
      } else if (Op == "clz" || Op == "ctz") {
        std::string B = Op == "clz" ? "__builtin_clzll((uint64_t)x) - " + std::to_string(64 - Bits)
                                    : "__builtin_ctzll((uint64_t)x)";
        if (Bits == 128)
          B = Op == "clz" ? "(uint64_t)(x >> 64) ? __builtin_clzll((uint64_t)(x >> 64)) : 64 + "
                            "__builtin_clzll((uint64_t)x)"
                          : "(uint64_t)x ? __builtin_ctzll((uint64_t)x) : 64 + "
                            "__builtin_ctzll((uint64_t)(x >> 64))";
        Fn += U + " " + Name + "(" + U + " x) { return x ? (" + U + ")(" + B + ") : " + W + "; }";
      } else if (Op == "popcount") {
        Fn += U + " " + Name + "(" + U + " x) { return (" + U + ")" +
              (Bits == 128 ? "(__builtin_popcountll((uint64_t)x) + "
                             "__builtin_popcountll((uint64_t)(x >> 64)))"
                           : "__builtin_popcountll((uint64_t)x)") +
              "; }";
      } else if (Op == "bswap") {
        std::string B = Bits == 16   ? "__builtin_bswap16(x)"
                        : Bits == 32 ? "__builtin_bswap32(x)"
                        : Bits == 64 ? "__builtin_bswap64(x)"
                        : Bits == 128
                            ? "((biara_u128)__builtin_bswap64((uint64_t)x) << 64) | "
                              "__builtin_bswap64((uint64_t)(x >> 64))"
                            : "x";
        Fn += U + " " + Name + "(" + U + " x) { return " + B + "; }";
      } else if (Op == "bitreverse") {
        Fn += U + " " + Name + "(" + U + " x) { " + U + " r = 0; for (unsigned i = 0; i < " + W +
              "; ++i) r |= (" + U + ")((x >> i) & 1) << (" + W + " - 1 - i); return r; }";
      } else if (Op == "abs") {
        Fn += U + " " + Name + "(" + U + " x) { return (" + S + ")x < 0 ? (" + U + ")-x : x; }";
      } else if (Op == "uadd_sat") {
        Fn += U + " " + Name + "(" + U + " a, " + U + " b) { " + U + " s = a + b; return s < a ? (" +
              U + ")~(" + U + ")0 : s; }";
      } else if (Op == "umax" || Op == "umin") {
        Fn += U + " " + Name + "(" + U + " a, " + U + " b) { return a " +
              (Op == "umax" ? ">" : "<") + " b ? a : b; }";
      } else if (Op == "smax" || Op == "smin") {
        Fn += U + " " + Name + "(" + U + " a, " + U + " b) { return (" + S + ")a " +
              (Op == "smax" ? ">" : "<") + " (" + S + ")b ? a : b; }";
      } else if (Op.size() > 4 && Op.substr(Op.size() - 4) == "_ovf") {
        std::string Kind = Op.substr(1, 3); // add, sub, mul
        bool Signed = Op[0] == 's';
        std::string T = Signed ? S : U;
        Fn += Agg + " " + Name + "(" + U + " a, " + U + " b) { " + Agg + " r; " + T + " v; r.f1 = " +
              "__builtin_" + Kind + "_overflow((" + T + ")a, (" + T + ")b, &v); r.f0 = (" + U +
              ")v; return r; }";
      } else {
        continue;
      }
      Out += Fn + "\n";
      SupportDefs[Name] = Fn + "\n";
    }
    Prelude += Out;
  }

  bool emitPending(COutput &Out) {
    helperDefs();
    if (!Out.write(Prelude))
      return false;
    Prelude.clear();
    for (auto &[N, Declared] : DataUsed)
      if (!Declared) {
        if (!Out.write("extern uint8_t *" + ident(N) + ";\n"))
          return false;
        Declared = true;
      }
    for (auto &[A, Declared] : StrsUsed)
      if (!Declared) {
        if (!Out.write("static const char str_" + hex(A).substr(2) + "[] = \"" +
                       Strings[A] + "\";\n"))
          return false;
        Declared = true;
      }
    if (AtolUsed && !AtolDeclared) {
      if (!Out.write(std::string(Posix ? "int64_t" : "uint64_t") + " atol(const char *);\n"))
        return false;
      AtolDeclared = true;
    }
    return true;
  }

  struct CText {
    uint64_t Tokens = 0, Casts = 0, Gotos = 0;
    std::set<StringRef> Identifiers;
  };
  CText scanText(StringRef Text) const {
    CText Result;
    bool Open = false, Type = false, StructName = false, Body = false;
    for (size_t I = 0; I < Text.size();) {
      if (isspace((unsigned char)Text[I])) { ++I; continue; }
      if (Text.substr(I).starts_with("/*")) {
        size_t End = Text.find("*/", I + 2);
        I = End == StringRef::npos ? Text.size() : End + 2;
        continue;
      }
      if (Text.substr(I).starts_with("//")) {
        size_t End = Text.find('\n', I + 2);
        I = End == StringRef::npos ? Text.size() : End;
        continue;
      }
      size_t Start = I++;
      bool Identifier = isalpha((unsigned char)Text[Start]) || Text[Start] == '_';
      if (Identifier || isdigit((unsigned char)Text[Start])) {
        while (I < Text.size() && (isalnum((unsigned char)Text[I]) || Text[I] == '_'))
          ++I;
      } else if (Text[Start] == '"' || Text[Start] == '\'') {
        char Quote = Text[Start];
        while (I < Text.size()) {
          char C = Text[I++];
          if (C == '\\' && I < Text.size()) ++I;
          else if (C == Quote) break;
        }
      }
      StringRef Token = Text.slice(Start, I);
      ++Result.Tokens;
      if (Identifier) Result.Identifiers.insert(Token);
      Result.Gotos += Token == "goto";
      if (Token == "{") Body = true;
      if (Token == "(") { Open = true; Type = false; StructName = false; }
      else if (Token == ")") {
        Result.Casts += Open && Type && Body;
        Open = false;
      } else if (Open) {
        if (Token == "const" || Token == "volatile" || Token == "*") {}
        else if (Token == "struct") { Type = true; StructName = true; }
        else if (StructName && Identifier) { StructName = false; }
        else if (Token == "bool" || Token == "char" || Token == "void" || Token == "float" ||
                 Token == "double" || Token == "int8_t" || Token == "int16_t" ||
                 Token == "int32_t" || Token == "int64_t" || Token == "uint8_t" ||
                 Token == "uint16_t" || Token == "uint32_t" || Token == "uint64_t" ||
                 Token == "uintptr_t" || Token == "biara_u128" || Token == "biara_i128" ||
                 CallbackArguments.count(Token))
          Type = true;
        else Open = false;
      }
    }
    return Result;
  }

  std::string emitLayout(const Layout &L) {
    std::string S = L.Name + " {\n";
    int64_t At = 0;
    for (const Field &Fd : L.Fields) {
      if (Fd.Off > At)
        S += "    uint8_t _pad_" + hex(At).substr(2) + "[" + std::to_string(Fd.Off - At) + "];\n";
      S += "    " + T.fieldTy(Fd) + " " + Fd.Name + ";\n";
      At = Fd.Off + Fd.Bytes;
    }
    if ((int64_t)L.Size > At)
      S += "    uint8_t _pad_" + hex(At).substr(2) + "[" + std::to_string(L.Size - At) + "];\n";
    return S + "} __attribute__((packed));\n";
  }

  static bool registerName(StringRef Name) {
    for (StringRef Reg : {"rax","rbx","rcx","rdx","rdi","rsi","rsp","rbp","rip",
                         "r8","r9","r10","r11","r12","r13","r14","r15"})
      if (Name == Reg) return true;
    if (Name.consume_front("x")) {
      unsigned N;
      return !Name.getAsInteger(10,N) && N < 31;
    }
    return false;
  }

  int packages(BiaraWrite Write, void *Ctx) {
    Packaging = true;
    SupportDefs["biara_u128"]="typedef unsigned __int128 biara_u128;\n";
    SupportDefs["biara_i128"]="typedef __int128 biara_i128;\n";
    for (Function &Fn : M)
      if (!Fn.isIntrinsic()) GlobalNames.insert(fnName(Fn));
    GlobalNames.insert("biara_cpu");
    bool Selected = false;
    for (Function &Fn : M)
      Selected |= Fn.getMetadata("biara.present") != nullptr;
    std::vector<Function *> Functions;
    for (Function &Fn : M)
      if (!Fn.isDeclaration() && !Fn.isIntrinsic() && entryOf(Fn,M.getContext()) &&
          (!Selected || presentOf(Fn,M.getContext())))
        Functions.push_back(&Fn);
    std::stable_sort(Functions.begin(), Functions.end(), [&](Function *A, Function *B) {
      if (Selected)
        return *presentOf(*A,M.getContext()) < *presentOf(*B,M.getContext());
      return *entryOf(*A,M.getContext()) < *entryOf(*B,M.getContext());
    });
    for (Function *Fn : Functions) {
      size_t Before = Unsupported;
      std::string Body = function(*Fn);
      std::string Sig = signature(*Fn);
      CText Text = scanText(Body);
      // Definitions are cached, but dependency selection starts fresh per
      // function. Follow referenced layouts recursively, never module-wide.
      helperDefs();
      Prelude.clear();
      std::map<std::string,std::pair<std::string,std::string>> Dependencies;
      auto add = [&](StringRef Kind, StringRef Name, std::string Def) {
        std::string Id = Kind.str() + ":" + Name.str();
        Dependencies.try_emplace(Id,std::make_pair(Kind.str(),std::move(Def)));
      };
      std::set<std::string> Needed;
      for (StringRef Id : Text.Identifiers) Needed.insert(Id.str());
      std::set<std::string> Expanded;
      while (!Needed.empty()) {
        std::string Id = *Needed.begin();
        Needed.erase(Needed.begin());
        if (!Expanded.insert(Id).second) continue;
        std::string Def;
        auto Support = SupportDefs.find(Id);
        if (Support != SupportDefs.end()) {
          Def = Support->second;
          bool Type = StringRef(Id).starts_with("biara_tuple") ||
                      StringRef(Id).starts_with("biara_callback_") ||
                      Id=="biara_u128" || Id=="biara_i128" || StringRef(Id).starts_with("biara_v");
          add(Type ? "type" : "helper",Id,Def);
        } else {
          for (auto &[C,L] : T.Layouts)
            if (!L.Scalar && StringRef(L.Name).drop_front(7) == Id) { Def=emitLayout(L); break; }
          if (Def.empty())
            for (auto &[R,L] : T.Frames)
              if (StringRef(L.Name).drop_front(7) == Id) { Def=emitLayout(L); break; }
          if (!Def.empty()) add("type",Id,Def);
        }
        if (!Def.empty())
          for (StringRef Dependency : scanText(Def).Identifiers)
            if (!Expanded.count(Dependency.str())) Needed.insert(Dependency.str());
      }
      for (auto &[Addr,Literal] : Strings) {
        std::string Id = "str_" + hex(Addr).substr(2);
        if (Text.Identifiers.count(Id))
          add("string",Id,"static const char " + Id + "[] = \"" + Literal + "\";\n");
      }
      for (auto &[Name,Declared] : DataUsed)
        if (Text.Identifiers.count(ident(Name)))
          add("global",Name,"extern uint8_t *" + ident(Name) + ";\n");
      if (Text.Identifiers.count("biara_cpu") || Text.Identifiers.count("BIARA_ENV")) {
        auto G=M.getGlobalVariable("biara_cpu");
        if (G && T.Frames.count(G))
          add("type","cpu_state",emitLayout(T.Frames.at(G)));
        add("global","biara_cpu","extern struct cpu_state biara_cpu;\n#define BIARA_ENV ((uint8_t *)&biara_cpu + " + std::to_string(Margin) + ")\n");
      }
      for (Function &Callee : M)
        if (&Callee != Fn && !Callee.isIntrinsic() && Text.Identifiers.count(fnName(Callee)) &&
            !SupportDefs.count(fnName(Callee)))
          add(Callee.isDeclaration() ? "import" : "function",fnName(Callee),signature(Callee,false)+";\n");
      if (Text.Identifiers.count("atol"))
        add("import","atol",std::string(Posix ? "int64_t" : "uint64_t") + " atol(const char *);\n");
      for (StringRef Integer : {"uint8_t","uint16_t","uint32_t","uint64_t","int8_t",
                               "int16_t","int32_t","int64_t","uintptr_t"})
        if (Expanded.count(Integer.str())) {
          add("include","stdint","#include <stdint.h>\n");
          break;
        }
      if (Expanded.count("bool") || Expanded.count("true") || Expanded.count("false"))
        add("include","stdbool","#include <stdbool.h>\n");
      std::string Deps="[";
      bool First=true;
      for (auto &[Id,D] : Dependencies) {
        Deps += (First ? "" : ",") + std::string("{\"id\":") + jsonStr(Id) +
                ",\"kind\":" + jsonStr(D.first) + ",\"text\":" + jsonStr(D.second) + "}";
        First=false;
      }
      Deps+="]";
      std::string NameJson="[";
      First=true;
      auto addName = [&](const Value *V) {
        auto N=Names.find(V);
        if (N==Names.end() || !Text.Identifiers.count(N->second)) return;
        NameJson += (First ? "" : ",") + std::string("{\"name\":") + jsonStr(N->second) +
                    ",\"original\":" + jsonStr(Originals[V]) + ",\"evidence\":" + jsonStr(NameEvidence[V]) + "}";
        First=false;
      };
      for (Argument &A : Fn->args()) addName(&A);
      for (Instruction &I : instructions(*Fn)) addName(&I);
      for (auto &[R,L] : T.Frames) {
        auto *A=dyn_cast<AllocaInst>(R);
        if (!A || A->getFunction()!=Fn) continue;
        for (auto &Field : L.Fields) if (Field.Debug && Text.Identifiers.count(Field.Name)) {
          NameJson += (First ? "" : ",") + std::string("{\"name\":") + jsonStr(Field.Name) +
                      ",\"original\":" + jsonStr(biara_layouts::Types::slotName(L,Field.Off)) + ",\"evidence\":\"debug\"}";
          First=false;
        }
      }
      NameJson+="]";
      uint64_t Regs=0;
      for (StringRef Id : Text.Identifiers) Regs+=registerName(Id);
      std::string Metrics="{\"tokens\":" + std::to_string(Text.Tokens) +
        ",\"temporaries\":" + std::to_string(TempCount) + ",\"register_names\":" + std::to_string(Regs) +
        ",\"casts\":" + std::to_string(Text.Casts) + ",\"gotos\":" + std::to_string(Text.Gotos) +
        ",\"max_nesting\":" + std::to_string(MaxDepth) + ",\"statements\":" + std::to_string(StatementCount) +
        ",\"mapped_statements\":" + std::to_string(MappedCount) + ",\"unsupported\":" + std::to_string(Unsupported-Before) + "}";
      std::string Json="{\"address\":" + std::to_string(*entryOf(*Fn,M.getContext())) +
        ",\"name\":" + jsonStr(fnName(*Fn)) + ",\"signature\":" + jsonStr(Sig) +
        ",\"body\":" + jsonStr(Body) + ",\"statements\":" + StatementJson +
        ",\"dependencies\":" + Deps + ",\"names\":" + NameJson + ",\"metrics\":" + Metrics + "}";
      int Status=Write(Ctx,Json.data(),Json.size());
      if (Status) return Status;
    }
    return 0;
  }

  int run(StringRef Banner, BiaraWrite Write, void *Ctx) {
    COutput Out(Write, Ctx);
    for (Function &Fn : M)
      if (!Fn.isIntrinsic())
        GlobalNames.insert(fnName(Fn));
    GlobalNames.insert("biara_cpu");
    if (!Out.write("/*\n * ") || !Out.write(Banner) ||
        !Out.write("\n */\n\n#include <stdbool.h>\n#include <stdint.h>\n\n"
                   "typedef unsigned __int128 biara_u128;\n"
                   "typedef __int128 biara_i128;\n\n"))
      return Out.status();

    // Layouts precede all prototypes and bodies; emit one at a time.
    std::set<std::string> Declared, Defined;
    for (auto &[C, L] : T.Layouts)
      if (!L.Scalar)
        if (Declared.insert(L.Name).second && !Out.write(L.Name + ";\n"))
          return Out.status();
    for (auto &[C, L] : T.Layouts)
      if (!L.Scalar)
        if (Defined.insert(L.Name).second && !Out.write("\n" + emitLayout(L)))
          return Out.status();
    for (auto &[R, L] : T.Frames)
      if (!Out.write("\n" + emitLayout(L)))
        return Out.status();
    if (GlobalVariable *G = M.getGlobalVariable("biara_cpu"); G && !G->use_empty())
      if (!Out.write("\n/* CPU state that registers do not cover (vector and FPU registers,\n * what "
                     "helpers read through env). */\nextern struct cpu_state biara_cpu;\n#define BIARA_ENV "
                     "((uint8_t *)&biara_cpu + " + std::to_string(Margin) + ")\n"))
        return Out.status();
    if (!Out.write("\n"))
      return Out.status();

    // Forward declarations allow bodies to stream in module order. Division
    // helpers are known from ABI form; other dependencies emerge while printing
    // each body and are emitted immediately before that body.
    for (Function &Fn : M) {
      if (Fn.isIntrinsic() || (Fn.isDeclaration() && Fn.use_empty()))
        continue;
      Names.clear();
      Taken.clear();
      NextSuffix.clear();
      for (Argument &A : Fn.args())
        declareName(&A, A.getName());
      if (Fn.isDeclaration() &&
          (Fn.getName().starts_with("biara_div") || Fn.getName().starts_with("biara_sdiv"))) {
        Helpers.try_emplace(Fn.getName().str() + "|" +
                           aggregate(cast<StructType>(Fn.getReturnType())), false);
        if (!emitPending(Out))
          return Out.status();
        continue;
      }
      std::string Sig = signature(Fn);
      if (!emitPending(Out) || !Out.write(Sig) || !Out.write(";\n"))
        return Out.status();
    }
    for (Function &Fn : M)
      if (!Fn.isDeclaration() && !Fn.isIntrinsic()) {
        std::string Body = function(Fn);
        if (!emitPending(Out) || !Out.write(Body))
          return Out.status();
      }
    if (Function *Main = M.getFunction("main"); Main && !Main->isDeclaration())
      if (!Out.write(entryWrapper(*Main)))
        return Out.status();
    return Out.finish();
  }
};

} // namespace

// The C source of module `M` (in ABI form) from the cached layout analysis,
// streamed to `out` in bounded chunks; `*Unsupported` counts constructs
// printed as placeholders. Returns 0 on success, the first nonzero sink
// status otherwise. Dependencies precede their first function use; no
// whole-module source buffer is built. Runs of 3+ newlines collapse to two
// across output boundaries. `L` must have been built for `M` (see
// cpp/layouts.h); the renderer never re-runs analysis, so facts and output
// share one convention.
extern "C" int biara_emit_c_cached(BiaraLayouts *L, LLVMModuleRef MRef, const BiaraCField *Cpu,
                                   size_t NCpu, const char *const *ConvArgs, size_t NConv,
                                   uint64_t Margin, const char *Banner, size_t *Unsupported,
                                   const BiaraData *Data, size_t NData, const BiaraStr *Strs,
                                   size_t NStrs, const BiaraProto *Prs, size_t NPrs,
                                   const BiaraStr *Sms, size_t NSms, uint32_t Mode,
                                   BiaraWrite out, void *ctx) {
  (void)Cpu;
  (void)NCpu;
  Module &M = *unwrap(MRef);
  biara_layouts::Types &T = biara_layouts::biara_layouts_types(L);
  *Unsupported = 0;
  Emitter E(M, T, *Unsupported, std::vector<std::string>(ConvArgs, ConvArgs + NConv), Margin,
            std::vector<BiaraData>(Data, Data + NData),
            std::vector<BiaraStr>(Strs, Strs + NStrs),
            std::vector<BiaraProto>(Prs, Prs + NPrs),
            std::vector<BiaraStr>(Sms, Sms + NSms));
  return Mode == 1 ? E.packages(out, ctx) : E.run(Banner, out, ctx);
}
