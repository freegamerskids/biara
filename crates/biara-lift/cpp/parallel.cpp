// Function-local optimization in bounded, isolated LLVM units. The caller
// overlaps extraction/serialization and ordered merging with W-1 computing
// threads. Original LLVM contexts and target machines never enter a worker.
// Bodies move between the module and job units; failures restore every body
// not yet merged. Only identified struct types need the full IR linker.
#include "llvm-c/Core.h"
#include "llvm-c/Error.h"
#include "llvm-c/Transforms/PassBuilder.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Linker/Linker.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CBindingWrapping.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <future>
#include <exception>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace llvm;
namespace {

struct PassOptions {
  LLVMPassBuilderOptionsRef Value = LLVMCreatePassBuilderOptions();
  ~PassOptions() { LLVMDisposePassBuilderOptions(Value); }
};

void run(Module &M, TargetMachine &TM, const char *Pipeline) {
  PassOptions Options;
  if (LLVMErrorRef E = LLVMRunPasses(wrap(&M), Pipeline,
                                   reinterpret_cast<LLVMTargetMachineRef>(&TM),
                                   Options.Value)) {
    char *Message = LLVMGetErrorMessage(E);
    std::string Text(Message);
    LLVMDisposeErrorMessage(Message);
    throw std::runtime_error(Text);
  }
}

void verify(Module &M) {
  std::string Text;
  raw_string_ostream Out(Text);
  if (verifyModule(M, &Out)) throw std::runtime_error(Text);
}

std::string serialize(Module &M) {
  std::string Bytes;
  raw_string_ostream Out(Bytes);
  WriteBitcodeToFile(M, Out);
  return Bytes;
}

// Lazily copy only globals referenced by a function, including initializer
// evidence used by constant folding. Other function bodies are never copied.
class Dependencies : public ValueMaterializer {
  Module &Unit;
  ValueToValueMapTy &Map;
public:
  Dependencies(Module &Unit, ValueToValueMapTy &Map) : Unit(Unit), Map(Map) {}
  Value *materialize(Value *V) override {
    auto *G = dyn_cast<GlobalValue>(V);
    if (!G) return nullptr;
    if (auto Found = Map.find(G); Found != Map.end()) return Found->second;
    GlobalValue *Copy;
    if (auto *Ty = dyn_cast<FunctionType>(G->getValueType())) {
      auto *F = Function::Create(Ty, GlobalValue::ExternalLinkage,
                                G->getAddressSpace(), G->getName(), &Unit);
      if (auto *Original = dyn_cast<Function>(G)) {
        F->copyAttributesFrom(Original);
        F->setPersonalityFn(nullptr);
        F->setPrefixData(nullptr);
        F->setPrologueData(nullptr);
      }
      Copy = F;
    } else {
      auto *Original = dyn_cast<GlobalVariable>(G);
      auto *Variable = new GlobalVariable(
          Unit, G->getValueType(), Original && Original->isConstant(),
          GlobalValue::ExternalLinkage, nullptr, G->getName(), nullptr,
          Original ? Original->getThreadLocalMode() : GlobalVariable::NotThreadLocal,
          G->getAddressSpace(), Original && Original->isExternallyInitialized());
      if (Original) Variable->copyAttributesFrom(Original);
      Copy = Variable;
    }
    Copy->setLinkage(GlobalValue::ExternalLinkage);
    Copy->setDSOLocal(false);
    Map[G] = Copy; // Before recursive initializers, including self references.
    if (auto *Original = dyn_cast<GlobalVariable>(G)) {
      auto *Variable = cast<GlobalVariable>(Copy);
      if (Original->hasInitializer())
        Variable->setInitializer(MapValue(Original->getInitializer(), Map,
                                         RF_None, nullptr, this));
      SmallVector<std::pair<unsigned, MDNode *>, 4> Metadata;
      Original->getAllMetadata(Metadata);
      for (auto &[Kind, Node] : Metadata)
        Variable->setMetadata(Kind, MapMetadata(Node, Map, RF_None, nullptr, this));
    }
    return Copy;
  }
};

// Move every block of From into To (an empty function of the same type) and
// rewrite references through Map: no instruction is copied or reallocated.
void moveBody(Function &From, Function &To, ValueToValueMapTy &Map,
              ValueMaterializer *Materializer) {
  auto Arg = To.arg_begin();
  for (Argument &A : From.args()) Map[&A] = &*Arg++;
  To.splice(To.end(), &From);
  SmallVector<std::pair<unsigned, MDNode *>, 4> Metadata;
  From.getAllMetadata(Metadata);
  From.clearMetadata();
  for (auto &[Kind, Node] : Metadata) To.setMetadata(Kind, Node);
  RemapFunction(To, Map, RF_IgnoreMissingLocals, nullptr, Materializer);
}

// Bodies leave M for the unit (M keeps the empty function objects, so calls
// from elsewhere stay valid) until `merge` or `restore` moves them back.
void extract(Module &M, ArrayRef<std::string> Names, Module &Unit) {
  Unit.setDataLayout(M.getDataLayout());
  Unit.setTargetTriple(M.getTargetTriple());
  Unit.setSourceFileName(M.getSourceFileName());
  ValueToValueMapTy Map;
  Dependencies Globals(Unit, Map);
  // Declare every root first so calls between roots resolve to the same body.
  for (const std::string &Name : Names)
    Globals.materialize(M.getFunction(Name));
  for (const std::string &Name : Names) {
    Function *F = M.getFunction(Name);
    auto *Copy = cast<Function>(Map[F]);
    auto NewArg = Copy->arg_begin();
    for (Argument &Arg : F->args()) (NewArg++)->setName(Arg.getName());
    moveBody(*F, *Copy, Map, &Globals);
    Copy->setLinkage(GlobalValue::ExternalLinkage);
    Copy->setDSOLocal(false);
  }
  // Module flags carry ABI/optimization requirements, not unrelated bodies.
  if (auto *Flags = M.getNamedMetadata("llvm.module.flags")) {
    auto *NewFlags = Unit.getOrInsertNamedMetadata("llvm.module.flags");
    for (MDNode *Flag : Flags->operands())
      NewFlags->addOperand(MapMetadata(Flag, Map, RF_None, nullptr, &Globals));
  }
}

// Unit globals by name in M; every unit global stands for one of M's.
void mapByName(Module &M, Module &Unit, ValueToValueMapTy &Map) {
  for (GlobalValue &G : Unit.global_values()) {
    GlobalValue *Original = M.getNamedValue(G.getName());
    if (!Original) throw std::runtime_error("extracted global has no original: " + G.getName().str());
    Map[&G] = Original;
  }
}

struct MachineConfig {
  const Target &Backend;
  Triple TargetTriple;
  std::string CPU, Features;
  TargetOptions Options;
  Reloc::Model Relocation;
  CodeModel::Model Model;
  CodeGenOptLevel Level;
  explicit MachineConfig(TargetMachine &TM)
      : Backend(TM.getTarget()), TargetTriple(TM.getTargetTriple()),
        CPU(TM.getTargetCPU()), Features(TM.getTargetFeatureString()),
        Options(TM.Options), Relocation(TM.getRelocationModel()),
        Model(TM.getCodeModel()), Level(TM.getOptLevel()) {}
  std::unique_ptr<TargetMachine> create() const {
    std::unique_ptr<TargetMachine> Machine(Backend.createTargetMachine(
        TargetTriple, CPU, Features, Options, Relocation, Model, Level));
    if (!Machine) throw std::runtime_error("cannot create worker target machine");
    return Machine;
  }
};

struct Job {
  ArrayRef<std::string> Names;
  // The original bodies until merged; returned to M if the round fails.
  std::unique_ptr<Module> Original;
  std::string Input, Output, Error;
  bool Failed = false;
  // Declared last: destruction joins the computation before freeing its input.
  std::future<void> Work;
};

// Return a job's unmerged original bodies to M.
void restore(Module &M, Job &J) {
  ValueToValueMapTy Map;
  mapByName(M, *J.Original, Map);
  for (const std::string &Name : J.Names)
    if (Function *To = M.getFunction(Name); To && To->empty())
      moveBody(*J.Original->getFunction(Name), *To, Map, nullptr);
}

void compute(Job &J, const MachineConfig &Config, const char *Pipeline) noexcept {
  try {
    // A target machine's DataLayout has context-specific caches. Both are
    // scoped to this job and destroyed before the next job can reuse memory.
    LLVMContext Context;
    auto Machine = Config.create();
    auto Parsed = parseBitcodeFile(MemoryBufferRef(J.Input, J.Names.front()), Context);
    if (!Parsed) throw std::runtime_error(toString(Parsed.takeError()));
    auto Unit = std::move(*Parsed);
    verify(*Unit);
    run(*Unit, *Machine, Pipeline);
    verify(*Unit);
    J.Output = serialize(*Unit);
  } catch (const std::exception &E) {
    J.Failed = true;
    try { J.Error = E.what(); } catch (...) {}
  } catch (...) {
    J.Failed = true;
  }
}


// Linker diagnostics must return to Rust, not the default fatal error handler.
struct Diagnostics {
  LLVMContext &Context;
  std::unique_ptr<DiagnosticHandler> Previous;
  std::string Text;
  static void capture(const DiagnosticInfo *Info, void *Opaque) {
    auto &Self = *static_cast<Diagnostics *>(Opaque);
    raw_string_ostream Out(Self.Text);
    DiagnosticPrinterRawOStream Printer(Out);
    Info->print(Printer);
    Out << '\n';
  }
  explicit Diagnostics(LLVMContext &C) : Context(C) {
    auto Handler = std::make_unique<DiagnosticHandler>(this);
    Handler->DiagHandlerCallback = capture;
    Previous = C.getDiagnosticHandler();
    C.setDiagnosticHandler(std::move(Handler), true);
  }
  ~Diagnostics() { Context.setDiagnosticHandler(std::move(Previous)); }
};

struct RestoreSymbols {
  struct State {
    std::string Name;
    GlobalValue::LinkageTypes Linkage;
    bool DSOLocal;
  };
  Module &M;
  std::vector<State> States;
  explicit RestoreSymbols(Module &M) : M(M) {}
  void add(GlobalValue &G) {
    States.push_back({G.getName().str(), G.getLinkage(), G.isDSOLocal()});
    // External declarations must resolve to original internal symbols too.
    G.setLinkage(GlobalValue::ExternalLinkage);
  }
  ~RestoreSymbols() {
    for (auto &S : States)
      if (auto *G = M.getNamedValue(S.Name)) {
        G->setLinkage(S.Linkage);
        G->setDSOLocal(S.DSOLocal);
      }
  }
};

// The IR linker rescans every type and metadata node of the destination on
// each link: merging all jobs that way is quadratic in the module size.
void link(Module &M, Job &J, std::unique_ptr<Module> Unit) {
  SmallVector<std::string, 32> Previous;
  for (const std::string &Name : J.Names) {
    Function *Original = M.getFunction(Name);
    if (!Original) throw std::runtime_error("original function disappeared: " + Name);
    auto Position = Original->getIterator();
    Previous.push_back(Position == M.begin() ? "" : std::prev(Position)->getName().str());
  }
  RestoreSymbols Restore(M);
  for (GlobalValue &G : Unit->global_values())
    if (auto *Existing = M.getNamedValue(G.getName())) Restore.add(*Existing);
  for (GlobalVariable &G : Unit->globals())
    if (M.getNamedValue(G.getName())) {
      // Initializers were optimization evidence; retain the original objects.
      G.setInitializer(nullptr);
      G.setLinkage(GlobalValue::ExternalLinkage);
    }
  for (const std::string &Name : J.Names) M.getFunction(Name)->deleteBody();
  Diagnostics Errors(M.getContext());
  if (Linker::linkModules(M, std::move(Unit), Linker::OverrideFromSrc))
    throw std::runtime_error(Errors.Text.empty() ? "cannot merge optimized functions"
                                               : Errors.Text);
  for (size_t I = 0; I < J.Names.size(); ++I) {
    auto *Root = M.getFunction(J.Names[I]);
    if (!Root || Root->isDeclaration())
      throw std::runtime_error("optimized body disappeared: " + J.Names[I]);
    auto Where = Previous[I].empty() ? M.begin()
                                    : std::next(M.getFunction(Previous[I])->getIterator());
    if (Where != Root->getIterator())
      M.getFunctionList().splice(Where, M.getFunctionList(), Root->getIterator());
  }
}

// Move each optimized body into its original (now empty) function object,
// mapping only the job's own globals, so a merge costs the job's size. Units
// with identified struct types need the linker's type mapping and take its path.
void merge(Module &M, Job &J) {
  auto Parsed = parseBitcodeFile(MemoryBufferRef(J.Output, J.Names.front()), M.getContext());
  if (!Parsed) throw std::runtime_error(toString(Parsed.takeError()));
  auto Unit = std::move(*Parsed);
  TypeFinder Types;
  Types.run(*Unit, /*onlyNamed=*/false);
  bool Identified = std::any_of(Types.begin(), Types.end(),
                                [](StructType *S) { return !S->isLiteral(); });
  // Validate before mutating M, so the fallback starts from the original.
  for (GlobalValue &G : Unit->global_values()) {
    GlobalValue *Existing = M.getNamedValue(G.getName());
    if (Existing ? Existing->getValueType() != G.getValueType()
                 : !G.isDeclaration() && !isa<GlobalVariable>(G))
      Identified = true;
  }
  if (Identified) return link(M, J, std::move(Unit));
  ValueToValueMapTy Map;
  std::vector<std::pair<GlobalVariable *, GlobalVariable *>> Created;
  for (GlobalValue &G : Unit->global_values()) {
    if (GlobalValue *Existing = M.getNamedValue(G.getName())) {
      // Existing initializers stay: the unit's copies were folding evidence.
      Map[&G] = Existing;
    } else if (auto *F = dyn_cast<Function>(&G)) {
      auto *D = Function::Create(F->getFunctionType(), F->getLinkage(), F->getAddressSpace(),
                                 F->getName(), &M);
      D->copyAttributesFrom(F);
      Map[&G] = D;
    } else if (auto *V = dyn_cast<GlobalVariable>(&G)) {
      // Created by a pass (a switch lookup table): moves with its initializer.
      auto *D = new GlobalVariable(M, V->getValueType(), V->isConstant(), V->getLinkage(),
                                   nullptr, V->getName(), nullptr, V->getThreadLocalMode(),
                                   V->getAddressSpace(), V->isExternallyInitialized());
      D->copyAttributesFrom(V);
      Map[&G] = D;
      Created.push_back({V, D});
    } else {
      throw std::runtime_error("unexpected global in optimized unit: " + G.getName().str());
    }
  }
  for (auto &[From, To] : Created)
    if (From->hasInitializer()) To->setInitializer(MapValue(From->getInitializer(), Map));
  for (const std::string &Name : J.Names) {
    Function *From = Unit->getFunction(Name);
    Function *To = M.getFunction(Name);
    if (!From || From->isDeclaration() || !To || !To->empty())
      throw std::runtime_error("optimized body disappeared: " + Name);
    To->setAttributes(From->getAttributes());
    moveBody(*From, *To, Map, nullptr);
  }
}


struct FunctionPipeline : FunctionPassManager {
  bool hasRequiredPass() const {
    for (const auto &P : Passes) if (P->isRequired()) return true;
    return false;
  }
};

void parallel(Module &M, TargetMachine &TM, const char *Pipeline, size_t Workers) {
  if (!Workers) throw std::runtime_error("decompilation workers must be nonzero");
  if (Workers == 1) { run(M, TM, Pipeline); return; }
  // Validate before scheduling; the ABI accepts only function-local pipelines.
  StringRef P(Pipeline);
  if (!P.starts_with("function(") || !P.ends_with(")"))
    throw std::runtime_error("parallel pipeline must contain only function passes");
  FunctionPipeline Check;
  PassBuilder Builder(&TM);
  if (Error E = Builder.parsePassPipeline(Check, P.drop_front(9).drop_back()))
    throw std::runtime_error(toString(std::move(E)));
  const bool Required = Check.hasRequiredPass();
  std::vector<std::string> Names;
  for (Function &F : M)
    if (!F.isDeclaration() && (Required || !F.hasFnAttribute(Attribute::OptimizeNone)))
      Names.push_back(F.getName().str());
  // Moving an address-taken block would invalidate blockaddress constants.
  // Such IR is not produced by lifting; keep the serial pass path for it.
  for (Function &F : M)
    for (BasicBlock &B : F)
      if (B.hasAddressTaken()) { run(M, TM, Pipeline); return; }
  if (Names.size() < 2) { run(M, TM, Pipeline); return; }
  Workers = std::min(Workers, Names.size());
  // Limit both root count and IR volume. A huge, indivisible function gets
  // its own unit instead of carrying 31 neighbors into its LLVM context.
  const size_t Grain = std::min<size_t>(32, (Names.size() - 1) / Workers + 1);
  constexpr size_t InstructionBudget = 64 * 1024;
  std::vector<size_t> Sizes;
  Sizes.reserve(Names.size());
  for (const std::string &Name : Names) {
    size_t Size = 0;
    for (BasicBlock &B : *M.getFunction(Name)) Size += B.size();
    Sizes.push_back(Size);
  }
  const MachineConfig Config(TM);
  size_t Next = 0;
  auto prepare = [&]() {
    const size_t Start = Next;
    size_t Size = 0;
    while (Next < Names.size() && Next - Start < Grain) {
      if (Next != Start && (Sizes[Next] > InstructionBudget ||
                            Size > InstructionBudget - Sizes[Next]))
        break;
      Size += Sizes[Next++];
      if (Size >= InstructionBudget) break;
    }
    auto J = std::make_unique<Job>();
    J->Names = ArrayRef<std::string>(Names).slice(Start, Next - Start);
    J->Original = std::make_unique<Module>(M.getModuleIdentifier(), M.getContext());
    try {
      // Retain the unit before moving any body, including partial extraction.
      extract(M, J->Names, *J->Original);
      J->Input = serialize(*J->Original);
    } catch (...) {
      restore(M, *J);
      throw;
    }
    return J;
  };
  auto launch = [&](Job &J) {
    J.Work = std::async(std::launch::async, [&Config, Pipeline, Ptr = &J] {
      compute(*Ptr, Config, Pipeline);
    });
  };
  // At most W original units and W-1 computing contexts are live. The caller
  // prepares one lookahead while workers run, then refills the oldest slot
  // before merging its result. Preparation sees a deterministic merge prefix,
  // regardless of worker completion order (including callee attributes).
  std::deque<std::unique_ptr<Job>> Jobs;
  try {
    while (Next < Names.size() && Jobs.size() < Workers - 1) {
      Jobs.push_back(prepare());
      launch(*Jobs.back());
    }
    while (!Jobs.empty()) {
      if (Next < Names.size()) Jobs.push_back(prepare());
      Job &J = *Jobs.front();
      J.Work.get();
      if (J.Failed)
        throw std::runtime_error("function unit " + J.Names.front() + ": " +
                         (J.Error.empty() ? "worker failed without a diagnostic" : J.Error));
      if (Jobs.size() == Workers) launch(*Jobs.back());
      merge(M, J);
      Jobs.pop_front();
    }
  } catch (...) {
    // All computing threads finish before the caller touches original IR.
    for (auto &J : Jobs) if (J->Work.valid()) J->Work.wait();
    for (auto &J : Jobs) restore(M, *J);
    throw;
  }
  verify(M);
}
} // namespace

extern "C" int biara_parallel_function_passes(LLVMModuleRef M,
    LLVMTargetMachineRef TM, const char *Pipeline, size_t Workers, char **Error) {
  *Error = nullptr;
  try {
    parallel(*unwrap(M), *reinterpret_cast<TargetMachine *>(TM), Pipeline, Workers);
    return 0;
  } catch (const std::exception &E) {
    *Error = ::strdup(E.what());
  } catch (...) {
    *Error = ::strdup("unexpected native function-pass failure");
  }
  return 1;
}
