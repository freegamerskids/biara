// Reusable interprocedural layout analysis, extracted from the C renderer
// (cpp/cgen.cpp: `Types`, formerly renderer-local).
//
// This header owns the native analysis the renderer consumes; the renderer
// establishes no second type convention. `BiaraLayouts` holds one cached
// `Types` result per transformed module, computed once in module/function/IR
// order (never allocator addresses) and shared by rendering (`Emitter`),
// fact export (`biara_layouts_json`), and the Rust `LayoutFacts` wrapper
// (src/layouts.rs, via `TransformedC::layout_facts`).
//
// Analysis contract (renderer and facts rely on this; keep it):
// - Observed access shapes only. Sizes are accessed extents, never declared
//   object bounds; audit object bounds must not consume them.
// - Pointer classes deliberately do not meet across calls: a generic callee
//   taking any pointer must not merge every struct passed to it. Cross-call
//   propagation is directional and context-sensitive instead:
//   offset-aware actual->formal constraints for arguments, returns, and
//   pointer fields, refined to a bounded fixpoint. Unrelated actuals at one
//   generic callee keep separate layouts; its formal receives only their
//   common evidence. One actual accumulates evidence from all its callees.
// - Overlapping incompatible accesses are explicit conflict facts
//   (`LayoutConflict`), never silently asserted source types. The renderer
//   falls back to casts on conflict, exactly as before extraction.
// - Frame embedding (a callee layout placed into a caller frame slot) and
//   structural sharing (equal layouts share one printed struct) are
//   preserved byte-for-byte from the extracted implementation.
// - Bounded work: the propagation fixpoint caps at 8 rounds; every dropped
//   fact (field-offset cap, unsupported/nonconstant address relationships,
//   overflowing offset translation) is reported through `LayoutLimits` and
//   the `FactStatus`, never a misleading `Complete` claim.
// - Stable identities: layout ids are 0-based indices into the exported
//   `layouts` array, assigned in deterministic emission order. Attaching
//   debug names (`biara_layouts_apply_debug`) only renames display fields;
//   ids, sizes, offsets, and bindings never move.
//
// Lifecycle (parent owns the shared-file integration; see src/layouts.rs
// `Handle`): build once per transformed module, cache in `TransformedC`
// ahead of the LLVM module (native analysis drops while the module stays
// alive), apply debug before facts/render (display names only), then render
// through the cached handle. Build failures return null (caller surfaces
// `Error::Llvm`); there is no silent re-analysis fallback.

#ifndef BIARA_LAYOUTS_H
#define BIARA_LAYOUTS_H

#include "llvm-c/Types.h"

#include <cstddef>
#include <cstdint>

extern "C" {
// A named field of the CPU state (offset from the start of `biara_cpu`).
// Offsets arrive env-relative from Rust; the builder adds the margin.
struct BiaraCField {
  int64_t off;
  uint32_t bytes;
  const char *name;
};

// A sink for emitted bytes: `write(p, n)` appends `n` bytes, returning 0 on
// success, nonzero to stop emission. Emission stops at the first nonzero
// return and propagates it.
typedef int (*BiaraWrite)(void *ctx, const char *p, size_t n);

// Opaque cached analysis: one `Types` result plus exported facts. Not
// thread-safe; build once per transformed module and reuse.
typedef struct BiaraLayouts BiaraLayouts;

// Read a function's guest entry without copying its metadata attachments.
// Returns 1 with `*Entry` set, or 0 when no entry is attached.
int biara_layouts_entry(LLVMValueRef Fn, uint64_t *Entry);
// Read one unsigned ABI-evidence metadata operand; returns 0 when absent.
int biara_layouts_u32_metadata(LLVMValueRef Fn, const char *Key, uint32_t Index,
                               uint32_t *Value);

// Build the cached analysis for `M` (ABI-form module). `Cpu` carries
// module-relative CPU field offsets (including the env margin). Returns
// null on allocation/analysis failure.
// Deterministic: iterates module/function/IR order only.
BiaraLayouts *biara_layouts_build(LLVMModuleRef M, const struct BiaraCField *Cpu,
                                  size_t NCpu);
// Re-run DWARF display renames after `!biara.debug_name` /
// `!biara.debug_objects` metadata changes. Structural facts (ids, sizes,
// offsets, bindings) are untouched. Returns 0 on success, 1 on failure
// (exceptions never cross the native boundary).
int biara_layouts_apply_debug(BiaraLayouts *L, LLVMModuleRef M);
// Apply user-declared struct bindings: one entry per bound layout class,
// each naming the declared struct plus its typed fields. Only the named
// classes change (never shape-matched unrelated layouts); ids, sizes
// (except asserted extra-field growth), offsets and bindings otherwise
// stay. Returns the bound layout count, or -1 on failure (exceptions
// never cross the native boundary).
struct BiaraStructField {
  int64_t off;
  uint32_t bytes;
  const char *name;
  const char *type;
};
struct BiaraStruct {
  const char *name;
  const struct BiaraStructField *fields;
  size_t nfields;
};
int biara_layouts_bind_structs(BiaraLayouts *L, const int *Classes, const struct BiaraStruct *Structs, size_t NBinds);
// Export owned facts as one UTF-8 JSON object (see src/layouts.rs
// `LayoutFacts` for field names). Small: layouts, bindings, conflicts,
// status, and limits only; no per-instruction data. Returns 0 on success,
// the first nonzero sink status otherwise.
int biara_layouts_json(const BiaraLayouts *L, BiaraWrite Write, void *Ctx);

// Cached renderer: consumes the existing analysis without re-running it.
// `L` must have been
// built for `M`. `Mode` 0 streams executable C, 1 streams function packages.
// `*Unsupported` counts constructs printed as placeholders. Returns 0 on
// success, the first nonzero sink status otherwise.
struct BiaraData;
struct BiaraStr;
struct BiaraProto;
int biara_emit_c_cached(BiaraLayouts *L, LLVMModuleRef M, const struct BiaraCField *Cpu,
                        size_t NCpu, const char *const *ConvArgs, size_t NConv, uint64_t Margin,
                        const char *Banner, size_t *Unsupported, const struct BiaraData *Data,
                        size_t NData, const struct BiaraStr *Strs, size_t NStrs,
                        const struct BiaraProto *Prs, size_t NPrs, const struct BiaraStr *Sms,
                        size_t NSms, uint32_t Mode, BiaraWrite out, void *ctx);
}

#ifdef __cplusplus
#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace biara_layouts {

// Root plus constant offset of an address (integer or pointer).
struct Base {
  llvm::Value *Root = nullptr; // nullptr: absolute address
  int64_t Off = 0;
};

// Root plus constant offset of an address (integer or pointer). Reduces
// through getelementptr, inttoptr/ptrtoint and constant adds.
Base base(llvm::Value *V, const llvm::DataLayout &DL, unsigned Depth = 0);

// A root that a pointer variable can stand for: a 64-bit-integer or pointer
// argument, load, call result, phi, or select.
bool pointerRoot(const llvm::Value *R);

// Largest offset a struct field is recovered at; larger offsets index
// arrays (or are absolute addresses) and stay casts.
constexpr int64_t kMaxField = 1 << 12;
// Rounds of cross-call constraint propagation (bounded fixpoint).
constexpr unsigned kPropagateRounds = 8;

struct Field {
  int64_t Off;
  unsigned Bytes;
  int Pointee = -1; // class of what the field points to
  int Embed = -1;   // a struct of this class, in place (frames)
  std::string Name;
  bool Debug = false;
  // User-asserted C type for this field (`""`: inferred only). When set
  // by a struct binding, the renderer spells this type instead of the
  // width-implied integer; provenance stays explicit (see export).
  std::string Asserted;
};

struct Layout {
  std::string Name; // "struct s1", ...
  std::vector<Field> Fields;
  uint64_t Size = 0; // accessed extent, not a declared object bound
  bool Scalar = false; // a pointer to the one field at offset 0
  int64_t Below = -1;   // frames: offset of the entry stack pointer

  const Field *at(int64_t Off, unsigned Bytes) const;
  const Field *startsAt(int64_t Off) const;
};

// Fields from (offset, bytes) accesses: widest per offset, then first-come
// non-overlapping.
std::vector<Field> fieldsOf(const std::map<int64_t, unsigned> &Acc, int64_t Lo, int64_t Hi);

// Evidence dropped by the bounded analysis, reported rather than hidden.
struct Limits {
  unsigned Iterations = 0;
  unsigned IterationCap = kPropagateRounds;
  unsigned CappedOffsets = 0;    // accesses at/above kMaxField
  unsigned UnsupportedBases = 0; // nonconstant address relationships
  unsigned OverflowedOffsets = 0; // offset translations that overflowed
  bool FixpointTruncated = false;
};

// Reusable layout inference: union-find pointer classes from observed
// accesses, directional cross-call propagation (never uniting actuals with
// formals), frame embedding, and structural sharing. See cpp/layouts.cpp.
struct Types {
  const llvm::DataLayout &DL;
  llvm::DenseMap<llvm::Value *, int> VarOf;
  std::vector<int> Parent;
  // Accesses: class -> offset -> widest bytes.
  std::map<int, std::map<int64_t, unsigned>> Acc;
  // Every observed width per (class, offset), including widths that lost
  // widest-wins and widths that arrived through propagation: conflict
  // evidence, never narrowed.
  std::map<int, std::map<int64_t, std::set<unsigned>>> Observed;
  std::map<int, std::set<unsigned>> AccSizes;
  std::map<int, bool> NonZeroAccess;
  std::map<std::pair<int, int64_t>, int> FieldPtr;
  std::map<int, Layout> Layouts; // by class representative
  // Frame order follows module/global/instruction order, never allocator
  // addresses.
  llvm::DenseMap<const llvm::Value *, unsigned> FrameOrder;
  struct FrameLess {
    const llvm::DenseMap<const llvm::Value *, unsigned> *Order;
    bool operator()(const llvm::Value *A, const llvm::Value *B) const;
  };
  std::map<const llvm::Value *, Layout, FrameLess> Frames;
  Limits Dropped;

  explicit Types(const llvm::DataLayout &DL);
  Types(const Types &) = delete;
  Types &operator=(const Types &) = delete;

  int find(int X);
  // Representative without path compression (for const readers/export).
  int rep(int X) const;
  void unite(int A, int B);
  int var(llvm::Value *R);
  // The class of a value that stands for a pointer variable, if any.
  int classOf(llvm::Value *V);
  const Layout *layoutOf(llvm::Value *V);
  void build(llvm::Module &M, const std::vector<BiaraCField> &Cpu);
  void propagate(const std::vector<std::tuple<Base, llvm::Value *, llvm::CallBase *>> &CallArgs,
                 const std::vector<std::pair<llvm::CallBase *, llvm::Value *>> &CallRets,
                 const std::map<llvm::Function *, std::vector<Base>> &RetBases,
                 const std::vector<std::pair<Base, llvm::Value *>> &Loaded,
                 const std::vector<std::pair<Base, llvm::Value *>> &Stored);
  // Partition refinement over the layouts: equal fields and pointees in
  // equal blocks, until stable; each block takes its first member's name.
  void share();
  // The class a pointer stored at `B` points to, if known.
  int pointeeAt(Base B);
  // Place a struct of class `C` at `Off` in frame `R`, over the scalar
  // fields there. False if it does not fit or is there already.
  bool embed(const llvm::Value *R, int64_t Off, int C);
  static std::string slotName(const Layout &L, int64_t Off);
  // C type of a pointer to class `C`'s layout.
  std::string ptrTy(int C);
  std::string fieldTy(const Field &F);
  // DWARF display renames; returns renamed fields. Structural facts stay.
  size_t debugFrames(llvm::Module &M);
  // User-declared struct bindings over shared layouts, applied per bound
  // class only (never by shape). Returns bound layouts. Classes,
  // bindings and ids stay.
  int bindStructs(const std::vector<std::tuple<int, std::string, std::vector<Field>>> &Binds);
};

// Access the cached inference for rendering (the cgen.cpp `Emitter` holds
// this reference; the handle owns it). Non-const: rendering path-compresses
// the union-find (representatives unchanged, output deterministic).
Types &biara_layouts_types(::BiaraLayouts *L);

} // namespace biara_layouts
#endif // __cplusplus

#endif // BIARA_LAYOUTS_H
