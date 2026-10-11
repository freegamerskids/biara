// Streaming LLVM IR output (see src/output.rs): print a module through a
// `raw_ostream` that forwards each chunk to a Rust `io::Write` callback, so
// neither a whole-module string nor a platform-specific path (`/dev/stdout`)
// is needed for stdout or piped output.

#include "llvm-c/Types.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <cstddef>
#include <cstdint>

using namespace llvm;

extern "C" {
// Write `len` bytes at `data`; return 0 on success, nonzero on error.
// Never unwinds: after the first error the stream drops the rest of the
// output instead of calling back again.
typedef int (*biara_write_fn)(void *ctx, const char *data, size_t len);
}

namespace {

class CallbackStream : public raw_ostream {
public:
  CallbackStream(biara_write_fn write, void *ctx) : write_(write), ctx_(ctx) {}

  bool failed() const { return failed_; }

private:
  void write_impl(const char *ptr, size_t size) override {
    if (failed_ || size == 0)
      return;
    if (write_(ctx_, ptr, size) != 0)
      failed_ = true;
    else
      position_ += size;
  }

  uint64_t current_pos() const override { return position_; }

  biara_write_fn write_;
  void *ctx_;
  bool failed_ = false;
  uint64_t position_ = 0;
};

} // namespace

// Print `M` in chunks; return 0, or 1 if the callback reported an error
// (the first one; later chunks are dropped). Flushes before returning, so a
// successful return means every byte reached the callback.
extern "C" int biara_print_module(LLVMModuleRef MRef, biara_write_fn write, void *ctx) {
  Module &M = *unwrap(MRef);
  CallbackStream os(write, ctx);
  M.print(os, nullptr);
  os.flush();
  return os.failed() ? 1 : 0;
}
