/*
 * libtcg: QEMU's TCG frontend exposed as a library.
 *
 * Stable C ABI between the patched QEMU build (one shared object per guest
 * architecture, libtcg-<arch>.so) and biara. Nothing in here references
 * QEMU-internal types; the translator output is copied into plain structs.
 *
 * Threading: QEMU keeps translator state in process globals. A process may
 * create at most one context per loaded library, and all calls into one
 * library must be serialised by the caller.
 */
#ifndef LIBTCG_H
#define LIBTCG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBTCG_API_VERSION 1

/* Return codes. */
#define LIBTCG_OK 0
/* The translator fetched bytes outside the supplied code buffer. */
#define LIBTCG_ERR_FETCH (-1)
/* Invalid argument (pc outside buffer, max_insns out of range, ...). */
#define LIBTCG_ERR_ARGS (-2)

/* Mirrors TCGType. */
typedef enum LibTcgType {
    LIBTCG_TYPE_I32 = 0,
    LIBTCG_TYPE_I64 = 1,
    LIBTCG_TYPE_I128 = 2,
    LIBTCG_TYPE_V64 = 3,
    LIBTCG_TYPE_V128 = 4,
    LIBTCG_TYPE_V256 = 5,
} LibTcgType;

/* Mirrors TCGTempKind. */
typedef enum LibTcgTempKind {
    LIBTCG_TEMP_EBB = 0,    /* live within one extended basic block */
    LIBTCG_TEMP_TB = 1,     /* live across the whole translation block */
    LIBTCG_TEMP_GLOBAL = 2, /* backed by memory at mem_base + mem_offset */
    LIBTCG_TEMP_FIXED = 3,  /* fixed host register; "env" (CPUArchState *) */
    LIBTCG_TEMP_CONST = 4,  /* constant, value in val */
} LibTcgTempKind;

typedef struct LibTcgTemp {
    uint8_t kind;      /* LibTcgTempKind */
    uint8_t type;      /* LibTcgType of this (sub)temp */
    uint8_t base_type; /* LibTcgType of the full value (I128 halves) */
    uint8_t subindex;  /* index of this half within base_type */
    int32_t mem_base;  /* temp index of the base pointer, -1 if none */
    int64_t mem_offset;
    int64_t val;       /* constant value for LIBTCG_TEMP_CONST */
    const char *name;  /* globals and fixed temps; NULL otherwise */
} LibTcgTemp;

/* Mirrors TCGOpDef. */
typedef struct LibTcgOpDef {
    const char *name;
    uint8_t nb_oargs;
    uint8_t nb_iargs;
    uint8_t nb_cargs;
    uint16_t flags; /* TCG_OPF_* */
} LibTcgOpDef;

/* A helper called by a "call" op. The C symbol is "helper_" + name. */
typedef struct LibTcgHelper {
    const char *name;
    void *func;        /* host address of the helper inside this library */
    uint32_t flags;    /* TCG_CALL_* */
    uint32_t typemask; /* dh_typemask encoding: 3 bits per slot, ret first */
} LibTcgHelper;

/*
 * One TCG op. Its arguments are args[args .. args + nb_oargs + nb_iargs +
 * nb_cargs) of the owning block, outputs first, then inputs, then constants.
 *
 * Output/input arguments are temp indices. Constant arguments are copied
 * verbatim except:
 *   - labels (set_label, br, brcond): label id;
 *   - call: a single constant, the index into LibTcgTranslationBlock.helpers;
 *   - qemu_ld/qemu_st/qemu_ld2/qemu_st2: the MemOp (mmu index dropped);
 *   - exit_tb: 0 for an unchained exit, LIBTCG_EXIT_TB_LINKED | idx when
 *     the exit names a goto_tb slot of this block.
 */
#define LIBTCG_EXIT_TB_LINKED 0x100u

typedef struct LibTcgOp {
    uint32_t opc;  /* index into libtcg_op_defs() */
    uint8_t type;  /* LibTcgType for integer and vector ops, else 0 */
    uint8_t vece;  /* log2 element size in bytes, vector ops only */
    uint8_t nb_oargs;
    uint8_t nb_iargs;
    uint8_t nb_cargs;
    uint32_t args;
} LibTcgOp;

typedef struct LibTcgTranslationBlock {
    uint64_t pc;
    uint32_t size;   /* bytes of guest code covered */
    uint32_t icount; /* guest instructions translated */
    const LibTcgOp *ops;
    size_t nb_ops;
    const uint64_t *args;
    size_t nb_args;
    /* All temps; globals occupy [0, nb_globals) and match the context. */
    const LibTcgTemp *temps;
    size_t nb_temps;
    const LibTcgHelper *helpers;
    size_t nb_helpers;
    uint32_t nb_labels;
} LibTcgTranslationBlock;

typedef struct LibTcgContextInfo {
    const char *arch;       /* e.g. "x86_64" */
    const char *cpu_model;
    uint32_t guest_bits;    /* guest address width */
    uint32_t nb_globals;
    const LibTcgTemp *globals;
    int32_t pc_global;      /* temp index of the guest program counter */
    int32_t env_global;     /* temp index of the fixed env pointer */
    uint32_t insn_start_words;
    size_t env_size;        /* sizeof(CPUArchState) */
} LibTcgContextInfo;

typedef struct LibTcgContext LibTcgContext;

uint32_t libtcg_api_version(void);

/*
 * Initialise QEMU and create the guest CPU. cpu_model may be NULL ("max").
 * Returns NULL if a context already exists in this library.
 */
LibTcgContext *libtcg_context_create(const char *cpu_model);
const LibTcgContextInfo *libtcg_context_info(const LibTcgContext *ctx);

/* The op definition table, indexed by LibTcgOp.opc. */
const LibTcgOpDef *libtcg_op_defs(size_t *count);

/*
 * The guest CPU state (CPUArchState) used for translation. Helper
 * functions expect this layout; callers may execute lifted code against it.
 */
void *libtcg_env(LibTcgContext *ctx);

/*
 * Translate one translation block starting at pc. code/code_len holds guest
 * bytes for addresses [code_base, code_base + code_len). max_insns in
 * [1, 512], or 0 for the maximum. On LIBTCG_OK *out must be released with
 * libtcg_tb_free.
 */
int libtcg_translate(LibTcgContext *ctx, const uint8_t *code, size_t code_len,
                     uint64_t code_base, uint64_t pc, uint32_t max_insns,
                     LibTcgTranslationBlock **out);
void libtcg_tb_free(LibTcgTranslationBlock *tb);

#ifdef __cplusplus
}
#endif

#endif /* LIBTCG_H */
