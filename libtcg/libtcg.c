/*
 * libtcg: QEMU's TCG frontend exposed as a library. See libtcg.h.
 *
 * Built by the patched QEMU meson build as libtcg-<target>.so from the same
 * objects as qemu-<target> (linux-user), with every symbol except the
 * libtcg_* API hidden by libtcg.ver.
 */
#include "qemu/osdep.h"
#include "qemu/accel.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "accel/accel-ops.h"
#include "accel/tcg/cpu-ops.h"
#include "exec/page-vary.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "hw/core/cpu.h"
#include "tcg/startup.h"
#include "tcg/tcg.h"
#include "tcg/helper-info.h"
#include "tcg/insn-start-words.h"

/* linux-user/main.c (declared in linux-user/user-internals.h). */
extern __thread CPUState *thread_cpu;

#include "cpu.h"
#include "libtcg.h"

struct LibTcgContext {
    CPUState *cpu;
    LibTcgContextInfo info;
    LibTcgTemp *globals;
    TranslationBlock tb;
};

static LibTcgContext *the_ctx;
static LibTcgOpDef *op_defs;

/* Code buffer for the translation in progress; see libtcg_fetch. */
static struct {
    const uint8_t *code;
    size_t len;
    uint64_t base;
    sigjmp_buf jmp;
} fetch;

/* ---- architecture-specific setup ---------------------------------------- */

#if defined(TARGET_X86_64)
#define LIBTCG_ARCH "x86_64"
#define LIBTCG_PC_OFFSET offsetof(CPUX86State, eip)

/* Linux user-mode selectors (__USER_CS / __USER_DS on x86_64). */
#define LIBTCG_USER_CS 0x33
#define LIBTCG_USER_DS 0x2b

/* 64-bit ring-3 flat state, as linux-user/i386/cpu_loop.c:init_main_thread. */
static void arch_setup(CPUState *cs)
{
    CPUX86State *env = cpu_env(cs);

    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
    env->eflags |= IF_MASK;
    memset(env->regs, 0, sizeof(env->regs));

    cpu_x86_load_seg_cache(env, R_CS, LIBTCG_USER_CS, 0, 0xffffffff,
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                           DESC_S_MASK | DESC_L_MASK |
                           (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
    cpu_x86_load_seg_cache(env, R_SS, LIBTCG_USER_DS, 0, 0xffffffff,
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                           DESC_S_MASK |
                           (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    cpu_x86_load_seg_cache(env, R_DS, 0, 0, 0, 0);
    cpu_x86_load_seg_cache(env, R_ES, 0, 0, 0, 0);
    cpu_x86_load_seg_cache(env, R_FS, 0, 0, 0, 0);
    cpu_x86_load_seg_cache(env, R_GS, 0, 0, 0, 0);
}
#elif defined(TARGET_AARCH64)
#define LIBTCG_ARCH "aarch64"
#define LIBTCG_PC_OFFSET offsetof(CPUARMState, pc)

/*
 * cpu_reset already leaves a CONFIG_USER_ONLY CPU in AArch64 EL0 with the
 * Linux SCTLR/TCR settings; the registers are cleared as
 * linux-user/aarch64/cpu_loop.c:init_main_thread does. Pointer-auth keys
 * stay zero so PAC results are deterministic.
 *
 * Top-byte-ignore is turned off: with TBI0 every branch target and memory
 * address goes through a sextract/and clean-up that hides plain pointer
 * arithmetic from analysis. Tagged pointers (HWASan, MTE) are rare in
 * ordinary binaries and are then taken at face value.
 */
static void arch_setup(CPUState *cs)
{
    CPUARMState *env = cpu_env(cs);

    memset(env->xregs, 0, sizeof(env->xregs));
    env->cp15.tcr_el[1] &= ~(1ULL << 37); /* TBI0 */
    arm_rebuild_hflags(env);
}
#else
#error "libtcg: unsupported target"
#endif

/* ---- helpers ------------------------------------------------------------ */

static void export_temp(TCGContext *s, const TCGTemp *ts, LibTcgTemp *out)
{
    out->kind = ts->kind;
    out->type = ts->type;
    out->base_type = ts->base_type;
    out->subindex = ts->temp_subindex;
    out->mem_base = ts->mem_base ? (int32_t)(ts->mem_base - s->temps) : -1;
    out->mem_offset = ts->mem_offset;
    out->val = ts->kind == TEMP_CONST ? ts->val : 0;
    out->name = (ts->kind == TEMP_GLOBAL || ts->kind == TEMP_FIXED)
                ? ts->name : NULL;
}

static bool libtcg_fetch(void *dest, vaddr pc, size_t len)
{
    uint64_t off = pc - fetch.base;

    if (pc < fetch.base || off > fetch.len || len > fetch.len - off) {
        siglongjmp(fetch.jmp, 1);
    }
    memcpy(dest, fetch.code + off, len);
    return true;
}

static uint32_t helper_index(GPtrArray *helpers, const TCGHelperInfo *info)
{
    for (guint i = 0; i < helpers->len; i++) {
        if (g_ptr_array_index(helpers, i) == info) {
            return i;
        }
    }
    g_ptr_array_add(helpers, (gpointer)info);
    return helpers->len - 1;
}

static LibTcgTranslationBlock *export_tb(TCGContext *s, TranslationBlock *tb)
{
    LibTcgTranslationBlock *out = g_new0(LibTcgTranslationBlock, 1);
    GArray *ops = g_array_new(false, true, sizeof(LibTcgOp));
    GArray *args = g_array_new(false, true, sizeof(uint64_t));
    GPtrArray *helpers = g_ptr_array_new();
    LibTcgTemp *temps = g_new0(LibTcgTemp, s->nb_temps);
    LibTcgHelper *hout;
    uintptr_t tb_rx = (uintptr_t)tcg_splitwx_to_rx(tb);
    TCGOp *op;

    for (int i = 0; i < s->nb_temps; i++) {
        export_temp(s, &s->temps[i], &temps[i]);
    }

    QTAILQ_FOREACH(op, &s->ops, link) {
        const TCGOpDef *def = &tcg_op_defs[op->opc];
        LibTcgOp o = {
            .opc = op->opc,
            .args = args->len,
        };
        unsigned nb_temps_args;

        if (op->opc == INDEX_op_call) {
            const TCGHelperInfo *info;
            uint64_t idx;

            o.nb_oargs = TCGOP_CALLO(op);
            o.nb_iargs = TCGOP_CALLI(op);
            o.nb_cargs = 1;
            nb_temps_args = o.nb_oargs + o.nb_iargs;
            for (unsigned i = 0; i < nb_temps_args; i++) {
                uint64_t t = arg_temp(op->args[i]) - s->temps;
                g_array_append_val(args, t);
            }
            info = (const TCGHelperInfo *)(uintptr_t)op->args[nb_temps_args + 1];
            idx = helper_index(helpers, info);
            g_array_append_val(args, idx);
            g_array_append_val(ops, o);
            continue;
        }

        if (def->flags & (TCG_OPF_INT | TCG_OPF_VECTOR)) {
            o.type = TCGOP_TYPE(op);
        }
        if (def->flags & TCG_OPF_VECTOR) {
            o.vece = TCGOP_VECE(op);
        }
        o.nb_oargs = def->nb_oargs;
        o.nb_iargs = def->nb_iargs;
        o.nb_cargs = def->nb_cargs;
        nb_temps_args = o.nb_oargs + o.nb_iargs;

        for (unsigned i = 0; i < nb_temps_args; i++) {
            uint64_t t = arg_temp(op->args[i]) - s->temps;
            g_array_append_val(args, t);
        }
        for (unsigned i = 0; i < o.nb_cargs; i++) {
            TCGArg a = op->args[nb_temps_args + i];
            uint64_t v = a;

            switch (op->opc) {
            case INDEX_op_set_label:
            case INDEX_op_br:
                v = arg_label(a)->id;
                break;
            case INDEX_op_brcond:
                if (i == 1) {
                    v = arg_label(a)->id;
                }
                break;
            case INDEX_op_qemu_ld:
            case INDEX_op_qemu_st:
            case INDEX_op_qemu_ld2:
            case INDEX_op_qemu_st2:
                v = get_memop(a);
                break;
            case INDEX_op_exit_tb:
                v = a ? (LIBTCG_EXIT_TB_LINKED | (a - tb_rx)) : 0;
                break;
            default:
                break;
            }
            g_array_append_val(args, v);
        }
        g_array_append_val(ops, o);
    }

    hout = g_new0(LibTcgHelper, helpers->len);
    for (guint i = 0; i < helpers->len; i++) {
        const TCGHelperInfo *info = g_ptr_array_index(helpers, i);
        hout[i] = (LibTcgHelper) {
            .name = info->name,
            .func = info->func,
            .flags = info->flags,
            .typemask = info->typemask,
        };
    }

    out->pc = tb->pc;
    out->size = tb->size;
    out->icount = tb->icount;
    out->nb_ops = ops->len;
    out->ops = (LibTcgOp *)g_array_free(ops, false);
    out->nb_args = args->len;
    out->args = (uint64_t *)g_array_free(args, false);
    out->nb_temps = s->nb_temps;
    out->temps = temps;
    out->nb_helpers = helpers->len;
    out->helpers = hout;
    out->nb_labels = s->nb_labels;
    g_ptr_array_free(helpers, true);
    return out;
}

/* ---- API ---------------------------------------------------------------- */

uint32_t libtcg_api_version(void)
{
    return LIBTCG_API_VERSION;
}

LibTcgContext *libtcg_context_create(const char *cpu_model)
{
    LibTcgContext *ctx;
    AccelState *accel;
    AccelClass *ac;
    const char *cpu_type;
    TCGContext *s;

    if (the_ctx) {
        return NULL;
    }
    if (!cpu_model) {
        cpu_model = "max";
    }

    error_init("libtcg");
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    cpu_type = parse_cpu_option(cpu_model);

    accel = current_accel();
    ac = ACCEL_GET_CLASS(accel);
    accel_init_interfaces(ac);
    ac->init_machine(accel, NULL);

    set_preferred_target_page_bits(ctz32(qemu_real_host_page_size()));
    finalize_target_page_bits();

    ctx = g_new0(LibTcgContext, 1);
    ctx->cpu = cpu_create(cpu_type);
    cpu_reset(ctx->cpu);
    thread_cpu = ctx->cpu;
    arch_setup(ctx->cpu);

    tcg_register_thread();
    s = tcg_ctx;
    ctx->globals = g_new0(LibTcgTemp, s->nb_globals);
    ctx->info.pc_global = -1;
    ctx->info.env_global = temp_idx(tcgv_ptr_temp(tcg_env));
    for (int i = 0; i < s->nb_globals; i++) {
        const TCGTemp *ts = &s->temps[i];

        export_temp(s, ts, &ctx->globals[i]);
        if (ts->kind == TEMP_GLOBAL && ts->mem_offset == LIBTCG_PC_OFFSET) {
            ctx->info.pc_global = i;
        }
    }

    ctx->info.arch = LIBTCG_ARCH;
    ctx->info.cpu_model = g_strdup(cpu_model);
    ctx->info.guest_bits = TARGET_LONG_BITS;
    ctx->info.nb_globals = s->nb_globals;
    ctx->info.globals = ctx->globals;
    ctx->info.insn_start_words = INSN_START_WORDS;
    ctx->info.env_size = sizeof(CPUArchState);

    op_defs = g_new0(LibTcgOpDef, tcg_op_defs_max);
    for (size_t i = 0; i < tcg_op_defs_max; i++) {
        op_defs[i] = (LibTcgOpDef) {
            .name = tcg_op_defs[i].name,
            .nb_oargs = tcg_op_defs[i].nb_oargs,
            .nb_iargs = tcg_op_defs[i].nb_iargs,
            .nb_cargs = tcg_op_defs[i].nb_cargs,
            .flags = tcg_op_defs[i].flags,
        };
    }

    the_ctx = ctx;
    return ctx;
}

const LibTcgContextInfo *libtcg_context_info(const LibTcgContext *ctx)
{
    return &ctx->info;
}

const LibTcgOpDef *libtcg_op_defs(size_t *count)
{
    *count = op_defs ? tcg_op_defs_max : 0;
    return op_defs;
}

void *libtcg_env(LibTcgContext *ctx)
{
    return cpu_env(ctx->cpu);
}

int libtcg_translate(LibTcgContext *ctx, const uint8_t *code, size_t code_len,
                     uint64_t code_base, uint64_t pc, uint32_t max_insns,
                     LibTcgTranslationBlock **out)
{
    CPUState *cs = ctx->cpu;
    TranslationBlock *tb = &ctx->tb;
    TCGTBCPUState st;
    TCGContext *s;
    volatile int limit;
    int n;

    *out = NULL;
    if (pc < code_base || pc - code_base >= code_len ||
        max_insns > TCG_MAX_INSNS) {
        return LIBTCG_ERR_ARGS;
    }
    limit = max_insns ? max_insns : TCG_MAX_INSNS;

    tcg_register_thread();
    s = tcg_ctx;
    thread_cpu = cs;

    /* Flags (mode bits) from the CPU state; the pc comes from the caller. */
    st = cs->cc->tcg_ops->get_tb_cpu_state(cs);

    memset(tb, 0, sizeof(*tb));
    tb->pc = pc;
    tb->cs_base = st.cs_base;
    tb->flags = st.flags;
    tb_set_page_addr0(tb, pc & TARGET_PAGE_MASK);

    s->gen_tb = tb;
    s->guest_mo = cs->cc->tcg_ops->guest_default_memory_order;

    fetch.code = code;
    fetch.len = code_len;
    fetch.base = code_base;
    libtcg_code_read = libtcg_fetch;

    if (sigsetjmp(fetch.jmp, 0) != 0) {
        libtcg_code_read = NULL;
        s->gen_tb = NULL;
        s->cpu = NULL;
        return LIBTCG_ERR_FETCH;
    }

    /*
     * More temps or ops than one TB may have (tcg_raise_tb_overflow):
     * start over with half as many instructions, as tb_gen_code does.
     */
    if (sigsetjmp(s->jmp_trans, 0) != 0) {
        g_assert(limit > 1);
        limit /= 2;
    }
    n = limit;
    /*
     * CF_NOIRQ: no icount/exit-request prologue.
     * CF_NO_GOTO_PTR: indirect exits become exit_tb instead of a host
     * lookup helper; the next pc is always left in the pc global.
     */
    tb->cflags = CF_NOIRQ | CF_NO_GOTO_PTR | (n & CF_COUNT_MASK);
    tb_set_page_addr1(tb, -1);

    tcg_func_start(s);
    s->cpu = cs;
    cs->cc->tcg_ops->translate_code(cs, tb, &n, pc,
                                    (void *)(code + (pc - code_base)));
    s->cpu = NULL;
    libtcg_code_read = NULL;

    *out = export_tb(s, tb);
    s->gen_tb = NULL;
    return LIBTCG_OK;
}

void libtcg_tb_free(LibTcgTranslationBlock *tb)
{
    if (!tb) {
        return;
    }
    g_free((void *)tb->ops);
    g_free((void *)tb->args);
    g_free((void *)tb->temps);
    g_free((void *)tb->helpers);
    g_free(tb);
}
