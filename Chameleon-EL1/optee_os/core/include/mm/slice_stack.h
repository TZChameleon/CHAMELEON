#ifndef SLICE_STACK_H
#define SLICE_STACK_H

#include <inttypes.h>
#include <kernel/misc.h>

/* same as structures in core/arch/arm/mm/core_mmu_lpae.c */
typedef uint64_t base_xlat_tbls_t[CFG_TEE_CORE_NB_CORE][NUM_BASE_LEVEL_ENTRIES];
typedef uint64_t xlat_tbl_t[XLAT_TABLE_ENTRIES];
struct mmu_partition
{
    base_xlat_tbls_t *base_tables;
    xlat_tbl_t *xlat_tables;
    xlat_tbl_t *l2_ta_tables;
    unsigned int xlat_tables_used;
    unsigned int asid;

#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
    /*
     * Indexes of the L1 table from 'xlat_tables'
     * that points to the user mappings.
     */
    l1_idx_t user_l1_table_idx[NUM_BASE_TABLES][CFG_TEE_CORE_NB_CORE];
#endif

    base_xlat_tbls_t *slice_base_tables[CTX_STORAGE_SIZE];
    unsigned int slice_xlat_tables_used[CTX_STORAGE_SIZE];
};

extern const unsigned long SecureStackBase;
extern unsigned long normal_stack[1];
extern unsigned long normal_ttbr[1];
extern unsigned long ptr_base_tables[1];
extern uint64_t slice_arguments[8];

/* spinlock for global vars */
unsigned int slice_stack_spinlock;

/* extern variables from core/arch/arm/mm/core_mmu_lpae.c */
extern base_xlat_tbls_t base_xlation_table[NUM_BASE_TABLES];

/* !!!!warning: x0-x7 are used to pass parameters, so it is impossible to use these registers carefully.(DO not override parameters!!!!) */

/* Store arguments (x0-x4 is enough currently) */
#define STORE_ARGS               \
    "ldr x7, =slice_arguments\n" \
    "str x0, [x7, #0]\n"         \
    "str x1, [x7, #8]\n"         \
    "str x2, [x7, #16]\n"        \
    "str x3, [x7, #24]\n"        \
    "str x4, [x7, #32]\n"

#define RESTORE_ARGS             \
    "ldr x7, =slice_arguments\n" \
    "ldr x0, [x7, #0]\n"         \
    "ldr x1, [x7, #8]\n"         \
    "ldr x2, [x7, #16]\n"        \
    "ldr x3, [x7, #24]\n"        \
    "ldr x4, [x7, #32]\n"

/* TTBR switch */
#define SWITCH_TO_NOMAL_TTBR           \
    "mrs x6, ttbr0_el1\n"              \
    "ldr x4, =ptr_default_partition\n" \
    "ldr x4, [x4]\n"                   \
    "ldr x7, [x4]\n"                   \
    "stp x6, x7, [sp, #-16]\n"         \
    "sub sp, sp, #16\n"                \
    "ldr x4, =base_xlation_table\n"    \
    "bl __get_core_pos\n"              \
    "mov x5, #32\n"                    \
    "mul x0, x0, x5\n"                 \
    "add x4, x4, x0\n"                 \
    "msr ttbr0_el1, x4\n"              \
    "isb\n"                            \
    "ldr x4, =ptr_default_partition\n" \
    "ldr x4, [x4]\n"                   \
    "ldr x5, =base_xlation_table\n"    \
    "str x5, [x4]\n"

#define SIWTCH_BACK_TO_OLD_TTBR        \
    "ldr x0, =SecureStackBase\n"       \
    "ldr x0, [x0]\n"                   \
    "ldp x6, x7, [x0, #-32]\n"         \
    "msr ttbr0_el1, x6\n"              \
    "ldr x4, =ptr_default_partition\n" \
    "ldr x4, [x4]\n"                   \
    "str x7, [x4]\n"

/* stack switch */
#define SWITCH_TO_SECURE_STACK                \
    "mov x4, sp\n" /*normal_stack mov to x4*/ \
    "ldr x7, =normal_stack\n"                 \
    "str x4, [x7]\n"                          \
    "ldr x5, =SecureStackBase\n"              \
    "ldr x5, [x5]\n"                          \
    "stp x29, x30, [x5, #-16]\n"              \
    "sub x5, x5, #16\n"                       \
    "mov sp, x5\n"

#define SWITCH_BACK_TO_NORMAL_STACK \
    "ldr x0, =SecureStackBase\n"    \
    "ldr x0, [x0]\n"                \
    "ldp x29, x30, [x0, #-16]\n"    \
    "ldr x7, =normal_stack\n"       \
    "ldr x0, [x7]\n"                \
    "mov sp, x0\n"

/*FIQ control*/
#define DISABLE_FIQ \
    "msr daifset, #1\n"

#define ENABLE_FIQ \
    "msr daifclr, #1\n"

/*IRQ control*/
#define DISABLE_IRQ \
    "msr daifset, #2\n"

#define ENABLE_IRQ \
    "msr daifclr, #2\n"

/*ASY control*/
#define DISABLE_ASY \
    "msr daifset, #4\n"

#define ENABLE_ASY \
    "msr daifclr, #4\n"

/*DBG control*/
#define DISABLE_DBG \
    "msr daifset, #8\n"

#define ENABLE_DBG \
    "msr daifclr, #8\n"

/*ALL EXP control*/
#define DISABLE_INTERRUPT \
    DISABLE_IRQ           \
    DISABLE_FIQ           \
    DISABLE_ASY           \
    DISABLE_DBG

#define ENABLE_INTERRUPT \
    ENABLE_DBG           \
    ENABLE_ASY           \
    ENABLE_FIQ           \
    ENABLE_IRQ

/**
 * Load-Acquire, Store-Release
 * LDAXR: https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/LDAXR--Load-Acquire-Exclusive-Register-
 * STLXR: https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/STLXR--Store-Release-Exclusive-Register-
 */

#define LOCK_VARS(var_name)                         \
    "mov w8, #1\n"                                  \
    "ldr x9, =" #var_name "\n"                      \
    "ldaxr w7, [x9]\n" /* mark [x9] as exclusive */ \
    "cmp w7, #0\n"                                  \
    "bne 16\n"                                      \
    "stlxr w7, w8, [x9]\n" /* block other write */  \
    "cmp w7, #0\n"                                  \
    "beq 12\n"                                      \
    "wfe\n"                                         \
    "b -36\n"      /* try again */                  \
    "mov x7, x7\n" /* `nop` */

#define UNLOCK_VARS(var_name)  \
    "mov w8, #0\n"             \
    "ldr x9, =" #var_name "\n" \
    "str w8, [x9]\n" /* clear spinlock */

#define LOCK_VARS_ALL \
    LOCK_VARS(slice_stack_spinlock)

#define UNLOCK_VARS_ALL \
    UNLOCK_VARS(slice_stack_spinlock)

/*ENTRY/EXIT gate*/
#define SECURE_ENTRY       \
    DISABLE_INTERRUPT      \
    LOCK_VARS_ALL          \
    STORE_ARGS             \
    SWITCH_TO_SECURE_STACK \
    SWITCH_TO_NOMAL_TTBR   \
    RESTORE_ARGS

#define SECURE_EXIT             \
    STORE_ARGS                  \
    SIWTCH_BACK_TO_OLD_TTBR     \
    SWITCH_BACK_TO_NORMAL_STACK \
    RESTORE_ARGS                \
    UNLOCK_VARS_ALL             \
    ENABLE_INTERRUPT

#define SECURE_ENTRY_NO_INTERRUPT \
    STORE_ARGS                    \
    SWITCH_TO_SECURE_STACK        \
    SWITCH_TO_NOMAL_TTBR          \
    RESTORE_ARGS

#define SECURE_EXIT_NO_INTERRUPT \
    STORE_ARGS                   \
    SIWTCH_BACK_TO_OLD_TTBR      \
    SWITCH_BACK_TO_NORMAL_STACK  \
    RESTORE_ARGS

#define SECURE_WRAPPER(RET_TYPE, FUNC, ...)                                        \
    asm(                                                                           \
        ".text\n"                                                                  \
        ".globl " #FUNC "\n"                                                       \
        ".align 16,0x90\n"                                                         \
        ".type " #FUNC ",@function\n" #FUNC ":\n"                                  \
        ".cfi_startproc\n"      /* Do whatever's needed on entry to secure area */ \
        SECURE_ENTRY            /* Call real version of function */                \
        "bl " #FUNC "_secure\n" /* Operation complete, go back to unsecure mode */ \
        SECURE_EXIT                                                                \
        "ret\n" #FUNC "_end:\n"                                                    \
        ".size " #FUNC ", " #FUNC "_end - " #FUNC "\n"                             \
        ".cfi_endproc\n");                                                         \
    RET_TYPE FUNC##_secure(__VA_ARGS__);                                           \
    RET_TYPE __attribute__((visibility("hidden"))) FUNC##_secure(__VA_ARGS__)

#define SECURE_WRAPPER_NO_INTERRUPT(RET_TYPE, FUNC, ...)                             \
    asm(                                                                             \
        ".text\n"                                                                    \
        ".globl " #FUNC "\n"                                                         \
        ".align 16,0x90\n"                                                           \
        ".type " #FUNC ",@function\n" #FUNC ":\n"                                    \
        ".cfi_startproc\n"        /* Do whatever's needed on entry to secure area */ \
        SECURE_ENTRY_NO_INTERRUPT /* Call real version of function */                \
        "bl " #FUNC "_secure\n"   /* Operation complete, go back to unsecure mode */ \
        SECURE_EXIT_NO_INTERRUPT                                                     \
        "ret\n" #FUNC "_end:\n"                                                      \
        ".size " #FUNC ", " #FUNC "_end - " #FUNC "\n"                               \
        ".cfi_endproc\n");                                                           \
    RET_TYPE FUNC##_secure(__VA_ARGS__);                                             \
    RET_TYPE __attribute__((visibility("hidden"))) FUNC##_secure(__VA_ARGS__)

#endif /* SLICE_STACK_H */