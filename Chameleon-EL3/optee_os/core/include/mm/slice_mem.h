#ifndef SLICE_MEM_H
#define SLICE_MEM_H

#ifndef __ASSEMBLER__
#include <assert.h>
#include <compiler.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu_types.h>
#include <types_ext.h>
#include <util.h>
#endif

#include <mm/core_mmu_arch.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <optee_msg.h>

// #define COUNT_SLICE_SMC 1
// #define COUNT_ALL_SMC 1
// #define LOG_CYCLES 1

#define RED(fmt) "\033[31m" fmt "\033[0m"

#ifndef MAX_XLAT_TABLES
#ifdef CFG_NS_VIRTUALIZATION
#define XLAT_TABLE_VIRTUALIZATION_EXTRA 3
#else
#define XLAT_TABLE_VIRTUALIZATION_EXTRA 0
#endif
#ifdef CFG_CORE_ASLR
#define XLAT_TABLE_ASLR_EXTRA 3
#else
#define XLAT_TABLE_ASLR_EXTRA 0
#endif
#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
#define XLAT_TABLE_TEE_EXTRA 8
#define XLAT_TABLE_USER_EXTRA (NUM_BASE_TABLES * CFG_TEE_CORE_NB_CORE)
#else
#define XLAT_TABLE_TEE_EXTRA 5
#define XLAT_TABLE_USER_EXTRA 0
#endif
#define MAX_XLAT_TABLES (XLAT_TABLE_TEE_EXTRA +            \
						 XLAT_TABLE_VIRTUALIZATION_EXTRA + \
						 XLAT_TABLE_ASLR_EXTRA +           \
						 XLAT_TABLE_USER_EXTRA)
#endif /*!MAX_XLAT_TABLES*/

#if (CORE_MMU_BASE_TABLE_LEVEL == 0)
#if (MAX_XLAT_TABLES <= UINT8_MAX)
typedef uint8_t l1_idx_t;
#elif (MAX_XLAT_TABLES <= UINT16_MAX)
typedef uint16_t l1_idx_t;
#else
#error MAX_XLAT_TABLES is suspiciously large, please check
#endif
#endif

/*
 * Miscellaneous MMU related constants
 */

#define INVALID_DESC 0x0
#define BLOCK_DESC 0x1
#define L3_BLOCK_DESC 0x3
#define TABLE_DESC 0x3
#define DESC_ENTRY_TYPE_MASK 0x3

#define XN (1ull << 2)
#define PXN (1ull << 1)
#define CONT_HINT (1ull << 0)

#define UPPER_ATTRS(x) (((x) & 0x7) << 52)
#define GP BIT64(50) /* Guarded Page, Aarch64 FEAT_BTI */
#define NON_GLOBAL (1ull << 9)
#define ACCESS_FLAG (1ull << 8)
#define NSH (0x0 << 6)
#define OSH (0x2 << 6)
#define ISH (0x3 << 6)

#define AP_RO (0x1 << 5)
#define AP_RW (0x0 << 5)
#define AP_UNPRIV (0x1 << 4)

#define NS (0x1 << 3)
#define LOWER_ATTRS_SHIFT 2
#define LOWER_ATTRS(x) (((x) & 0xfff) << LOWER_ATTRS_SHIFT)

#define ATTR_DEVICE_nGnRE_INDEX 0x0
#define ATTR_IWBWA_OWBWA_NTR_INDEX 0x1
#define ATTR_DEVICE_nGnRnE_INDEX 0x2
#define ATTR_TAGGED_NORMAL_MEM_INDEX 0x3
#define ATTR_INDEX_MASK 0x7

#define ATTR_DEVICE_nGnRnE (0x0)
#define ATTR_DEVICE_nGnRE (0x4)
#define ATTR_IWBWA_OWBWA_NTR (0xff)
/* Same as ATTR_IWBWA_OWBWA_NTR but with memory tagging.  */
#define ATTR_TAGGED_NORMAL_MEM (0xf0)

#define MAIR_ATTR_SET(attr, index) (((uint64_t)attr) << ((index) << 3))

#define OUTPUT_ADDRESS_MASK (0x0000FFFFFFFFF000ULL)

/* (internal) physical address size bits in EL3/EL1 */
#define TCR_PS_BITS_4GB (0x0)
#define TCR_PS_BITS_64GB (0x1)
#define TCR_PS_BITS_1TB (0x2)
#define TCR_PS_BITS_4TB (0x3)
#define TCR_PS_BITS_16TB (0x4)
#define TCR_PS_BITS_256TB (0x5)

#define FOUR_KB_SHIFT 12
#define PAGE_SIZE_SHIFT FOUR_KB_SHIFT
#define PAGE_SIZE (1 << PAGE_SIZE_SHIFT)
#define PAGE_SIZE_MASK (PAGE_SIZE - 1)
#define IS_PAGE_ALIGNED(addr) (((addr) & PAGE_SIZE_MASK) == 0)

#define XLAT_ENTRY_SIZE_SHIFT 3 /* Each MMU table entry is 8 bytes (1 << 3) */
#define XLAT_ENTRY_SIZE (1 << XLAT_ENTRY_SIZE_SHIFT)

#define XLAT_TABLE_SIZE_SHIFT PAGE_SIZE_SHIFT
#define XLAT_TABLE_SIZE (1 << XLAT_TABLE_SIZE_SHIFT)

/* Values for number of entries in each MMU translation table */
#define XLAT_TABLE_ENTRIES_SHIFT (XLAT_TABLE_SIZE_SHIFT - XLAT_ENTRY_SIZE_SHIFT)
#define XLAT_TABLE_ENTRIES (1 << XLAT_TABLE_ENTRIES_SHIFT)
#define XLAT_TABLE_ENTRIES_MASK (XLAT_TABLE_ENTRIES - 1)

#define XLAT_TABLE_LEVEL_MAX U(3)

/* Values to convert a memory address to an index into a translation table */
#define L3_XLAT_ADDRESS_SHIFT PAGE_SIZE_SHIFT
#define L2_XLAT_ADDRESS_SHIFT (L3_XLAT_ADDRESS_SHIFT + \
							   XLAT_TABLE_ENTRIES_SHIFT)
#define L1_XLAT_ADDRESS_SHIFT (L2_XLAT_ADDRESS_SHIFT + \
							   XLAT_TABLE_ENTRIES_SHIFT)
#define L0_XLAT_ADDRESS_SHIFT (L1_XLAT_ADDRESS_SHIFT + \
							   XLAT_TABLE_ENTRIES_SHIFT)
#define XLAT_ADDR_SHIFT(level) (PAGE_SIZE_SHIFT +                   \
								((XLAT_TABLE_LEVEL_MAX - (level)) * \
								 XLAT_TABLE_ENTRIES_SHIFT))

/* Base table */
#define BASE_XLAT_ADDRESS_SHIFT XLAT_ADDR_SHIFT(CORE_MMU_BASE_TABLE_LEVEL)
#define BASE_XLAT_BLOCK_SIZE XLAT_BLOCK_SIZE(CORE_MMU_BASE_TABLE_LEVEL)

#define NUM_BASE_LEVEL_ENTRIES \
	BIT(CFG_LPAE_ADDR_SPACE_BITS - BASE_XLAT_ADDRESS_SHIFT)

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
#define NUM_BASE_TABLES 2
#else
#define NUM_BASE_TABLES 1
#endif

#define UUID_STR_LENGTH 37

#define CTX_STORAGE_SIZE 6
#define SESS_STORAGE_SIZE 6

/* exported functions */
void init_slice_ctx(void);
void entry_gate_std(struct optee_msg_arg *arg);
void exit_gate_std(struct optee_msg_arg *arg);
void entry_gate_fast(struct thread_smc_args *args);
void exit_gate_fast(struct thread_smc_args *args);
void _entry_gate(uint32_t smc_call_type, uint32_t a1 __unused, uint32_t a2 __unused, uint32_t a3, uint32_t a4 __unused, uint32_t a5 __unused);
uint64_t simple_gate(uint64_t start_cycle, uint64_t trash);

/* https://aijishu.com/a/1060000000212593 */
static inline uint64_t rdfrq(void)
{
	uint64_t freq;

	__asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(freq));

	return freq;
}

static inline uint64_t rdtsc(void)
{
	uint64_t tsc;

	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(tsc));

	return tsc;
}

/* Structure for storing uuid and session, etc. */
typedef struct
{
	uint32_t is_opened;
	uint32_t sess_id;
} slice_sess_state_t;

typedef struct
{
	char uuid[UUID_STR_LENGTH];
	int table_idx;
	int table_allocated;
	int table_enabled;
	int refcnt;
	int atf_idx;
	uint64_t start_cycle, end_cycle; // for testing
	slice_sess_state_t sess_info[SESS_STORAGE_SIZE];
} slice_ctx_t;

/* Secure Memory */
#define SECMEM __attribute__((section("secmem")))
#define NUM_PAGE_DESC_ENTRIES 0x1000
#define PG_FRAME 0x000FFFFFFFFFF000ul
#define PAGE_DESC_IDX_MASK 0x00FFF000ul
#define L1_PAGE_IDX_MASK 0xC0000000ul
#define L2_PAGE_IDX_MASK 0x00C00000ul

/* Enum representing the four page types */
enum page_type_t
{
	PG_UNUSED = 0,		 /*  0: A page has not been tagged */
	PG_L1,				 /*  1: Defines a page being used as an L1 PTP */
	PG_L2,				 /*  2: Defines a page being used as an L2 PTP */
	PG_L3,				 /*  3: Defines a page being used as an L3 PTP */
	PG_L4,				 /*  4: Defines a page being used as an L4 PTP */
	PG_LEAF,			 /*  5: Generic type representing a valid LEAF page */
	PG_KDATA,			 /*  6: Defines a kernel data page */
	PG_UDATA,			 /*  7: Defines a user data page */
	PG_KCODE,			 /*  8: Defines a kernel code page */
	PG_UCODE,			 /*  9: Defines a user code page */
	PG_SECMEM,			 /* 10: Defines a slice page */
	PG_GHOST,			 /* 11: Defines a secure page */
	PG_DML1,			 /* 12: Defines a L1 PTP for the direct map */
	PG_DML2,			 /* 13: Defines a L2 PTP for the direct map */
	PG_DML3,			 /* 14: Defines a L3 PTP for the direct map */
	PG_DML4,			 /* 15: Defines a L4 PTP for the direct map */
	PG_SLICE_LIB1,		 /* 16: A page for slice service lib1 */
	PG_SLICE_LIB2,		 /* 17: A page for slice service lib2 */
	PG_SLICE_LIB3,		 /* 18: A page for slice service lib3 */
	PG_SLICE_LIB4,		 /* 19: A page for slice service lib4 */
	PG_SLICE_LIB5,		 /* 20: A page for slice service lib5 */
	PG_SLICE_LIB6,		 /* 21: A page for slice service lib6 */
	PG_SLICE_LIB7,		 /* 22: A page for slice service lib7 */
	PG_SLICE_LIB8,		 /* 23: A page for slice service lib8 */
	PG_SLICE_LIB9,		 /* 24: A page for slice service lib8 */
	PG_SLICE_LIB10,		 /* 25: A page for slice service lib8 */
	PG_SLICE_LIB_OTHERS, /* 26: A page for slice service lib others */
};

/*
 * There is one element of this structure for each physical page of memory in the system.
 * It records information about the physical memory
 * (and the  data stored within it) that Secure-MMU needs to perform its MMU safety checks.
 * This structure is page metadata information
 */
typedef struct page_desc_t
{
	enum page_type_t type;
	uintptr_t pgVaddr;
	unsigned ghostPTP : 1;
	unsigned stack : 1;
	unsigned code : 1;
	unsigned active : 1;
	unsigned count : 12;
	unsigned user : 1;
	unsigned index;
	char uuid[UUID_STR_LENGTH];
} page_desc_t;

/* Slice Bitmap */
#define SLICE_BITS_COUNT 11
#define SLICE_SHIFT_BITS PG_SLICE_LIB1
#define SLICE_LIB1_BIT (1 << (PG_SLICE_LIB1 - SLICE_SHIFT_BITS))
#define SLICE_LIB2_BIT (1 << (PG_SLICE_LIB2 - SLICE_SHIFT_BITS))
#define SLICE_LIB3_BIT (1 << (PG_SLICE_LIB3 - SLICE_SHIFT_BITS))
#define SLICE_LIB4_BIT (1 << (PG_SLICE_LIB4 - SLICE_SHIFT_BITS))
#define SLICE_LIB5_BIT (1 << (PG_SLICE_LIB5 - SLICE_SHIFT_BITS))
#define SLICE_LIB6_BIT (1 << (PG_SLICE_LIB6 - SLICE_SHIFT_BITS))
#define SLICE_LIB7_BIT (1 << (PG_SLICE_LIB7 - SLICE_SHIFT_BITS))
#define SLICE_LIB8_BIT (1 << (PG_SLICE_LIB8 - SLICE_SHIFT_BITS))
#define SLICE_LIB9_BIT (1 << (PG_SLICE_LIB9 - SLICE_SHIFT_BITS))
#define SLICE_LIB10_BIT (1 << (PG_SLICE_LIB10 - SLICE_SHIFT_BITS))
#define SLICE_LIB_OTHERS_BIT (1 << (PG_SLICE_LIB_OTHERS - SLICE_SHIFT_BITS))

#define FIXED_LIB_BITS SLICE_LIB7_BIT
#define DRM_LIB_BITS SLICE_LIB1_BIT | SLICE_LIB2_BIT | SLICE_LIB3_BIT | \
						 SLICE_LIB4_BIT | SLICE_LIB7_BIT
#define CRYPTO_LIB_BITS SLICE_LIB1_BIT | SLICE_LIB2_BIT | SLICE_LIB3_BIT |     \
							SLICE_LIB4_BIT | SLICE_LIB5_BIT | SLICE_LIB6_BIT | \
							SLICE_LIB7_BIT | SLICE_LIB8_BIT | SLICE_LIB10_BIT
#define STORAGE_LIB_BITS SLICE_LIB1_BIT | SLICE_LIB2_BIT | SLICE_LIB6_BIT | \
							 SLICE_LIB9_BIT | FIXED_LIB_BITS
#define PAY_LIB_BITS SLICE_LIB1_BIT | SLICE_LIB2_BIT | SLICE_LIB3_BIT |     \
						 SLICE_LIB4_BIT | SLICE_LIB5_BIT | SLICE_LIB6_BIT | \
						 SLICE_LIB8_BIT | SLICE_LIB9_BIT | FIXED_LIB_BITS
#define IDENTITY_LIB_BITS SLICE_LIB1_BIT | SLICE_LIB3_BIT | SLICE_LIB5_BIT | FIXED_LIB_BITS

/* Memory Update Flags */
#define SLICE_MEMORY_INVALID 0	 /* The update is not valid and should not be performed */
#define SLICE_MEMORY_READ_ONLY 1 /* The update is valid but should disable write access */
#define SLICE_MEMORY_AVAILABLE 2 /* The update is valid and can be performed */

extern void init_memory_tagging(void);
extern void slice_memory_tagging(int table_idx, char *uuid_str);
extern void slice_set_page_table_tagging(paddr_t pa, unsigned level);
extern void slice_update_mapping(struct core_mmu_table_info *tbl_info, unsigned int idx, paddr_t pa, uint32_t attr);
extern int is_slice_tagging_enabled(struct core_mmu_table_info *tbl_info);

extern uint64_t mattr_to_desc(unsigned level, uint32_t attr);

#endif /* SLICE_MEM_H */