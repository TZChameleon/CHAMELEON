#ifndef SLICE_MEM_H
#define SLICE_MEM_H

#include <stdint.h>

#define UUID_STR_LENGTH 37

#define CTX_STORAGE_SIZE 6
#define SESS_STORAGE_SIZE 6

/* Secure Memory */
#define NUM_PAGE_DESC_ENTRIES 0x1000
#define PG_FRAME 0x000FFFFFFFFFF000ul
#define PAGE_DESC_IDX_MASK 0x00FFF000ul
#define L1_PAGE_IDX_MASK 0xC0000000ul
#define L2_PAGE_IDX_MASK 0x00C00000ul

typedef unsigned long paddr_t;

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

#define TEE_MATTR_VALID_BLOCK		BIT(0)
#define TEE_MATTR_TABLE			BIT(3)
#define TEE_MATTR_PR			BIT(4)
#define TEE_MATTR_PW			BIT(5)
#define TEE_MATTR_PX			BIT(6)
#define TEE_MATTR_PRW			(TEE_MATTR_PR | TEE_MATTR_PW)
#define TEE_MATTR_PRX			(TEE_MATTR_PR | TEE_MATTR_PX)
#define TEE_MATTR_PRWX			(TEE_MATTR_PRW | TEE_MATTR_PX)
#define TEE_MATTR_UR			BIT(7)
#define TEE_MATTR_UW			BIT(8)
#define TEE_MATTR_UX			BIT(9)
#define TEE_MATTR_URW			(TEE_MATTR_UR | TEE_MATTR_UW)
#define TEE_MATTR_URX			(TEE_MATTR_UR | TEE_MATTR_UX)
#define TEE_MATTR_URWX			(TEE_MATTR_URW | TEE_MATTR_UX)
#define TEE_MATTR_PROT_MASK	\
		(TEE_MATTR_PRWX | TEE_MATTR_URWX | TEE_MATTR_GUARDED)

#define TEE_MATTR_GLOBAL		BIT(10)
#define TEE_MATTR_SECURE		BIT(11)

#define OPTEE_MSG_CMD_OPEN_SESSION	U(0)
#define OPTEE_MSG_CMD_INVOKE_COMMAND	U(1)
#define OPTEE_MSG_CMD_CLOSE_SESSION	U(2)
#define OPTEE_MSG_CMD_CANCEL		U(3)
#define OPTEE_MSG_CMD_REGISTER_SHM	U(4)
#define OPTEE_MSG_CMD_UNREGISTER_SHM	U(5)
#define OPTEE_MSG_CMD_DO_BOTTOM_HALF	U(6)
#define OPTEE_MSG_CMD_STOP_ASYNC_NOTIF	U(7)

#define CFG_TEE_CORE_NB_CORE 2
#define NUM_BASE_LEVEL_ENTRIES 4

typedef uint64_t base_xlat_tbls_t[CFG_TEE_CORE_NB_CORE][NUM_BASE_LEVEL_ENTRIES];

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
	slice_sess_state_t sess_info[SESS_STORAGE_SIZE];
} slice_ctx_t;

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

typedef struct
{
	char uuid[UUID_STR_LENGTH];
	uint64_t ptr_base_table;
	uint64_t ttbr_table[4];
	int is_used;
} slice_ttbr_table_t;

void init_ttbr_table(void);
int check_uuid_bound(char *uuid_str);
int page_table_update_is_valid(page_desc_t *secure_page_desc, paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa);
void update_secure_attr(page_desc_t *secure_page_desc, paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa, uint32_t attr);
void do_mmu_update(uint64_t *tbl, unsigned int idx, uint64_t desc, uint64_t pa);
int update_ctx_uuid(slice_ctx_t *global_slice_table_ctx, char *uuid_str);
int get_entry_idx_by_uuid(slice_ctx_t *global_slice_table_ctx, char *uuid_str);
int get_ctx_table_idx(slice_ctx_t *global_slice_table_ctx, char *uuid_str, int entry_idx, base_xlat_tbls_t *slice_base_xlation_tables, uint64_t *phys_slice_ttbr_addr);
slice_ttbr_table_t *get_slice_ttbr_table_by_uuid(slice_ctx_t *global_slice_table_ctx, uint32_t entry_idx, char *uuid_str);
int clear_phys_slice_table_entry(slice_ctx_t *global_slice_table_ctx, uint32_t entry_idx, char *uuid_str);

#endif /* SLICE_MEM_H */