#include <mm/core_mmu.h>
#include <mm/slice_mem.h>
#include <mm/slice_stack.h>
#include <mm/mobj.h>
#include <sm/optee_smc.h>
#include <optee_msg.h>
#include <kernel/linker.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/misc.h>
#include <kernel/tlb_helpers.h>
#include <kernel/cache_helpers.h>
#include <kernel/spinlock.h>
#include <stdio.h>
#include <string.h>
#include <tee/uuid.h>

/* secure stack */
char SecureStack[1 << 12] SECMEM __attribute__((aligned(16))); /* SP should be aligned with 0x10 */
const uintptr_t SecureStackBase = (uintptr_t)SecureStack + sizeof(SecureStack);

/* storing data for SECURE STACK */
unsigned long normal_stack[1];
unsigned long normal_ttbr[1];
unsigned long ptr_base_tables[1];
uint64_t slice_arguments[8] SECMEM;

#ifdef LOG_CYCLES
uint64_t cycles_in_memory_checking = 0;
uint64_t cycles_in_ttbr_switching = 0;
uint64_t cycles_in_ta_initialization = 0;
#endif // LOG_CYCLES

/* extern variables from core/arch/arm/mm/core_mmu_lpae.c */
extern struct mmu_partition *ptr_default_partition;
extern base_xlat_tbls_t slice_base_xlation_tables[CTX_STORAGE_SIZE][NUM_BASE_TABLES];
extern xlat_tbl_t slice_xlat_tables[CTX_STORAGE_SIZE][MAX_XLAT_TABLES];

/* UUID list */
static char uuid_acipher[] = "a734eed9-d6a1-4244-aa50-7c99719e7b7b";
static char uuid_secure_storage[] = "f4e750bb-1437-4fbf-8785-8d3580c34994";
static char uuid_hotp[] = "484d4143-2d53-4841-3120-4a6f636b6542";
static char uuid_wallet[] = "f894e6e0-1215-11e6-9281-0002a5d5c51b";
static char uuid_clearkey[] = "442ed209-b8e2-405e-8384-5cc78c753428";
static char uuid_hello_world[] __unused = "8aaaf200-2450-11e4-abe2-0002a5d5c51b";
static char uuid_aes[] __unused = "5dbac793-f574-4871-8ad3-04331ec17f24";
static char uuid_random[] __unused = "b6c53aba-9669-4668-a7f2-205629d00f86";

static slice_ctx_t global_slice_table_ctx[CTX_STORAGE_SIZE] SECMEM; /* global structure for slice context storation */
static bool slice_ctx_is_init __unused = false;						/* deprecated */

static struct mutex slice_mutex __unused;			  /* deprecated */
static unsigned int slice_spinlock = SPINLOCK_UNLOCK; // https://github.com/OP-TEE/optee_os/issues/4906#issuecomment-937698775

/* Secure Memory */
static unsigned int slice_mmu_spinlock = SPINLOCK_UNLOCK;
static page_desc_t secure_page_desc[NUM_PAGE_DESC_ENTRIES] SECMEM;

/* get secure memory lock */
static inline uint32_t MMULock_Acquire(void)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&slice_mmu_spinlock);

	return exceptions;
}

/* release secure memory lock */
static inline void MMULock_Release(uint32_t exceptions)
{
	cpu_spin_unlock_xrestore(&slice_mmu_spinlock, exceptions);
}

/* allocate slice_xlat_tables */
static uint64_t *core_mmu_slice_xlat_table_alloc(struct mmu_partition *prtn, int entry_idx)
{
	uint64_t *new_table = NULL;

	if (prtn->slice_xlat_tables_used[entry_idx] >= MAX_XLAT_TABLES)
	{
		EMSG("[%d] %u xlat tables exhausted", entry_idx, MAX_XLAT_TABLES);
		return NULL;
	}

	new_table = slice_xlat_tables[entry_idx][prtn->slice_xlat_tables_used[entry_idx]++];

	DMSG("[%d] slice xlat tables used %u / %u", entry_idx, prtn->slice_xlat_tables_used[entry_idx], MAX_XLAT_TABLES);

	return new_table;
}

/* copy memory mappings to slice_table from default partition */
static bool core_init_mmu_prtn_copy_slice_table(struct mmu_partition *prtn, int entry_idx)
{
	struct core_mmu_table_info l1_tbl_info, l2_tbl_info, l3_tbl_info;
	uint64_t *l1_tbl, *l2_tbl, *l3_tbl;
	vaddr_t l1_va, l2_va, l3_va;
	int level = CORE_MMU_BASE_TABLE_LEVEL;
	unsigned int l0_idx, l1_idx, l2_idx;
	paddr_t pa;
	uint32_t attr;
	uint64_t *slice_l1_tbl, *slice_l2_tbl, *slice_l3_tbl;

	// restore the base table
	prtn->base_tables = base_xlation_table;

	// level 1
	core_mmu_find_table(prtn, 0, level, &l1_tbl_info);
	l1_tbl = l1_tbl_info.table;
	l1_va = l1_tbl_info.va_base;
	// create slice L0 table
	slice_l1_tbl = prtn->slice_base_tables[entry_idx][0][get_core_pos()];
	for (l0_idx = 0; l0_idx < l1_tbl_info.num_entries; l0_idx++) // traverse all memory mappings
	{
		core_mmu_get_entry(&l1_tbl_info, l0_idx, &pa, &attr);
		if (pa != 0) // physical address is not null
		{
			if (attr & TEE_MATTR_TABLE) // entry attribute is page table page
			{
				// level 2
				core_mmu_find_table(prtn, l1_va, level + 1, &l2_tbl_info);
				l2_tbl = l2_tbl_info.table;
				l2_va = l2_tbl_info.va_base;
				// create slice_l2_tbl
				slice_l2_tbl = core_mmu_slice_xlat_table_alloc(prtn, entry_idx);
				if (slice_l2_tbl == NULL)
				{
					return false;
				}
				slice_l1_tbl[l0_idx] = virt_to_phys(slice_l2_tbl) | TABLE_DESC;
				for (l1_idx = 0; l1_idx < l2_tbl_info.num_entries; l1_idx++)
				{
					core_mmu_get_entry(&l2_tbl_info, l1_idx, &pa, &attr);
					if (pa != 0) // physical address is not null
					{
						if (attr & TEE_MATTR_TABLE) // entry attribute is page table page
						{
							// level 3
							core_mmu_find_table(prtn, l2_va, level + 2, &l3_tbl_info);
							l3_tbl = l3_tbl_info.table;
							l3_va = l3_tbl_info.va_base;
							// create slice_l3_tbl
							slice_l3_tbl = core_mmu_slice_xlat_table_alloc(prtn, entry_idx);
							if (slice_l3_tbl == NULL)
							{
								return false;
							}
							slice_l2_tbl[l1_idx] = virt_to_phys(slice_l3_tbl) | TABLE_DESC;
							for (l2_idx = 0; l2_idx < l3_tbl_info.num_entries; l2_idx++)
							{
								core_mmu_get_entry(&l3_tbl_info, l2_idx, &pa, &attr);
								if (pa != 0) // physical address is not null
								{
									if (attr & TEE_MATTR_TABLE)
									{
										EMSG(RED("Last level can not be a table @ 0x%lx (0x%x)"), pa, attr);
									}
									else // page table is memory page
									{
										slice_l3_tbl[l2_idx] = l3_tbl[l2_idx];
									}
								}
								l3_va += BIT64(l3_tbl_info.shift);
							}
						}
						else // page table is memory page
						{
							slice_l2_tbl[l1_idx] = l2_tbl[l1_idx];
						}
					}
					l2_va += BIT64(l2_tbl_info.shift);
				}
			}
			else // page table is memory page
			{
				slice_l1_tbl[l0_idx] = l1_tbl[l0_idx];
			}
		}
		l1_va += BIT64(l1_tbl_info.shift);
	}

	return true;
}

static int get_ctx_table_idx(int entry_idx)
{
	uint32_t exceptions;
	int table_idx = -1;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);

	table_idx = global_slice_table_ctx[entry_idx].table_idx;

	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	return table_idx;
}

static void set_slice_table_allocated(int entry_idx)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);

	global_slice_table_ctx[entry_idx].table_allocated = 1;

	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);
}

static void set_slice_table_enabled(int entry_idx)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);

	global_slice_table_ctx[entry_idx].table_enabled = 1;

	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);
}

/* allocate and sync slice tables */
static void alloc_and_map_slice_tables(struct mmu_partition *prtn, int table_idx)
{
	size_t n;
#ifdef LOG_CYCLES
	uint64_t start_cycle, end_cycle;
#endif // LOG_CYCLES

#ifdef LOG_CYCLES
	start_cycle = rdtsc();
#endif // LOG_CYCLES

	core_init_mmu_prtn_copy_slice_table(prtn, table_idx);

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
	{
		if (n == get_core_pos())
			continue;

		memcpy(prtn->slice_base_tables[table_idx][0][n],
			   prtn->slice_base_tables[table_idx][0][get_core_pos()],
			   XLAT_ENTRY_SIZE * NUM_BASE_LEVEL_ENTRIES);
	}

#ifdef LOG_CYCLES
	end_cycle = rdtsc();
	cycles_in_ta_initialization += (end_cycle - start_cycle);
#endif // LOG_CYCLES
}

/* cleanup slice table structure */
static void cleanup_slice_tables(struct mmu_partition *prtn, int entry_idx)
{
	prtn->slice_xlat_tables_used[entry_idx] = 0;
	// dont need to cleanup tables to remain the kernel mappings
}

/* clear slice context entry */
static void clear_slice_ctx_entry(int entry_idx)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	memset(global_slice_table_ctx[entry_idx].uuid, 0, UUID_STR_LENGTH);
	memset(global_slice_table_ctx[entry_idx].sess_info, 0, sizeof(global_slice_table_ctx[entry_idx].sess_info));
	global_slice_table_ctx[entry_idx].table_idx = -1;
	global_slice_table_ctx[entry_idx].table_allocated = 0;
	global_slice_table_ctx[entry_idx].table_enabled = 0;
	global_slice_table_ctx[entry_idx].refcnt = 0;
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);
}

/* get uuid string from optee_msg_arg */
static void get_uuid_from_params(struct optee_msg_arg *arg, char *uuid_str)
{
	TEE_UUID uuid;

	if (arg->cmd != OPTEE_MSG_CMD_OPEN_SESSION)
	{
		EMSG(RED("Error calling get_uuid_from_params"));
		return;
	}

	tee_uuid_from_octets(&uuid, (void *)&arg->params[0].u.value);
	// translate struct uuid to str format
	snprintf(uuid_str, UUID_STR_LENGTH, "%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 "-%02" PRIx8 "%02" PRIx8 "-%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8,
			 uuid.timeLow, uuid.timeMid, uuid.timeHiAndVersion,
			 uuid.clockSeqAndNode[0], uuid.clockSeqAndNode[1], uuid.clockSeqAndNode[2], uuid.clockSeqAndNode[3],
			 uuid.clockSeqAndNode[4], uuid.clockSeqAndNode[5], uuid.clockSeqAndNode[6], uuid.clockSeqAndNode[7]);
}

/* check if table_idx is allocated before */
static int slice_table_is_allocated(int entry_idx)
{
	uint32_t exceptions;
	int table_allocated = 0;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);

	table_allocated = global_slice_table_ctx[entry_idx].table_allocated;

	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	return 1 == table_allocated;
}

/* check if table_idx is enabled before */
static int slice_table_is_enabled(int entry_idx)
{
	uint32_t exceptions;
	int table_enabled = 0;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);

	table_enabled = global_slice_table_ctx[entry_idx].table_enabled;

	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	return 1 == table_enabled;
}

/* update slice context uuid */
static int update_ctx_uuid(char *uuid_str)
{
	uint32_t exceptions;
	int entry_idx = -1;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++) // if uuid is stored before
	{
		if (global_slice_table_ctx[i].refcnt && 0 == memcmp(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH))
		{
			// session_id & refcnt will be updated in exit_gate;
			memcpy(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH);
			global_slice_table_ctx[i].table_idx = i; // only used when slice table is enabled
			for (int j = 0; j < SESS_STORAGE_SIZE; j++)
			{
				if (global_slice_table_ctx[i].sess_info[j].is_opened == 0)
				{
					global_slice_table_ctx[i].sess_info[j].is_opened = 1;
					entry_idx = i;
					goto out;
				}
			}
			EMSG(RED("[SLICE] Session out of usage"));
			goto error_out;
		}
	}

	for (int i = 0; i < CTX_STORAGE_SIZE; i++) // if uuid is never stored
	{
		if (global_slice_table_ctx[i].refcnt)
		{
			continue;
		}
		else
		{
			// session_id & refcnt will be updated in exit_gate;
			memcpy(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH);
			global_slice_table_ctx[i].table_idx = i; // only used when slice table is enabled
			for (int j = 0; j < SESS_STORAGE_SIZE; j++)
			{
				if (global_slice_table_ctx[i].sess_info[j].is_opened == 0)
				{
					global_slice_table_ctx[i].sess_info[j].is_opened = 1;
					entry_idx = i;
					goto out;
				}
			}
			EMSG(RED("[SLICE] Session out of usage"));
			goto error_out;
		}
	}
	EMSG(RED("[SLICE] Context out of usage"));

error_out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	assert(entry_idx == -1);
	return entry_idx;

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	return entry_idx;
}

/* get uuid string from slice context by session id */
static int get_uuid_by_session_id(struct optee_msg_arg *arg, char *uuid_str)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (global_slice_table_ctx[i].refcnt) // refcnt at least is 1
		{
			for (int j = 0; j < SESS_STORAGE_SIZE; j++)
			{
				if (global_slice_table_ctx[i].sess_info[j].sess_id == arg->session)
				{
					memcpy(uuid_str, global_slice_table_ctx[i].uuid, UUID_STR_LENGTH);
					goto out;
				}
			}
		}
	}
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	EMSG(RED("[SLICE] UUID not found"));
	return -1;

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	return 0;
}

/* get slice table entry index from slice context by uuid string */
static int get_entry_idx_by_uuid(char *uuid_str)
{
	uint32_t exceptions;
	int entry_idx = -1;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (0 == memcmp(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH))
		{
			entry_idx = global_slice_table_ctx[i].table_idx;
			goto out;
		}
	}
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	EMSG(RED("[SLICE] Context not found"));
	assert(entry_idx == -1);
	return entry_idx;

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);
	return entry_idx;
}

/* update session id in slice context */
static int update_session_id(struct optee_msg_arg *arg)
{
	uint32_t exceptions;
	char uuid_str[UUID_STR_LENGTH];

	get_uuid_from_params(arg, uuid_str); // Can not get uuid every time

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);

	if (0 == arg->session)
	{
		for (int i = 0; i < CTX_STORAGE_SIZE; i++)
		{
			if (0 == memcmp(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH))
			{
				for (int j = 0; j < SESS_STORAGE_SIZE; j++)
				{
					if (1 == global_slice_table_ctx[i].sess_info[j].is_opened && 0 == global_slice_table_ctx[i].sess_info[j].sess_id)
					{
						global_slice_table_ctx[i].sess_info[j].is_opened = 0; // open session failed, clear is_opened flag
						goto out;
					}
				}
			}
		}
	}

	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (0 == memcmp(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH))
		{
			for (int j = 0; j < SESS_STORAGE_SIZE; j++)
			{
				if (1 == global_slice_table_ctx[i].sess_info[j].is_opened && 0 == global_slice_table_ctx[i].sess_info[j].sess_id)
				{
					global_slice_table_ctx[i].sess_info[j].sess_id = arg->session; // update in exit_gate
					global_slice_table_ctx[i].refcnt++;
					goto out;
				}
			}
		}
	}
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	EMSG(RED("[SLICE] Not found"));
	return -1;

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	return 0;
}

/* get slice table entry index from slice context by session id */
static int get_entry_idx_by_session_id(struct optee_msg_arg *arg)
{
	uint32_t exceptions;
	int entry_idx = -1;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (global_slice_table_ctx[i].refcnt)
		{
			for (int j = 0; j < SESS_STORAGE_SIZE; j++)
			{
				if (arg->session == global_slice_table_ctx[i].sess_info[j].sess_id)
				{
					entry_idx = i;
					goto out;
				}
			}
		}
	}
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	// EMSG(RED("[SLICE] Context not found"));
	assert(entry_idx == -1);
	return entry_idx;

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);
	return entry_idx;
}

/* remove session id in slice context */
static int remove_session_id(struct optee_msg_arg *arg)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (global_slice_table_ctx[i].refcnt)
		{
			for (int j = 0; j < SESS_STORAGE_SIZE; j++)
			{
				if (arg->session == global_slice_table_ctx[i].sess_info[j].sess_id)
				{
					global_slice_table_ctx[i].sess_info[j].sess_id = 0;
					global_slice_table_ctx[i].sess_info[j].is_opened = 0;
					global_slice_table_ctx[i].refcnt--;
					goto out;
				}
			}
		}
	}
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	EMSG(RED("[SLICE] Context not found"));
	return -1;

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);
	return 0;
}

/* get refcnt from slice context by uuid string */
static int get_ctx_refcnt_by_uuid(char *uuid_str)
{
	uint32_t exceptions;
	int refcnt = -1;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (0 == memcmp(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH))
		{
			refcnt = global_slice_table_ctx[i].refcnt;
			goto out;
		}
	}
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	EMSG(RED("[SLICE] Context not found"));
	assert(refcnt == -1);
	return refcnt;

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);
	return refcnt;
}

/* check if session is opened */
static int no_session_is_opened(char *uuid_str)
{
	uint32_t exceptions;
	int result = 1;

	exceptions = cpu_spin_lock_xsave(&slice_spinlock);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (0 == memcmp(global_slice_table_ctx[i].uuid, uuid_str, UUID_STR_LENGTH))
		{
			for (int j = 0; j < SESS_STORAGE_SIZE; j++)
			{
				if (global_slice_table_ctx[i].sess_info[j].is_opened)
				{
					result = 0;
					goto out;
				}
			}
		}
	}

out:
	cpu_spin_unlock_xrestore(&slice_spinlock, exceptions);

	return result;
}

/* set memory page read only */
static void __unused set_page_ro(struct core_mmu_table_info *tbl_info, unsigned int idx, paddr_t pa, uint32_t old_attr)
{
	uint32_t new_attr;

	/* Ignore if page is not table */
	if (!(old_attr & TEE_MATTR_TABLE))
		return;

	new_attr = (old_attr & ~TEE_MATTR_PROT_MASK) | TEE_MATTR_PR;

	core_mmu_set_entry(tbl_info, idx, pa, new_attr);
}

/* get pages decriptor */
static page_desc_t *get_page_desc_ptr(unsigned long pa)
{
	unsigned long idx = (pa & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
	int in_range = 1;

	if (0 == pa)
	{
		return 0;
	}

	if (!in_range)
	{
		DMSG("[Out of range] get_page_desc_ptr: 0x%lx", pa);
		// non-secure page
		return NULL;
	}

	// secure_page_desc[idx].index = idx;

	return secure_page_desc + idx;
}

/* original page table page tagging */
static void declare_page_table_entries(struct mmu_partition *prtn)
{
	page_desc_t *current_page_desc;
	paddr_t pa;
	uint32_t attr;
	unsigned long idx;
	struct core_mmu_table_info l1_tbl_info, l2_tbl_info, l3_tbl_info;
	uint64_t *l1_tbl, *l2_tbl, *l3_tbl;
	vaddr_t l1_va, l2_va, l3_va;
	int level = CORE_MMU_BASE_TABLE_LEVEL;
	unsigned int l0_idx, l1_idx, l2_idx;

	core_mmu_find_table(prtn, 0, level, &l1_tbl_info);
	l1_tbl = l1_tbl_info.table;
	l1_va = l1_tbl_info.va_base;
	// L1 entry point to page table page
	current_page_desc = get_page_desc_ptr(virt_to_phys(l1_tbl));
	current_page_desc->type = PG_L1; /* Set the page type to L1 */
	current_page_desc->user = 0;	 /* Set the priv flag to kernel */
	current_page_desc->count = 1;
	for (l0_idx = 0; l0_idx < l1_tbl_info.num_entries; l0_idx++)
	{
		core_mmu_get_entry(&l1_tbl_info, l0_idx, &pa, &attr);
		if (0 != pa)
		{
			if (attr & TEE_MATTR_TABLE)
			{
				core_mmu_find_table(prtn, l1_va, level + 1, &l2_tbl_info);
				l2_tbl = l2_tbl_info.table;
				l2_va = l2_tbl_info.va_base;
				// L2 entry point to page table page
				current_page_desc = get_page_desc_ptr(virt_to_phys(l2_tbl));
				current_page_desc->type = PG_L2; /* Set the page type to L2 */
				current_page_desc->user = 0;
				current_page_desc->count = 1;
				for (l1_idx = 0; l1_idx < l2_tbl_info.num_entries; l1_idx++)
				{
					core_mmu_get_entry(&l2_tbl_info, l1_idx, &pa, &attr);
					if (0 != pa)
					{
						if (attr & TEE_MATTR_TABLE)
						{
							core_mmu_find_table(prtn, l2_va, level + 2, &l3_tbl_info);
							l3_tbl = l3_tbl_info.table;
							l3_va = l3_tbl_info.va_base;
							// L3 entry point to page table page
							current_page_desc = get_page_desc_ptr(virt_to_phys(l3_tbl));
							current_page_desc->type = PG_L3; /* Set the page type to L3 */
							current_page_desc->user = 0;
							current_page_desc->count = 1;
							for (l2_idx = 0; l2_idx < l3_tbl_info.num_entries; l2_idx++)
							{
								core_mmu_get_entry(&l3_tbl_info, l2_idx, &pa, &attr);
								if (0 != pa)
								{
									if (attr & TEE_MATTR_TABLE)
									{
										EMSG(RED("Last level can not be a table @ 0x%lx (0x%x)"), pa, attr);
									}
									else
									{
										current_page_desc = get_page_desc_ptr(pa);
										current_page_desc->type = PG_KDATA;
										current_page_desc->user = 0;
										current_page_desc->count = 1;
									}
								}
								l3_va += BIT64(l3_tbl_info.shift);
							}
						}
						else
						{
							// L2 entry point to 2MB page
							idx = (pa & L2_PAGE_IDX_MASK) / PAGE_SIZE; // offset:1<<21
							secure_page_desc[idx].type = PG_KDATA;
							secure_page_desc[idx].user = 0;
							secure_page_desc[idx].count = 1;
						}
					}
					l2_va += BIT64(l2_tbl_info.shift);
				}
			}
			else
			{
				// L1 entry ponit to 1GB page
				idx = (pa & L1_PAGE_IDX_MASK) / PAGE_SIZE; // offset:1<<30
				secure_page_desc[idx].type = PG_KDATA;
				secure_page_desc[idx].user = 0;
				secure_page_desc[idx].count = 1;
			}
		}
		l1_va += BIT64(l1_tbl_info.shift);
	}
}

/* slice page table page tagging */
static void declare_slice_page_table_entries(struct mmu_partition *prtn, int table_idx, char *uuid_str)
{
	page_desc_t *current_page_desc;
	paddr_t pa;
	uint32_t attr;
	unsigned long idx;
	struct core_mmu_table_info l1_tbl_info, l2_tbl_info, l3_tbl_info;
	uint64_t *l1_tbl, *l2_tbl, *l3_tbl;
	vaddr_t l1_va, l2_va, l3_va;
	int level = CORE_MMU_BASE_TABLE_LEVEL;
	unsigned int l0_idx, l1_idx, l2_idx;

	slice_core_mmu_find_table(prtn, 0, level, &l1_tbl_info, table_idx);
	l1_tbl = l1_tbl_info.table;
	l1_va = l1_tbl_info.va_base;
	// L1 entry point to page table page
	current_page_desc = get_page_desc_ptr(virt_to_phys(l1_tbl));
	current_page_desc->type = PG_L1; /* Set the page type to L1 */
	current_page_desc->user = 0;	 /* Set the priv flag to kernel */
	current_page_desc->count = 1;
	memcpy(current_page_desc->uuid, uuid_str, UUID_STR_LENGTH);
	for (l0_idx = 0; l0_idx < l1_tbl_info.num_entries; l0_idx++)
	{
		core_mmu_get_entry(&l1_tbl_info, l0_idx, &pa, &attr);
		if (0 != pa)
		{
			if (attr & TEE_MATTR_TABLE)
			{
				set_page_ro(&l1_tbl_info, l0_idx, pa, attr); /* l2 table */
				slice_core_mmu_find_table(prtn, l1_va, level + 1, &l2_tbl_info, table_idx);
				l2_tbl = l2_tbl_info.table;
				l2_va = l2_tbl_info.va_base;
				// L2 entry point to page table page
				current_page_desc = get_page_desc_ptr(virt_to_phys(l2_tbl));
				current_page_desc->type = PG_L2; /* Set the page type to L2 */
				current_page_desc->user = 0;
				current_page_desc->count = 1;
				memcpy(current_page_desc->uuid, uuid_str, UUID_STR_LENGTH);
				for (l1_idx = 0; l1_idx < l2_tbl_info.num_entries; l1_idx++)
				{
					core_mmu_get_entry(&l2_tbl_info, l1_idx, &pa, &attr);
					if (0 != pa)
					{
						if (attr & TEE_MATTR_TABLE)
						{
							set_page_ro(&l2_tbl_info, l1_idx, pa, attr); /* l3 table */
							slice_core_mmu_find_table(prtn, l2_va, level + 2, &l3_tbl_info, table_idx);
							l3_tbl = l3_tbl_info.table;
							l3_va = l3_tbl_info.va_base;
							// L3 entry point to page table page
							current_page_desc = get_page_desc_ptr(virt_to_phys(l3_tbl));
							current_page_desc->type = PG_L3; /* Set the page type to L3 */
							current_page_desc->user = 0;
							current_page_desc->count = 1;
							memcpy(current_page_desc->uuid, uuid_str, UUID_STR_LENGTH);
							for (l2_idx = 0; l2_idx < l3_tbl_info.num_entries; l2_idx++)
							{
								core_mmu_get_entry(&l3_tbl_info, l2_idx, &pa, &attr);
								if (0 != pa)
								{
									if (attr & TEE_MATTR_TABLE)
									{
										EMSG(RED("Last level can not be a table @ 0x%lx (0x%x)"), pa, attr);
									}
									else /* set user code */
									{
										current_page_desc = get_page_desc_ptr(pa);
										// DMSG("pa: 0x%lx, current_page_desc->type: %d", pa, current_page_desc->type);
										if (PG_UNUSED == current_page_desc->type)
										{
											DMSG("set UDATA @ 0x%lx", pa);
											current_page_desc->type = PG_UDATA;
											current_page_desc->user = 0;
											current_page_desc->count = 1;
											memcpy(current_page_desc->uuid, uuid_str, UUID_STR_LENGTH);
										}
									}
								}
								l3_va += BIT64(l3_tbl_info.shift);
							}
						}
						else
						{
							// L2 entry point to 2MB page
							idx = (pa & L2_PAGE_IDX_MASK) / PAGE_SIZE; // offset:1<<21
							secure_page_desc[idx].type = PG_KDATA;
							secure_page_desc[idx].user = 0;
							secure_page_desc[idx].count = 1;
							memcpy(secure_page_desc[idx].uuid, uuid_str, UUID_STR_LENGTH);
						}
					}
					l2_va += BIT64(l2_tbl_info.shift);
				}
			}
			else
			{
				// L1 entry ponit to 1GB page
				idx = (pa & L1_PAGE_IDX_MASK) / PAGE_SIZE; // offset:1<<30
				secure_page_desc[idx].type = PG_KDATA;
				secure_page_desc[idx].user = 0;
				secure_page_desc[idx].count = 1;
				memcpy(secure_page_desc[idx].uuid, uuid_str, UUID_STR_LENGTH);
			}
		}
		l1_va += BIT64(l1_tbl_info.shift);
	}
}

/* declare kernel text section type */
static void declare_kernel_code_pages(void)
{
	/* Get pointers for the pages */
	unsigned long idx;
	uintptr_t page;
	uintptr_t start_text_page = virt_to_phys((void *)__text_start) & PG_FRAME;
	uintptr_t end_text_page = virt_to_phys((void *)__text_end) & PG_FRAME;

	/*
	 * Scan through each page in the text segment.  Note that it is a code page,
	 * and make the page read-only within the page table.
	 */
	for (page = start_text_page; page < end_text_page; page += PAGE_SIZE)
	{
		/* Mark the page as both a code page and kernel level */
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_KCODE;
		secure_page_desc[idx].user = 0;
	}
}

/* declare secure memory section type */
static void declare_secmem_pages(void)
{
	unsigned long idx;
	unsigned long page;
	unsigned long start_secmem_page = virt_to_phys((void *)__sec_mem_start) & PG_FRAME;
	unsigned long end_secmem_page = virt_to_phys((void *)__sec_mem_end) & PG_FRAME;

	for (page = start_secmem_page; page < end_secmem_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SECMEM;
		secure_page_desc[idx].user = 0;
	}
}

/* declare slice section types */
static void declare_slice_pages(void)
{
	unsigned long idx, page;
	unsigned long start_lib1_page = virt_to_phys((void *)__vcore_unpg_rx_lib1_start) & PG_FRAME;
	unsigned long end_lib1_page = virt_to_phys((void *)__vcore_unpg_rx_lib1_end) & PG_FRAME;
	unsigned long start_lib2_page = virt_to_phys((void *)__vcore_unpg_rx_lib2_start) & PG_FRAME;
	unsigned long end_lib2_page = virt_to_phys((void *)__vcore_unpg_rx_lib2_end) & PG_FRAME;
	unsigned long start_lib3_page = virt_to_phys((void *)__vcore_unpg_rx_lib3_start) & PG_FRAME;
	unsigned long end_lib3_page = virt_to_phys((void *)__vcore_unpg_rx_lib3_end) & PG_FRAME;
	unsigned long start_lib4_page = virt_to_phys((void *)__vcore_unpg_rx_lib4_start) & PG_FRAME;
	unsigned long end_lib4_page = virt_to_phys((void *)__vcore_unpg_rx_lib4_end) & PG_FRAME;
	unsigned long start_lib5_page = virt_to_phys((void *)__vcore_unpg_rx_lib5_start) & PG_FRAME;
	unsigned long end_lib5_page = virt_to_phys((void *)__vcore_unpg_rx_lib5_end) & PG_FRAME;
	unsigned long start_lib6_page = virt_to_phys((void *)__vcore_unpg_rx_lib6_start) & PG_FRAME;
	unsigned long end_lib6_page = virt_to_phys((void *)__vcore_unpg_rx_lib6_end) & PG_FRAME;
	unsigned long start_lib7_page = virt_to_phys((void *)__vcore_unpg_rx_lib7_start) & PG_FRAME;
	unsigned long end_lib7_page = virt_to_phys((void *)__vcore_unpg_rx_lib7_end) & PG_FRAME;
	unsigned long start_lib8_page = virt_to_phys((void *)__vcore_unpg_rx_lib8_start) & PG_FRAME;
	unsigned long end_lib8_page = virt_to_phys((void *)__vcore_unpg_rx_lib8_end) & PG_FRAME;
	unsigned long start_lib9_page = virt_to_phys((void *)__vcore_unpg_rx_lib9_start) & PG_FRAME;
	unsigned long end_lib9_page = virt_to_phys((void *)__vcore_unpg_rx_lib9_end) & PG_FRAME;
	unsigned long start_lib10_page = virt_to_phys((void *)__vcore_unpg_rx_lib10_start) & PG_FRAME;
	unsigned long end_lib10_page = virt_to_phys((void *)__vcore_unpg_rx_lib10_end) & PG_FRAME;

	for (page = start_lib1_page; page < end_lib1_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB1;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib2_page; page < end_lib2_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB2;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib3_page; page < end_lib3_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB3;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib4_page; page < end_lib4_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB4;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib5_page; page < end_lib5_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB5;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib6_page; page < end_lib6_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB6;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib7_page; page < end_lib7_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB7;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib8_page; page < end_lib8_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB8;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib9_page; page < end_lib9_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB9;
		secure_page_desc[idx].user = 0;
	}

	for (page = start_lib10_page; page < end_lib10_page; page += PAGE_SIZE)
	{
		idx = (page & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
		secure_page_desc[idx].type = PG_SLICE_LIB10;
		secure_page_desc[idx].user = 0;
	}
}

/* init page mapping */
SECURE_WRAPPER_NO_INTERRUPT(void, init_memory_tagging, void)
{
	uint32_t exceptions;

	exceptions = MMULock_Acquire();

	/* Walk the kernel page tables and initialize the secure_page_desc */
	declare_page_table_entries(ptr_default_partition);

	/* Identify kernel code pages and intialize the descriptors */
	declare_kernel_code_pages();

	/* Make all SuperSpace pages read-only */
	declare_secmem_pages();

	/* Declare slice sections pages */
	declare_slice_pages();

	MMULock_Release(exceptions);
}

/* declare slice page mapping */
SECURE_WRAPPER(void, slice_memory_tagging, int table_idx, char *uuid_str)
{
	uint32_t exceptions;
#ifdef LOG_CYCLES
	uint64_t start_cycle, end_cycle;
#endif // LOG_CYCLES

	exceptions = MMULock_Acquire();

#ifdef LOG_CYCLES
	start_cycle = rdtsc();
#endif // LOG_CYCLES

	/* Walk the slice kernel page tables and the secure_page_desc */
	declare_slice_page_table_entries(ptr_default_partition, table_idx, uuid_str);

#ifdef LOG_CYCLES
	end_cycle = rdtsc();
	cycles_in_ta_initialization += (end_cycle - start_cycle);
#endif // LOG_CYCLES

	MMULock_Release(exceptions);
}

/* check if slice tagging is enabled */
int is_slice_tagging_enabled(struct core_mmu_table_info *tbl_info)
{
	uint32_t exceptions;
	page_desc_t *current_page_desc;
	int is_aval = 0;

	exceptions = MMULock_Acquire();

	current_page_desc = get_page_desc_ptr(virt_to_phys(tbl_info->table));
	is_aval = PG_UNUSED != current_page_desc->type;

	MMULock_Release(exceptions);

	return is_aval;
}

/* check new table tagging */
SECURE_WRAPPER(void, slice_set_page_table_tagging, paddr_t pa, unsigned level)
{
	uint32_t exceptions;
	page_desc_t *current_page_desc;

	exceptions = MMULock_Acquire();

	current_page_desc = get_page_desc_ptr(pa);

	/* Setup metadata tracking for this new page */
	switch (level)
	{
	case 1:
		if (PG_L1 != current_page_desc->type)
		{
			current_page_desc->type = PG_L1;
		}
		break;
	case 2:
		if (PG_L2 != current_page_desc->type)
		{
			current_page_desc->type = PG_L2;
		}
		break;
	case 3:
		if (PG_L3 != current_page_desc->type)
		{
			current_page_desc->type = PG_L3;
		}
		break;
	default:
		DMSG("Unknown level %d", level);
		break;
	}

	MMULock_Release(exceptions);
}

/* get slice sections bitmap by uuid */
static uint16_t get_slice_bitmap_by_uuid(char *uuid_str)
{

	if (0 == memcmp(uuid_str, uuid_acipher, UUID_STR_LENGTH))
	{
		return CRYPTO_LIB_BITS;
	}
	else if (0 == memcmp(uuid_str, uuid_secure_storage, UUID_STR_LENGTH))
	{
		return STORAGE_LIB_BITS;
	}
	else if (0 == memcmp(uuid_str, uuid_wallet, UUID_STR_LENGTH))
	{
		return PAY_LIB_BITS;
	}
	else if (0 == memcmp(uuid_str, uuid_hotp, UUID_STR_LENGTH))
	{
		return IDENTITY_LIB_BITS;
	}
	else if (0 == memcmp(uuid_str, uuid_clearkey, UUID_STR_LENGTH))
	{
		return DRM_LIB_BITS;
	}
	else
	{
		return 0;
	}
}

/* check if the update is valid */
static int page_table_update_is_valid(paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa)
{
	char uuid_str[37];
	uint16_t slice_bitmap = -1;
	page_desc_t *table_desc = get_page_desc_ptr(table_pa);
	page_desc_t *orig_desc __unused = get_page_desc_ptr(orig_pa);
	page_desc_t *new_desc = get_page_desc_ptr(new_pa);

	// check libs access legality & update table entry
	if (SLICE_BITS_COUNT + 1 > (new_desc->type - SLICE_SHIFT_BITS))
	{
		memcpy(uuid_str, table_desc->uuid, UUID_STR_LENGTH);
		slice_bitmap = get_slice_bitmap_by_uuid(uuid_str);
		if (slice_bitmap & (1 << (new_desc->type - SLICE_SHIFT_BITS)))
		{
			;
		}
		else
		{
			DMSG(RED("[SLICE] Invalid access @ 0x%lx (type: %d) -> 0x%lx (type: %d)"), table_pa, table_desc->type, new_pa, new_desc->type);
			return SLICE_MEMORY_INVALID;
		}
	}

	// check table type
	if (PG_L1 == table_desc->type)
	{
		if (PG_L2 == new_desc->type || PG_KDATA == new_desc->type || PG_KCODE == new_desc->type)
		{
			;
		}
		else
		{
			DMSG(RED("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)"), table_pa, table_desc->type, new_pa, new_desc->type);
			return SLICE_MEMORY_INVALID;
		}
	}
	else if (PG_L2 == table_desc->type)
	{
		if (PG_L3 == new_desc->type || PG_KDATA == new_desc->type || PG_KCODE == new_desc->type)
		{
			;
		}
		else
		{
			DMSG(RED("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)"), table_pa, table_desc->type, new_pa, new_desc->type);
			return SLICE_MEMORY_INVALID;
		}
	}
	else if (PG_L3 == table_desc->type)
	{
		if (PG_KDATA == new_desc->type || PG_KCODE == new_desc->type)
		{
			;
		}
		else if (PG_UDATA == new_desc->type || PG_UCODE == new_desc->type)
		{
			;
		}
		else
		{
			if (PG_UNUSED == new_desc->type) /* Update user page tagging */
			{
				unsigned long idx;
				idx = (new_pa & PAGE_DESC_IDX_MASK) / PAGE_SIZE;
				secure_page_desc[idx].type = PG_UDATA;
				secure_page_desc[idx].user = 1;
			}
			else
			{
				DMSG(RED("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)"), table_pa, table_desc->type, new_pa, new_desc->type);
				return SLICE_MEMORY_INVALID;
			}
		}
	}
	else
	{
		DMSG(RED("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)"), table_pa, table_desc->type, new_pa, new_desc->type);
		return SLICE_MEMORY_INVALID;
	}

	return SLICE_MEMORY_AVAILABLE;
}

/* update new memory page refcnt */
static void update_new_page_data(paddr_t table_pa, paddr_t orig_pa __unused, paddr_t new_pa)
{
	page_desc_t *table_desc __unused = get_page_desc_ptr(table_pa);
	page_desc_t *orig_desc __unused = get_page_desc_ptr(orig_pa);
	page_desc_t *new_desc = get_page_desc_ptr(new_pa);

	if (table_pa & 0x1)
	{
		if (!(new_desc->count < ((1u << 13) - 1)))
		{
			DMSG("overflow for the mapping count");
			return;
		}
		new_desc->count++;
	}
}

/* update orginal memory page refcnt */
static void update_orig_page_data(paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa)
{
	page_desc_t *table_desc __unused = get_page_desc_ptr(table_pa);
	page_desc_t *orig_desc = get_page_desc_ptr(orig_pa);
	page_desc_t *new_desc __unused = get_page_desc_ptr(new_pa);

	if ((table_pa & 0x1) && (orig_desc->count))
	{
		--(orig_desc->count);
	}
}

/* do secure memory attribute update */
static void update_secure_attr(paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa, uint32_t attr)
{
	page_desc_t *table_desc __unused = get_page_desc_ptr(table_pa);
	page_desc_t *orig_desc __unused = get_page_desc_ptr(orig_pa);
	page_desc_t *new_desc __unused = get_page_desc_ptr(new_pa);

	// Update counter in every memory pages
	if (new_pa != orig_pa)
	{
		update_orig_page_data(table_pa, orig_pa, new_pa);
		update_new_page_data(table_pa, orig_pa, new_pa);
	}
	else if ((table_pa & 0x1) && (attr & TEE_MATTR_VALID_BLOCK) == 0)
	{
		update_orig_page_data(table_pa, orig_pa, new_pa);
	}
	else if (((table_pa & 0x1) == 0) && (attr & TEE_MATTR_VALID_BLOCK))
	{
		update_new_page_data(table_pa, orig_pa, new_pa);
	}
	else
	{
		// DMSG("No need to update");
	}
}

/* update memory mapping */
static void do_mmu_update(struct core_mmu_table_info *tbl_info, unsigned int idx, paddr_t pa, uint32_t attr)
{
	uint64_t *tbl;
	uint64_t desc;

	assert(idx < tbl_info->num_entries);

	tbl = tbl_info->table;
	desc = mattr_to_desc(tbl_info->level, attr);

	// DMSG("Update 0x%lx -> 0x%lx", (uint64_t)(&tbl[idx]), desc | pa);
	tbl[idx] = desc | pa;
}

/* update memory mapping */
SECURE_WRAPPER(void, slice_update_mapping, struct core_mmu_table_info *tbl_info, unsigned int idx, paddr_t pa, uint32_t attr)
{
	uint32_t exceptions;
	paddr_t table_pa = virt_to_phys(tbl_info->table);
	paddr_t orig_pa = *((uint64_t *)tbl_info->table + idx);		/* original memory address */
	paddr_t new_pa = mattr_to_desc(tbl_info->level, attr) | pa; /* new memory address for assigning */
#ifdef LOG_CYCLES
	uint64_t start_cycle, end_cycle;
#endif // LOG_CYCLES

	exceptions = MMULock_Acquire();

#ifdef LOG_CYCLES
	start_cycle = rdtsc();
#endif // LOG_CYCLES

	switch (page_table_update_is_valid(table_pa, orig_pa, new_pa))
	{
	case SLICE_MEMORY_INVALID:
		DMSG("Invalid mmu update!");
		break;
	case SLICE_MEMORY_READ_ONLY:
		DMSG("Read only memory!");
		break;
	case SLICE_MEMORY_AVAILABLE:
		/* direct update */
		update_secure_attr(table_pa, orig_pa, new_pa, attr);
		do_mmu_update(tbl_info, idx, pa, attr);
		break;
	default:
		DMSG("Invalid page update!");
		break;
	}

#ifdef LOG_CYCLES
	end_cycle = rdtsc();
	cycles_in_memory_checking += (end_cycle - start_cycle);
#endif // LOG_CYCLES

	MMULock_Release(exceptions);
}

SECURE_WRAPPER(void, simple_gate, unsigned long arg0)
{
	int result __unused;

	do
	{
		result = arg0 + 0xcafebabe;
	} while (0);
}

void test_secure_gate(void)
{
	uint64_t start_cycle, end_cycle, diff_cycle;

	start_cycle = rdtsc();

	// for (int i = 0; i < 1000000; i++)
	// {
	// 	simple_gate(0x10001);
	// }
	simple_gate(0x10001);

	end_cycle = rdtsc();

	diff_cycle = end_cycle - start_cycle;
	DMSG("gate switch time: %lu cycles", diff_cycle);
}

/* unmap the slice sections by uuid */
static void slice_unmap_page_mappings(char *uuid_str, int table_idx)
{
	uint16_t slice_bitmap = -1;
	vaddr_t lib1_va = (vaddr_t)&__vcore_unpg_rx_lib1_start;
	size_t lib1_s = (size_t)&__vcore_unpg_rx_lib1_size;
	size_t lib1_num_page = lib1_s / SMALL_PAGE_SIZE;
	vaddr_t lib2_va = (vaddr_t)&__vcore_unpg_rx_lib2_start;
	size_t lib2_s = (size_t)&__vcore_unpg_rx_lib2_size;
	size_t lib2_num_page = lib2_s / SMALL_PAGE_SIZE;
	vaddr_t lib3_va = (vaddr_t)&__vcore_unpg_rx_lib3_start;
	size_t lib3_s = (size_t)&__vcore_unpg_rx_lib3_size;
	size_t lib3_num_page = lib3_s / SMALL_PAGE_SIZE;
	vaddr_t lib4_va = (vaddr_t)&__vcore_unpg_rx_lib4_start;
	size_t lib4_s = (size_t)&__vcore_unpg_rx_lib4_size;
	size_t lib4_num_page = lib4_s / SMALL_PAGE_SIZE;
	vaddr_t lib5_va = (vaddr_t)&__vcore_unpg_rx_lib5_start;
	size_t lib5_s = (size_t)&__vcore_unpg_rx_lib5_size;
	size_t lib5_num_page = lib5_s / SMALL_PAGE_SIZE;
	vaddr_t lib6_va = (vaddr_t)&__vcore_unpg_rx_lib6_start;
	size_t lib6_s = (size_t)&__vcore_unpg_rx_lib6_size;
	size_t lib6_num_page = lib6_s / SMALL_PAGE_SIZE;
	vaddr_t lib7_va = (vaddr_t)&__vcore_unpg_rx_lib7_start;
	size_t lib7_s = (size_t)&__vcore_unpg_rx_lib7_size;
	size_t lib7_num_page = lib7_s / SMALL_PAGE_SIZE;
	vaddr_t lib8_va = (vaddr_t)&__vcore_unpg_rx_lib8_start;
	size_t lib8_s = (size_t)&__vcore_unpg_rx_lib8_size;
	size_t lib8_num_page = lib8_s / SMALL_PAGE_SIZE;
	vaddr_t lib9_va = (vaddr_t)&__vcore_unpg_rx_lib9_start;
	size_t lib9_s = (size_t)&__vcore_unpg_rx_lib9_size;
	size_t lib9_num_page = lib9_s / SMALL_PAGE_SIZE;
	vaddr_t lib10_va = (vaddr_t)&__vcore_unpg_rx_lib10_start;
	size_t lib10_s = (size_t)&__vcore_unpg_rx_lib10_size;
	size_t lib10_num_page = lib10_s / SMALL_PAGE_SIZE;

	slice_bitmap = get_slice_bitmap_by_uuid(uuid_str);
	if ((0 == (slice_bitmap & SLICE_LIB1_BIT)))
	{
		slice_core_mmu_unmap_pages(lib1_va, lib1_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB2_BIT)))
	{
		slice_core_mmu_unmap_pages(lib2_va, lib2_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB3_BIT)))
	{
		slice_core_mmu_unmap_pages(lib3_va, lib3_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB4_BIT)))
	{
		slice_core_mmu_unmap_pages(lib4_va, lib4_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB5_BIT)))
	{
		slice_core_mmu_unmap_pages(lib5_va, lib5_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB6_BIT)))
	{
		slice_core_mmu_unmap_pages(lib6_va, lib6_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB7_BIT)))
	{
		slice_core_mmu_unmap_pages(lib7_va, lib7_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB8_BIT)))
	{
		slice_core_mmu_unmap_pages(lib8_va, lib8_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB9_BIT)))
	{
		slice_core_mmu_unmap_pages(lib9_va, lib9_num_page, table_idx);
	}
	if ((0 == (slice_bitmap & SLICE_LIB10_BIT)))
	{
		slice_core_mmu_unmap_pages(lib10_va, lib10_num_page, table_idx);
	}
}

/* initialize slice context structure */
void init_slice_ctx(void)
{
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		clear_slice_ctx_entry(i);
	}
}

/* entry gate for standard smc calls */
void entry_gate_std(struct optee_msg_arg *arg)
{
	int entry_idx = -1;
	uint32_t exceptions;
	uint64_t new_ttbr = 0;
	char uuid_str[UUID_STR_LENGTH];
	int table_idx = -1;
#ifdef LOG_CYCLES
	uint64_t start_cycle, end_cycle;
#endif // LOG_CYCLES

#ifdef LOG_CYCLES
	if (OPTEE_MSG_CMD_OPEN_SESSION == arg->cmd)
	{
		cycles_in_memory_checking = 0;
		cycles_in_ta_initialization = 0;
		cycles_in_ttbr_switching = 0;
	}
#endif // LOG_CYCLES

	// disable external interrupt for get_core_pos
	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

#ifdef LOG_CYCLES
	start_cycle = rdtsc();
#endif // LOG_CYCLES

	// deal with uuid
	if (OPTEE_MSG_CMD_OPEN_SESSION == arg->cmd)
	{
		get_uuid_from_params(arg, uuid_str);
		entry_idx = update_ctx_uuid(uuid_str);
	}
	else
	{
		get_uuid_by_session_id(arg, uuid_str);
		entry_idx = get_entry_idx_by_uuid(uuid_str);
	}

	// get table_idx
	table_idx = get_ctx_table_idx(entry_idx);

	// compare TA uuid
	if ((0 == memcmp(uuid_str, uuid_acipher, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_secure_storage, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_wallet, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_hotp, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_clearkey, UUID_STR_LENGTH)))
	{
		if (OPTEE_MSG_CMD_OPEN_SESSION == arg->cmd)
		{
			// create slice table mapping
			alloc_and_map_slice_tables(ptr_default_partition, table_idx);
			// set slice table allocated
			set_slice_table_allocated(entry_idx);
			// unmap pages
			slice_unmap_page_mappings(uuid_str, table_idx);
		}
		// switch ttbr0_el1
		new_ttbr = virt_to_phys(ptr_default_partition->slice_base_tables[table_idx][0][get_core_pos()]);
		write_ttbr0_el1(new_ttbr);
		isb();
		tlbi_all();
		icache_inv_all();
		// switch default_partition->base_tables
		ptr_default_partition->base_tables = ptr_default_partition->slice_base_tables[table_idx];
	}
	else
	{
		// calculate old ttbr for current core
		new_ttbr = virt_to_phys(base_xlation_table[0][get_core_pos()]);
		// restore ttbr0_el1
		write_ttbr0_el1(new_ttbr);
		isb();
		tlbi_all();
		icache_inv_all();
		// restore default_partition->base_tables
		ptr_default_partition->base_tables = base_xlation_table;
	}

#ifdef LOG_CYCLES
	end_cycle = rdtsc();
	cycles_in_ttbr_switching += (end_cycle - start_cycle);
#endif // LOG_CYCLES

	thread_unmask_exceptions(exceptions);
}

/* exit gate for standard smc calls */
void exit_gate_std(struct optee_msg_arg *arg)
{
	int entry_idx = -1;
	uint32_t exceptions;
	uint64_t current_ttbr __unused;
	uint64_t new_ttbr __unused;
	char uuid_str[UUID_STR_LENGTH];
	int table_idx = -1;
#ifdef LOG_CYCLES
	uint64_t start_cycle, end_cycle;
#endif // LOG_CYCLES

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

#ifdef LOG_CYCLES
	start_cycle = rdtsc();
#endif // LOG_CYCLES

	// deal with ctx info
	if (OPTEE_MSG_CMD_OPEN_SESSION == arg->cmd)
	{
		update_session_id(arg);
		get_uuid_from_params(arg, uuid_str);
	}
	else
	{
		get_uuid_by_session_id(arg, uuid_str);
	}

	// get entry idx
	entry_idx = get_entry_idx_by_session_id(arg);

	// get table_idx
	table_idx = get_ctx_table_idx(entry_idx);

	if (OPTEE_MSG_CMD_CLOSE_SESSION == arg->cmd) // set base_xlation_table to original
	{
		remove_session_id(arg);
		if (0 == get_ctx_refcnt_by_uuid(uuid_str) && no_session_is_opened(uuid_str))
		{
			clear_slice_ctx_entry(entry_idx);

			// cleanup slice tables
			cleanup_slice_tables(ptr_default_partition, entry_idx);
		}
	}

	if (OPTEE_MSG_CMD_OPEN_SESSION == arg->cmd && slice_table_is_allocated(entry_idx) && !slice_table_is_enabled(entry_idx))
	{
		// secure memory tagging
		slice_memory_tagging(table_idx, uuid_str);
		// set table enabled
		set_slice_table_enabled(entry_idx);
	}

#ifdef LOG_CYCLES
	end_cycle = rdtsc();
	cycles_in_ttbr_switching += (end_cycle - start_cycle);
#endif // LOG_CYCLES

#ifdef LOG_CYCLES
	if (OPTEE_MSG_CMD_CLOSE_SESSION == arg->cmd)
	{
		DMSG("cycles in Memory Checking: %lu", cycles_in_memory_checking);
		DMSG("cycles in TA Initialization: %lu", cycles_in_ta_initialization);
		DMSG("cycles in TTBR Switching: %lu", cycles_in_ttbr_switching);
	}
#endif // LOG_CYCLES

	thread_unmask_exceptions(exceptions);
}

/* entry gate for fast smc calls */
void entry_gate_fast(struct thread_smc_args *args __unused)
{
	;
}

/* exit gate for fast smc calls */
void exit_gate_fast(struct thread_smc_args *args __unused)
{
	;
}

/* entry gate for all smc calls (only for some RPC calls) */
void _entry_gate(uint32_t smc_call_type, uint32_t a1 __unused, uint32_t a2 __unused, uint32_t a3, uint32_t a4 __unused, uint32_t a5 __unused)
{
	TEE_UUID uuid;
	char uuid_str[UUID_STR_LENGTH];
	int thread_id = -1;
	int entry_idx = -1;
	uint32_t exceptions;
	uint64_t current_ttbr __unused;
	uint64_t new_ttbr;
#ifdef LOG_CYCLES
	uint64_t start_cycle, end_cycle;
#endif // LOG_CYCLES

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

#ifdef LOG_CYCLES
	start_cycle = rdtsc();
#endif // LOG_CYCLES

	switch (smc_call_type)
	{
	case OPTEE_SMC_CALL_RETURN_FROM_RPC:
		thread_id = a3;
		if (NULL == threads[thread_id].tsd.ctx) // thread_rpc_shm_cache_clear
		{
			current_ttbr = read_ttbr0_el1();
			if (ptr_default_partition->base_tables != base_xlation_table)
			{
				// calculate old ttbr for current core
				new_ttbr = virt_to_phys(base_xlation_table[0][get_core_pos()]);
				// restore ttbr0_el1
				write_ttbr0_el1(new_ttbr);
				isb();
				tlbi_all();
				icache_inv_all();
				// restore default_partition->base_tables
				ptr_default_partition->base_tables = base_xlation_table;
			}
			break;
		}
		else
		{
			uuid = threads[thread_id].tsd.ctx->uuid;
			// translate struct uuid to str format
			snprintf(uuid_str, UUID_STR_LENGTH, "%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 "-%02" PRIx8 "%02" PRIx8 "-%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8,
					 uuid.timeLow, uuid.timeMid, uuid.timeHiAndVersion,
					 uuid.clockSeqAndNode[0], uuid.clockSeqAndNode[1], uuid.clockSeqAndNode[2], uuid.clockSeqAndNode[3],
					 uuid.clockSeqAndNode[4], uuid.clockSeqAndNode[5], uuid.clockSeqAndNode[6], uuid.clockSeqAndNode[7]);
			if ((0 == memcmp(uuid_str, uuid_acipher, UUID_STR_LENGTH)) ||
				(0 == memcmp(uuid_str, uuid_secure_storage, UUID_STR_LENGTH)) ||
				(0 == memcmp(uuid_str, uuid_wallet, UUID_STR_LENGTH)) ||
				(0 == memcmp(uuid_str, uuid_hotp, UUID_STR_LENGTH)) ||
				(0 == memcmp(uuid_str, uuid_clearkey, UUID_STR_LENGTH)))
			{
				entry_idx = get_entry_idx_by_uuid(uuid_str);
				// switch ttbr0_el1
				new_ttbr = virt_to_phys(ptr_default_partition->slice_base_tables[entry_idx][0][get_core_pos()]);
				write_ttbr0_el1(new_ttbr);
				isb();
				tlbi_all();
				icache_inv_all();
				// switch default_partition->base_tables
				ptr_default_partition->base_tables = ptr_default_partition->slice_base_tables[entry_idx];
			}
			else
			{
				// calculate old ttbr for current core
				new_ttbr = virt_to_phys(base_xlation_table[0][get_core_pos()]);
				// restore ttbr0_el1
				write_ttbr0_el1(new_ttbr);
				isb();
				tlbi_all();
				icache_inv_all();
				// restore default_partition->base_tables
				ptr_default_partition->base_tables = base_xlation_table;
			}
		}
		break;
	case OPTEE_SMC_CALL_WITH_ARG:
		break;
	case OPTEE_SMC_CALL_WITH_RPC_ARG:
		break;
	case OPTEE_SMC_CALL_WITH_REGD_ARG:
		break;
	default:
		EMSG(RED("[SLICE] Unkown Type"));
		break;
	}

#ifdef LOG_CYCLES
	end_cycle = rdtsc();
	cycles_in_ttbr_switching += (end_cycle - start_cycle);
#endif // LOG_CYCLES

	thread_unmask_exceptions(exceptions);
}
