#include <stddef.h>
#include <string.h>
#include <assert.h>

#include <common/debug.h>

#include "slice_mem.h"

/* UUID list */
static char uuid_acipher[] = "a734eed9-d6a1-4244-aa50-7c99719e7b7b";
static char uuid_secure_storage[] = "f4e750bb-1437-4fbf-8785-8d3580c34994";
static char uuid_hotp[] = "484d4143-2d53-4841-3120-4a6f636b6542";
static char uuid_wallet[] = "f894e6e0-1215-11e6-9281-0002a5d5c51b";
static char uuid_clearkey[] = "442ed209-b8e2-405e-8384-5cc78c753428";
static char uuid_hello_world[] __unused = "8aaaf200-2450-11e4-abe2-0002a5d5c51b";
static char uuid_aes[] __unused = "5dbac793-f574-4871-8ad3-04331ec17f24";
static char uuid_random[] __unused = "b6c53aba-9669-4668-a7f2-205629d00f86";

int check_uuid_bound(char *uuid_str)
{
	// compare TA uuid
	if ((0 == memcmp(uuid_str, uuid_acipher, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_secure_storage, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_wallet, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_hotp, UUID_STR_LENGTH)) ||
		(0 == memcmp(uuid_str, uuid_clearkey, UUID_STR_LENGTH)))
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static int mapping_to_uuid(char *uuid_str)
{
	if (0 == memcmp(uuid_str, uuid_acipher, UUID_STR_LENGTH))
	{
		return 0;
	}
	else if (0 == memcmp(uuid_str, uuid_secure_storage, UUID_STR_LENGTH))
	{
		return 1;
	}
	else if (0 == memcmp(uuid_str, uuid_wallet, UUID_STR_LENGTH))
	{
		return 2;
	}
	else if (0 == memcmp(uuid_str, uuid_hotp, UUID_STR_LENGTH))
	{
		return 3;
	}
	else if (0 == memcmp(uuid_str, uuid_clearkey, UUID_STR_LENGTH))
	{
		return 4;
	}
	else
	{
		return -1;
	}
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

/* get pages decriptor */
static page_desc_t *get_page_desc_ptr(page_desc_t *secure_page_desc, unsigned long pa)
{
	unsigned long idx = (pa & PAGE_DESC_IDX_MASK) / PAGE_SIZE;

	if (0 == pa)
	{
		return NULL;
	}

	// secure_page_desc[idx].index = idx;

	return secure_page_desc + idx;
}

/* check if the update is valid */
int page_table_update_is_valid(page_desc_t *secure_page_desc, paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa)
{
	char uuid_str[UUID_STR_LENGTH];
	uint16_t slice_bitmap = -1;
	page_desc_t *table_desc = get_page_desc_ptr(secure_page_desc, table_pa);
	page_desc_t *orig_desc __unused = get_page_desc_ptr(secure_page_desc, orig_pa);
	page_desc_t *new_desc = get_page_desc_ptr(secure_page_desc, new_pa);

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
			ERROR("[SLICE] Invalid access @ 0x%lx (type: %d) -> 0x%lx (type: %d)", table_pa, table_desc->type, new_pa, new_desc->type);
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
			ERROR("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)", table_pa, table_desc->type, new_pa, new_desc->type);
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
			ERROR("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)", table_pa, table_desc->type, new_pa, new_desc->type);
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
				ERROR("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)", table_pa, table_desc->type, new_pa, new_desc->type);
				return SLICE_MEMORY_INVALID;
			}
		}
	}
	else
	{
		ERROR("Wrong? @ 0x%lx (type: %d) -> 0x%lx (type: %d)", table_pa, table_desc->type, new_pa, new_desc->type);
		return SLICE_MEMORY_INVALID;
	}

	return SLICE_MEMORY_AVAILABLE;
}

/* update orginal memory page refcnt */
static void update_orig_page_data(page_desc_t *secure_page_desc, paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa)
{
	page_desc_t *table_desc __unused = get_page_desc_ptr(secure_page_desc, table_pa);
	page_desc_t *orig_desc = get_page_desc_ptr(secure_page_desc, orig_pa);
	page_desc_t *new_desc __unused = get_page_desc_ptr(secure_page_desc, new_pa);

	if ((table_pa & 0x1) && (orig_desc->count))
	{
		--(orig_desc->count);
	}
}

/* update new memory page refcnt */
static void update_new_page_data(page_desc_t *secure_page_desc, paddr_t table_pa, paddr_t orig_pa __unused, paddr_t new_pa)
{
	page_desc_t *table_desc __unused = get_page_desc_ptr(secure_page_desc, table_pa);
	page_desc_t *orig_desc __unused = get_page_desc_ptr(secure_page_desc, orig_pa);
	page_desc_t *new_desc = get_page_desc_ptr(secure_page_desc, new_pa);

	if (table_pa & 0x1)
	{
		if (!(new_desc->count < ((1u << 13) - 1)))
		{
			ERROR("overflow for the mapping count");
			return;
		}
		new_desc->count++;
	}
}

/* do secure memory attribute update */
void update_secure_attr(page_desc_t *secure_page_desc, paddr_t table_pa, paddr_t orig_pa, paddr_t new_pa, uint32_t attr)
{

	// Update counter in every memory pages
	if (new_pa != orig_pa)
	{
		update_orig_page_data(secure_page_desc, table_pa, orig_pa, new_pa);
		update_new_page_data(secure_page_desc, table_pa, orig_pa, new_pa);
	}
	else if ((table_pa & 0x1) && (attr & TEE_MATTR_VALID_BLOCK) == 0)
	{
		update_orig_page_data(secure_page_desc, table_pa, orig_pa, new_pa);
	}
	else if (((table_pa & 0x1) == 0) && (attr & TEE_MATTR_VALID_BLOCK))
	{
		update_new_page_data(secure_page_desc, table_pa, orig_pa, new_pa);
	}
	else
	{
		;
	}
}

/* update memory mapping */
void do_mmu_update(uint64_t *tbl, unsigned int idx, uint64_t desc, uint64_t pa)
{

	// WARN("Update 0x%lx -> 0x%lx\n", tbl[idx], desc | pa);
	tbl[idx] = desc | pa;
}

/* Table for TA & TTBR mappings */
slice_ttbr_table_t ttbr_table[CTX_STORAGE_SIZE][SESS_STORAGE_SIZE];

void init_ttbr_table(void)
{
	// NOTICE("sizeof(ttbr_table) = %ld\n", sizeof(ttbr_table));
	memset(ttbr_table, 0, sizeof(ttbr_table));
}

int get_ctx_table_idx(slice_ctx_t *global_slice_table_ctx, char *uuid_str, int entry_idx, base_xlat_tbls_t *slice_base_xlation_tables, uint64_t *phys_slice_ttbr_addr)
{
	int table_idx = -1, idx = -1;

	table_idx = global_slice_table_ctx[entry_idx].table_idx;

	idx = mapping_to_uuid(uuid_str);
	for (int i = 0; i < CTX_STORAGE_SIZE; i++)
	{
		if (ttbr_table[idx][i].is_used == 0)
		{
			// NOTICE("i = %d, is_used = %d\n", i, ttbr_table[idx][i].is_used);
			ttbr_table[idx][i].is_used = 1;
			memcpy(ttbr_table[idx][i].uuid, uuid_str, UUID_STR_LENGTH);
			ttbr_table[idx][i].ptr_base_table = (uint64_t) slice_base_xlation_tables[entry_idx];
			for (int j = 0; j < CFG_TEE_CORE_NB_CORE; j++)
			{
				ttbr_table[idx][i].ttbr_table[j] = *(phys_slice_ttbr_addr + CFG_TEE_CORE_NB_CORE * entry_idx + j);
				// NOTICE("ttbr_table[%d][%d].ttbr_table[%d] = 0x%lx\n", idx, i, j, ttbr_table[idx][i].ttbr_table[j]);
			}
			global_slice_table_ctx[entry_idx].atf_idx = i;
			break;
		}
	}

	return table_idx;
}

slice_ttbr_table_t *get_slice_ttbr_table_by_uuid(slice_ctx_t *global_slice_table_ctx, uint32_t entry_idx, char *uuid_str)
{
	int idx = -1, i = -1;

	idx = mapping_to_uuid(uuid_str);
	i = global_slice_table_ctx[entry_idx].atf_idx;
	if (ttbr_table[idx][i].is_used && memcmp(ttbr_table[idx][i].uuid, uuid_str, UUID_STR_LENGTH) == 0)
	{
		// NOTICE("idx = %d, i = %d\n", idx, i);
		return &ttbr_table[idx][i];
	}

	assert(0);

	return NULL;
}

int clear_phys_slice_table_entry(slice_ctx_t *global_slice_table_ctx, uint32_t entry_idx, char *uuid_str)
{
	int idx = -1, i = -1;

	idx = mapping_to_uuid(uuid_str);
	i = global_slice_table_ctx[entry_idx].atf_idx;
	if (ttbr_table[idx][i].is_used && memcmp(ttbr_table[idx][i].uuid, uuid_str, UUID_STR_LENGTH) == 0)
	{
		// WARN("idx = %d, i = %d\n", idx, i);
		return (ttbr_table[idx][i].is_used = 0);
	}

	assert(0);

	return -1;
}
