/* SPDX-License-Identifier: (BSD-2-Clause AND MIT) */
/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2008-2010 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <mm/core_mmu.h>
#include <platform_config.h>
#include <util.h>

/*
 * TEE_RAM_VA_START:            The start virtual address of the TEE RAM
 * TEE_TEXT_VA_START:           The start virtual address of the OP-TEE text
 */
#define TEE_RAM_VA_START        TEE_RAM_START
#define TEE_TEXT_VA_START       (TEE_RAM_VA_START + \
					(TEE_LOAD_ADDR - TEE_RAM_START))

/*
 * Note:
 * Clang 11 (ld.lld) generates non-relocatable reference when using ROUNDDOWN()
 * from <util.h>, which does not work with ASLR.
 */
#define LD_ROUNDDOWN(x, y) ((x) - ((x) % (y)))

OUTPUT_FORMAT(CFG_KERN_LINKER_FORMAT)
OUTPUT_ARCH(CFG_KERN_LINKER_ARCH)

ENTRY(_start)
SECTIONS
{
	. = TEE_TEXT_VA_START;
#ifdef ARM32
	ASSERT(!(TEE_TEXT_VA_START & 31), "text start should align to 32bytes")
#endif
#ifdef ARM64
	ASSERT(!(TEE_TEXT_VA_START & 127), "text start should align to 128bytes")
#endif
	__text_start = .;

	/*
	 * Memory between TEE_TEXT_VA_START and page aligned rounded down
	 * value will be mapped with unpaged "text" section attributes:
	 * likely to be read-only/executable.
	 */
	__flatmap_unpg_rx_start = LD_ROUNDDOWN(__text_start, SMALL_PAGE_SIZE);

	.text : {
		KEEP(*(.text._start))
		__identity_map_init_start = .;
		__text_data_start = .;
		*(.identity_map.data)
		__text_data_end = .;
		*(.identity_map .identity_map.* \
			/*
			 * The one below is needed because it's a weak
			 * symbol that may be overridden by platform
			 * specific code.
			 */
		  .text.get_core_pos_mpidr)
		__identity_map_init_end = .;
		KEEP(*(.text.init .text.plat_cpu_reset_early \
		       .text.reset .text.reset_primary .text.unhandled_cpu \
		       .text.__assert_flat_mapped_range))

#ifdef CFG_WITH_PAGER
		*(.text)
/* Include list of sections needed for paging */
#include <text_unpaged.ld.S>
#else
#ifdef CFG_SERVICE_SLICE
        EXCLUDE_FILE(*tee_svc.o *tee_svc_cryp.o *tee_svc_storage.o) *(.text .text.*)
		KEEP(*(.text.get_prop_tee_dev_id .text.get_prop_tee_sys_time_prot_level \
			.text.get_prop_client_id .text.get_prop_client_endian \
			.text.get_prop_ta_app_id .text.get_prop_feat_bti_implemented \
			.text.get_prop_feat_pauth_implemented \
			.text.get_prop_feat_memtag_implemented .text.get_prop_set \
			.text.get_prop_struct .text.utee_param_to_param \
			.text.alloc_temp_sec_mem .text.tee_svc_copy_param \
			.text.tee_svc_update_out_param));
		KEEP(*(.text.tee_svc_storage_get_enum .text.tee_svc_close_enum \
			.text.remove_corrupt_obj .text.tee_svc_storage_read_head \
			.text.tee_svc_storage_init_file .text.tee_svc_storage_close_all_enum));
		KEEP(*(.text.op_u32_to_binary_helper .text.op_u32_from_binary_helper \
			.text.op_attr_secret_value_from_user .text.op_attr_secret_value_to_user \
			.text.op_attr_secret_value_to_binary .text.op_attr_secret_value_from_binary \
			.text.op_attr_secret_value_from_obj .text.op_attr_secret_value_clear \
			.text.op_attr_bignum_from_user .text.op_attr_bignum_to_user \
			.text.op_attr_bignum_to_binary .text.op_attr_bignum_from_binary \
			.text.op_attr_bignum_from_obj .text.op_attr_bignum_clear \
			.text.op_attr_bignum_free .text.op_attr_value_from_user \
			.text.op_attr_value_to_user .text.op_attr_value_to_binary \
			.text.op_attr_value_from_binary .text.op_attr_value_from_obj \
			.text.op_attr_value_clear .text.op_attr_25519_from_user \
			.text.op_attr_25519_to_user .text.op_attr_25519_to_binary \
			.text.op_attr_25519_from_binary .text.op_attr_25519_from_obj \
			.text.op_attr_25519_clear .text.op_attr_25519_free \
			.text.get_user_u64_as_size_t .text.put_user_u64 \
			.text.tee_svc_cryp_obj_find_type_attr_idx .text.tee_svc_find_type_props \
			.text.set_attribute .text.get_attribute .text.tee_obj_attr_free \
			.text.tee_obj_attr_clear .text.tee_obj_attr_to_binary \
			.text.tee_obj_attr_from_binary .text.tee_obj_attr_copy_from \
			.text.is_gp_legacy_des_key_size .text.check_key_size .text.tee_obj_set_type \
			.text.copy_in_attrs .text.tee_svc_cryp_check_attr .text.get_ec_key_size \
			.text.get_used_bits .text.tee_svc_cryp_obj_populate_type \
			.text.check_pub_rsa_key .text.tee_svc_obj_generate_key_rsa \
			.text.tee_svc_obj_generate_key_dsa .text.tee_svc_obj_generate_key_dh \
			.text.tee_svc_obj_generate_key_ecc .text.tee_svc_obj_generate_key_x25519 \
			.text.tee_svc_obj_generate_key_ed25519 .text.tee_svc_obj_ed25519_parse_params \
			.text.tee_svc_obj_ed25519_sign .text.tee_svc_obj_ed25519_verify \
			.text.tee_svc_cryp_get_state .text.cryp_state_free \
			.text.tee_svc_cryp_check_key_type .text.translate_compat_algo \
			.text.tee_svc_cryp_free_states .text.is_xof_algo \
			.text.tee_svc_cipher_update_helper .text.get_hkdf_params \
			.text.get_concat_kdf_params .text.get_pbkdf2_params .text.get_sm2_kep_params \
			.text.pkcs1_get_salt_len));
		KEEP(*(.text.__tee_alg_get_main_alg .text.__tee_alg_get_class \
			.text.tee_svc_cryp_get_state.* .text.tee_svc_copy_param.* \
			.text.memtag_strip_tag_vaddr .text.tee_svc_storage_file_ops \
			.text.memtag_strip_tag .text.memtag_strip_tag_const .text.mobj_put_wipe \
			.text.to_user_ta_ctx .text.__tee_alg_get_digest_hash \
			.text.__tee_alg_hash_algo .text.tee_svc_obj_ed25519_parse_params.constprop.0)); /* Others */
#else
		*(.text .text.*)
#endif
#endif
		*(.sram.text.glue_7* .gnu.linkonce.t.*)
		. = ALIGN(8);
	}
	__text_end = .;

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_unpg_rx_size = . - __flatmap_unpg_rx_start;
	__flatmap_unpg_ro_start = .;

	.rodata : ALIGN(8) {
		__rodata_start = .;
		*(.gnu.linkonce.r.*)
#ifdef CFG_WITH_PAGER
		*(.rodata .rodata.__unpaged .rodata.__unpaged.*)
#include <rodata_unpaged.ld.S>
#else
		*(.rodata .rodata.*)
#ifndef CFG_CORE_ASLR
		. = ALIGN(8);
		KEEP(*(SORT(.scattered_array*)));
#endif
#endif
		. = ALIGN(8);
		__rodata_end = .;
	}

#if defined(CFG_CORE_ASLR)
	.data.rel.ro : {
#if !defined(CFG_WITH_PAGER)
		. = ALIGN(8);
		KEEP(*(SORT(.scattered_array*)));
#endif
		*(.data.rel.ro.__unpaged .data.rel.ro.__unpaged.*)
	}
#endif

	.got : { *(.got.plt) *(.got) }
	.note.gnu.property : { *(.note.gnu.property) }
	.plt : { *(.plt) }

	.ctors : ALIGN(8) {
		__ctor_list = .;
		KEEP(*(.ctors .ctors.* .init_array .init_array.*))
		__ctor_end = .;
	}
	.dtors : ALIGN(8) {
		__dtor_list = .;
		KEEP(*(.dtors .dtors.* .fini_array .fini_array.*))
		__dtor_end = .;
	}

	/* .ARM.exidx is sorted, so has to go in its own output section.  */
	.ARM.exidx : {
		__exidx_start = .;
		*(.ARM.exidx* .gnu.linkonce.armexidx.*)
		__exidx_end = .;
	}

	.ARM.extab : {
		__extab_start = .;
		*(.ARM.extab*)
		__extab_end = .;
	}

	/* Start page aligned read-write memory */
#ifdef CFG_CORE_RWDATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_unpg_ro_size = . - __flatmap_unpg_ro_start;

#ifdef CFG_SERVICE_SLICE
	. = ALIGN(SMALL_PAGE_SIZE);
	__vcore_unpg_rx_lib1_start = .;
	.lib1_section : {
		KEEP(*(.text.syscall_panic .text.syscall_cryp_obj_close \
			.text.syscall_log .text.syscall_storage_obj_create \
			.text.syscall_storage_obj_read .text.syscall_cryp_obj_get_info \
			.text.syscall_cryp_obj_alloc .text.syscall_check_access_rights \
			.text.syscall_hash_init .text.syscall_cryp_obj_reset \
			.text.syscall_cryp_state_free .text.syscall_storage_obj_open \
			.text.syscall_cryp_state_alloc .text.syscall_cryp_obj_populate \
			.text.syscall_storage_obj_write .text.syscall_cryp_obj_copy));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib1_size = . - __vcore_unpg_rx_lib1_start;
	__vcore_unpg_rx_lib1_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib2_start = .;
	.lib2_section : {
		KEEP(*(.text.syscall_storage_obj_seek .text.syscall_storage_obj_rename));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib2_size = . - __vcore_unpg_rx_lib2_start;
	__vcore_unpg_rx_lib2_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib3_start = .;
	.lib3_section : {
		KEEP(*(.text.syscall_hash_final .text.syscall_invoke_ta_command \
			.text.syscall_open_ta_session .text.syscall_close_ta_session));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib3_size = . - __vcore_unpg_rx_lib3_start;
	__vcore_unpg_rx_lib3_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib4_start = .;
	.lib4_section : {
		KEEP(*(.text.syscall_cipher_init .text.syscall_authenc_update_payload \
			.text.syscall_cipher_final .text.syscall_cipher_update));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib4_size = . - __vcore_unpg_rx_lib4_start;
	__vcore_unpg_rx_lib4_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib5_start = .;
	.lib5_section : {
		KEEP(*(.text.syscall_hash_update .text.syscall_cryp_random_number_generate));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib5_size = . - __vcore_unpg_rx_lib5_start;
	__vcore_unpg_rx_lib5_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib6_start = .;
	.lib6_section : {
		KEEP(*(.text.syscall_asymm_operate .text.syscall_storage_obj_del));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib6_size = . - __vcore_unpg_rx_lib6_start;
	__vcore_unpg_rx_lib6_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib7_start = .;
	.lib7_section : {
		KEEP(*(.text.syscall_get_property .text.syscall_get_property_name_to_index));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib7_size = . - __vcore_unpg_rx_lib7_start;
	__vcore_unpg_rx_lib7_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib8_start = .;
	.lib8_section : {
		KEEP(*(.text.syscall_asymm_verify .text.syscall_cryp_obj_get_attr \
			.text.syscall_cryp_derive_key));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib8_size = . - __vcore_unpg_rx_lib8_start;
	__vcore_unpg_rx_lib8_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib9_start = .;
	.lib9_section : {
		KEEP(*(.text.syscall_get_time .text.syscall_storage_obj_trunc));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib9_size = . - __vcore_unpg_rx_lib9_start;
	__vcore_unpg_rx_lib9_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	__vcore_unpg_rx_lib10_start = .;
	.lib10_section : {
		KEEP(*(.text.syscall_storage_next_enum .text.syscall_authenc_dec_final \
			.text.syscall_storage_start_enum .text.syscall_storage_alloc_enum \
			.text.syscall_authenc_enc_final .text.syscall_cryp_obj_generate_key \
			.text.syscall_storage_free_enum .text.syscall_authenc_init));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_lib10_size = . - __vcore_unpg_rx_lib10_start;
	__vcore_unpg_rx_lib10_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);

	/* others section */
	__vcore_unpg_rx_others_start = .;
	.others_section : {
		KEEP(*(.text.syscall_not_supported .text.syscall_get_cancellation_flag \
			.text.syscall_unmask_cancellation .text.syscall_mask_cancellation \
			.text.syscall_wait .text.syscall_set_ta_time \
			.text.syscall_cryp_obj_restrict_usage .text.syscall_obj_generate_key \
			.text.syscall_cryp_state_copy .text.syscall_authenc_update_aad \
			.text.syscall_storage_reset_enum));
		. = ALIGN(SMALL_PAGE_SIZE);
	}
	__vcore_unpg_rx_others_size = . - __vcore_unpg_rx_others_start;
	__vcore_unpg_rx_others_end = .;
	. = ALIGN(SMALL_PAGE_SIZE);
#endif

#ifdef CFG_NS_VIRTUALIZATION
	__flatmap_nex_rw_start = . ;
	.nex_data : ALIGN(8) {
		*(.nex_data .nex_data.*)
	}

	.nex_bss : ALIGN(8) {
		__nex_bss_start = .;
		*(.nex_bss .nex_bss.*)
		__nex_bss_end = .;
	}

	/*
	 * We want to keep all nexus memory in one place, because
	 * it should be always mapped and it is easier to map one
	 * memory region than two.
	 * Next section are NOLOAD ones, but they are followed
	 * by sections with data. Thus, this NOLOAD section will
	 * be included in the resulting binary, filled with zeroes
	 */
	.nex_stack (NOLOAD) : {
		__nozi_stack_start = .;
		KEEP(*(.nozi_stack.stack_tmp .nozi_stack.stack_abt))
		. = ALIGN(8);
		__nozi_stack_end = .;
	}

	.nex_heap (NOLOAD) : {
		__nex_heap_start = .;
		. += CFG_CORE_NEX_HEAP_SIZE;
		. = ALIGN(16 * 1024);
		__nex_heap_end = .;
	}
	.nex_nozi (NOLOAD) : {
		ASSERT(!(ABSOLUTE(.) & (16 * 1024 - 1)), "align nozi to 16kB");
		KEEP(*(.nozi.mmu.base_table .nozi.mmu.l2))
	}

	. = ALIGN(SMALL_PAGE_SIZE);

	__flatmap_nex_rw_size = . - __flatmap_nex_rw_start;
	__flatmap_nex_rw_end = .;
#endif

	__flatmap_unpg_rw_start = .;

	.data : ALIGN(8) {
		/* writable data  */
		__data_start_rom = .;
		/* in one segment binaries, the rom data address is on top
		   of the ram data address */
		__data_start = .;
		*(.data .data.* .gnu.linkonce.d.*)
		. = ALIGN(8);
	}

	/*
	 * create secure memory section
	 */
	.secmem : {
		. = ALIGN(SMALL_PAGE_SIZE);
		__sec_mem_start = .;
		*(secmem)
		. = ALIGN(SMALL_PAGE_SIZE);
		__sec_mem_end = .;
	}

	/* unintialized data */
	.bss : {
		__data_end = .;
		__bss_start = .;
		*(.bss .bss.*)
		*(.gnu.linkonce.b.*)
		*(COMMON)
		. = ALIGN(8);
		__bss_end = .;
	}

	.heap1 (NOLOAD) : {
		/*
		 * We're keeping track of the padding added before the
		 * .nozi section so we can do something useful with
		 * this otherwise wasted memory.
		 */
		__heap1_start = .;
#ifndef CFG_WITH_PAGER
		. += CFG_CORE_HEAP_SIZE;
#endif
#ifdef CFG_WITH_LPAE
		. = ALIGN(4 * 1024);
#else
		. = ALIGN(16 * 1024);
#endif
		__heap1_end = .;
	}
	/*
	 * Uninitialized data that shouldn't be zero initialized at
	 * runtime.
	 *
	 * L1 mmu table requires 16 KiB alignment
	 */
	.nozi (NOLOAD) : {
		__nozi_start = .;
		KEEP(*(.nozi .nozi.*))
		. = ALIGN(16);
		__nozi_end = .;
		/*
		 * If virtualization is enabled, abt and tmp stacks will placed
		 * at above .nex_stack section and thread stacks will go there
		 */
		__nozi_stack_start = .;
		KEEP(*(.nozi_stack .nozi_stack.*))
		. = ALIGN(8);
		__nozi_stack_end = .;
	}

#ifdef CFG_WITH_PAGER
	.heap2 (NOLOAD) : {
		__heap2_start = .;
		/*
		 * Reserve additional memory for heap, the total should be
		 * at least CFG_CORE_HEAP_SIZE, but count what has already
		 * been reserved in .heap1
		 */
		. += CFG_CORE_HEAP_SIZE - (__heap1_end - __heap1_start);
		. = ALIGN(SMALL_PAGE_SIZE);
		__heap2_end = .;
	}

	/* Start page aligned read-only memory */
	__flatmap_unpg_rw_size = . - __flatmap_unpg_rw_start;

	__init_start = .;
	__flatmap_init_rx_start = .;

	ASSERT(!(__flatmap_init_rx_start & (SMALL_PAGE_SIZE - 1)),
		"read-write memory is not paged aligned")

	.text_init : {
		__text_init_start = .;
/*
 * Include list of sections needed for boot initialization, this list
 * overlaps with unpaged.ld.S but since unpaged.ld.S is first all those
 * sections will go into the unpaged area.
 */
#include <text_init.ld.S>
		KEEP(*(.text.startup.*));
		/* Make sure constructor functions are available during init */
		KEEP(*(.text._GLOBAL__sub_*));
		. = ALIGN(8);
		__text_init_end = .;
	}

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif
	__flatmap_init_rx_size = . - __flatmap_init_rx_start;
	__flatmap_init_ro_start = .;

	.rodata_init : {
		__rodata_init_start = .;
#include <rodata_init.ld.S>
#ifndef CFG_CORE_ASLR
		. = ALIGN(8);
		KEEP(*(SORT(.scattered_array*)));
#endif
		__rodata_init_end = .;
	}
#ifdef CFG_CORE_ASLR
	.data.rel.ro_init : ALIGN(8) {
		KEEP(*(SORT(.scattered_array*)));
	}
#endif
	. = ALIGN(8);
	__ro_and_relro_data_init_end = .;

	__init_end = ALIGN(__ro_and_relro_data_init_end, SMALL_PAGE_SIZE);
	__get_tee_init_end = __init_end;
	__init_size = __init_end - __init_start;

	/* vcore flat map stops here. No need to page align, rodata follows. */
	__flatmap_init_ro_size = __init_end - __flatmap_init_ro_start;

	.rodata_pageable : ALIGN(8) {
		__rodata_pageable_start = .;
		*(.rodata*)
		__rodata_pageable_end = .;
	}

#ifdef CFG_CORE_RODATA_NOEXEC
	. = ALIGN(SMALL_PAGE_SIZE);
#endif

	.text_pageable : ALIGN(8) {
		__text_pageable_start = .;
		*(.text*)
		. = ALIGN(SMALL_PAGE_SIZE);
		__text_pageable_end = .;
	}

	__pageable_part_end = .;
	__pageable_part_start = __init_end;
	__pageable_start = __init_start;
	__pageable_end = __pageable_part_end;

	ASSERT(TEE_LOAD_ADDR >= TEE_RAM_START,
		"Load address before start of physical memory")
	ASSERT(TEE_LOAD_ADDR < (TEE_RAM_START + TEE_RAM_PH_SIZE),
		"Load address after end of physical memory")
	ASSERT((TEE_RAM_VA_START + TEE_RAM_PH_SIZE - __init_end) >
		SMALL_PAGE_SIZE, "Too few free pages to initialize paging")


#endif /*CFG_WITH_PAGER*/

#ifdef CFG_CORE_SANITIZE_KADDRESS
	. = TEE_RAM_VA_START + (TEE_RAM_VA_SIZE * 8) / 9 - 8;
	. = ALIGN(8);
	.asan_shadow : {
		__asan_shadow_start = .;
		. += TEE_RAM_VA_SIZE / 9;
		__asan_shadow_end = .;
		__asan_shadow_size = __asan_shadow_end - __asan_shadow_start;
	}
#endif /*CFG_CORE_SANITIZE_KADDRESS*/

	__end = .;

#ifndef CFG_WITH_PAGER
	__init_size = __data_end - TEE_TEXT_VA_START;
#endif
	/*
	 * Guard against moving the location counter backwards in the assignment
	 * below.
	 */
	ASSERT(. <= (TEE_RAM_VA_START + TEE_RAM_VA_SIZE),
		"TEE_RAM_VA_SIZE is too small")
	. = TEE_RAM_VA_START + TEE_RAM_VA_SIZE;

	_end_of_ram = .;

#ifndef CFG_WITH_PAGER
	__flatmap_unpg_rw_size = _end_of_ram - __flatmap_unpg_rw_start;
	__get_tee_init_end = .;
#endif

	/*
	 * These regions will not become a normal part of the dumped
	 * binary, instead some are interpreted by the dump script and
	 * converted into suitable format for OP-TEE itself to use.
	 */
	.dynamic : { *(.dynamic) }
	.hash : { *(.hash) }
	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }

	.rel : {
		*(.rel.*)
	}
	.rela : {
		*(.rela.*)
	}
#ifndef CFG_CORE_ASLR
	ASSERT(SIZEOF(.rel) == 0, "Relocation entries not expected")
	ASSERT(SIZEOF(.rela) == 0, "Relocation entries not expected")
#endif

	/DISCARD/ : {
		/* Strip unnecessary stuff */
		*(.comment .note .eh_frame .interp)
		/* Strip meta variables */
		*(__keep_meta_vars*)
	}

}

/* Unpaged read-only memories */
__vcore_unpg_rx_start = __flatmap_unpg_rx_start;
__vcore_unpg_ro_start = __flatmap_unpg_ro_start;
#ifdef CFG_CORE_RODATA_NOEXEC
__vcore_unpg_rx_size = __flatmap_unpg_rx_size;
__vcore_unpg_ro_size = __flatmap_unpg_ro_size;
#else
__vcore_unpg_rx_size = __flatmap_unpg_rx_size + __flatmap_unpg_ro_size;
__vcore_unpg_ro_size = 0;
#endif
__vcore_unpg_rx_end = __vcore_unpg_rx_start + __vcore_unpg_rx_size;
__vcore_unpg_ro_end = __vcore_unpg_ro_start + __vcore_unpg_ro_size;

/* Unpaged read-write memory */
__vcore_unpg_rw_start = __flatmap_unpg_rw_start;
__vcore_unpg_rw_size = __flatmap_unpg_rw_size;
__vcore_unpg_rw_end = __vcore_unpg_rw_start + __vcore_unpg_rw_size;

#ifdef CFG_NS_VIRTUALIZATION
/* Nexus read-write memory */
__vcore_nex_rw_start = __flatmap_nex_rw_start;
__vcore_nex_rw_size = __flatmap_nex_rw_size;
__vcore_nex_rw_end = __vcore_nex_rw_start + __vcore_nex_rw_size;
#endif

#ifdef CFG_WITH_PAGER
/*
 * Core init mapping shall cover up to end of the physical RAM.
 * This is required since the hash table is appended to the
 * binary data after the firmware build sequence.
 */
#define __FLATMAP_PAGER_TRAILING_SPACE	\
	(TEE_RAM_START + TEE_RAM_PH_SIZE - \
		(__flatmap_init_ro_start + __flatmap_init_ro_size))

/* Paged/init read-only memories */
__vcore_init_rx_start = __flatmap_init_rx_start;
__vcore_init_ro_start = __flatmap_init_ro_start;
#ifdef CFG_CORE_RODATA_NOEXEC
__vcore_init_rx_size = __flatmap_init_rx_size;
__vcore_init_ro_size = __flatmap_init_ro_size + __FLATMAP_PAGER_TRAILING_SPACE;
#else
__vcore_init_rx_size = __flatmap_init_rx_size + __flatmap_init_ro_size +
		       __FLATMAP_PAGER_TRAILING_SPACE;
__vcore_init_ro_size = 0;
#endif /* CFG_CORE_RODATA_NOEXEC */
__vcore_init_rx_end = __vcore_init_rx_start + __vcore_init_rx_size;
__vcore_init_ro_end = __vcore_init_ro_start + __vcore_init_ro_size;
#endif /* CFG_WITH_PAGER */

#ifdef CFG_CORE_SANITIZE_KADDRESS
__asan_map_start = (__asan_shadow_start / SMALL_PAGE_SIZE) *
		   SMALL_PAGE_SIZE;
__asan_map_end = ((__asan_shadow_end - 1) / SMALL_PAGE_SIZE) *
		 SMALL_PAGE_SIZE + SMALL_PAGE_SIZE;
__asan_map_size = __asan_map_end - __asan_map_start;
#endif /*CFG_CORE_SANITIZE_KADDRESS*/
