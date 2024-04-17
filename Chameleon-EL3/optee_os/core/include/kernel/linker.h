/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */
#ifndef __KERNEL_LINKER_H
#define __KERNEL_LINKER_H

#include <kernel/dt.h>
#include <types_ext.h>

/*
 * Symbols exported by the link script.
 */

#ifdef __arm__

/*
 * These addresses will be the start or end of the exception binary search
 * index table (.ARM.exidx section)
 */
extern const uint8_t __exidx_start[];
extern const uint8_t __exidx_end[];
extern const uint8_t __extab_start[];
extern const uint8_t __extab_end[];

#endif

/*
 * Warning! (ASLR) Do not use any of the _SZ_UNSAFE defines or _size[] variables
 * below in code that runs after dynamic relocations have been applied. Their
 * value could be *wrong* after relocation (for instance Aarch64 GCC 9.2
 * generates dynamic relocations for the _size[] symbols, but Clang 11.0.0 does
 * not). The _SZ_UNSAFE macros are mostly here for use in register_phys_mem()
 * where the _SZ macros would be rejected by the compiler ('initializer element
 * is not constant'). Other uses are likely to be incorrect.
 */

#define VCORE_UNPG_RX_PA	((unsigned long)__vcore_unpg_rx_start)
#define VCORE_UNPG_RX_SZ_UNSAFE	((size_t)__vcore_unpg_rx_size)
#define VCORE_UNPG_RX_SZ	((size_t)(__vcore_unpg_rx_end - \
					  __vcore_unpg_rx_start))
#ifdef CFG_SERVICE_SLICE
#define VCORE_UNPG_RX_LIB1_PA       ((unsigned long)__vcore_unpg_rx_lib1_start)
#define VCORE_UNPG_RX_LIB1_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib1_size)
#define VCORE_UNPG_RX_LIB1_SZ       ((size_t)(__vcore_unpg_rx_lib1_end - \
                                         __vcore_unpg_rx_lib1_start))
#define VCORE_UNPG_RX_LIB2_PA       ((unsigned long)__vcore_unpg_rx_lib2_start)
#define VCORE_UNPG_RX_LIB2_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib2_size)
#define VCORE_UNPG_RX_LIB2_SZ       ((size_t)(__vcore_unpg_rx_lib2_end - \
                                         __vcore_unpg_rx_lib2_start))
#define VCORE_UNPG_RX_LIB3_PA       ((unsigned long)__vcore_unpg_rx_lib3_start)
#define VCORE_UNPG_RX_LIB3_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib3_size)
#define VCORE_UNPG_RX_LIB3_SZ       ((size_t)(__vcore_unpg_rx_lib3_end - \
                                         __vcore_unpg_rx_lib3_start))
#define VCORE_UNPG_RX_LIB4_PA       ((unsigned long)__vcore_unpg_rx_lib4_start)
#define VCORE_UNPG_RX_LIB4_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib4_size)
#define VCORE_UNPG_RX_LIB4_SZ       ((size_t)(__vcore_unpg_rx_lib4_end - \
                                         __vcore_unpg_rx_lib4_start))
#define VCORE_UNPG_RX_LIB5_PA       ((unsigned long)__vcore_unpg_rx_lib5_start)
#define VCORE_UNPG_RX_LIB5_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib5_size)
#define VCORE_UNPG_RX_LIB5_SZ       ((size_t)(__vcore_unpg_rx_lib5_end - \
                                         __vcore_unpg_rx_lib5_start))
#define VCORE_UNPG_RX_LIB6_PA       ((unsigned long)__vcore_unpg_rx_lib6_start)
#define VCORE_UNPG_RX_LIB6_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib6_size)
#define VCORE_UNPG_RX_LIB6_SZ       ((size_t)(__vcore_unpg_rx_lib6_end - \
                                         __vcore_unpg_rx_lib6_start))
#define VCORE_UNPG_RX_LIB7_PA       ((unsigned long)__vcore_unpg_rx_lib7_start)
#define VCORE_UNPG_RX_LIB7_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib7_size)
#define VCORE_UNPG_RX_LIB7_SZ       ((size_t)(__vcore_unpg_rx_lib7_end - \
                                         __vcore_unpg_rx_lib7_start))
#define VCORE_UNPG_RX_LIB8_PA       ((unsigned long)__vcore_unpg_rx_lib8_start)
#define VCORE_UNPG_RX_LIB8_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib8_size)
#define VCORE_UNPG_RX_LIB8_SZ       ((size_t)(__vcore_unpg_rx_lib8_end - \
                                         __vcore_unpg_rx_lib8_start))
#define VCORE_UNPG_RX_LIB9_PA       ((unsigned long)__vcore_unpg_rx_lib9_start)
#define VCORE_UNPG_RX_LIB9_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib9_size)
#define VCORE_UNPG_RX_LIB9_SZ       ((size_t)(__vcore_unpg_rx_lib9_end - \
                                         __vcore_unpg_rx_lib9_start))
#define VCORE_UNPG_RX_LIB10_PA       ((unsigned long)__vcore_unpg_rx_lib10_start)
#define VCORE_UNPG_RX_LIB10_SZ_UNSAFE        ((size_t)__vcore_unpg_rx_lib10_size)
#define VCORE_UNPG_RX_LIB10_SZ       ((size_t)(__vcore_unpg_rx_lib10_end - \
                                         __vcore_unpg_rx_lib10_start))
#define VCORE_UNPG_RX_OTHERS_PA        ((unsigned long)__vcore_unpg_rx_others_start)
#define VCORE_UNPG_RX_OTHERS_SZ_UNSAFE ((size_t)__vcore_unpg_rx_others_size)
#define VCORE_UNPG_RX_OTHERS_SZ        ((size_t)(__vcore_unpg_rx_others_end - \
                                          __vcore_unpg_rx_others_start))
#endif
#define VCORE_UNPG_RO_PA	((unsigned long)__vcore_unpg_ro_start)
#define VCORE_UNPG_RO_SZ_UNSAFE	((size_t)__vcore_unpg_ro_size)
#define VCORE_UNPG_RO_SZ	((size_t)(__vcore_unpg_ro_end - \
					  __vcore_unpg_ro_start))
#define VCORE_UNPG_RW_PA	((unsigned long)__vcore_unpg_rw_start)
#define VCORE_UNPG_RW_SZ_UNSAFE	((size_t)__vcore_unpg_rw_size)
#define VCORE_UNPG_RW_SZ	((size_t)(__vcore_unpg_rw_end - \
					  __vcore_unpg_rw_start))
#define VCORE_NEX_RW_PA	((unsigned long)__vcore_nex_rw_start)
#define VCORE_NEX_RW_SZ_UNSAFE	((size_t)__vcore_nex_rw_size)
#define VCORE_NEX_RW_SZ	((size_t)__vcore_nex_rw_end - \
					 __vcore_nex_rw_start)
#define VCORE_INIT_RX_PA	((unsigned long)__vcore_init_rx_start)
#define VCORE_INIT_RX_SZ_UNSAFE	((size_t)__vcore_init_rx_size)
#define VCORE_INIT_RX_SZ	((size_t)(__vcore_init_rx_end - \
					  __vcore_init_rx_start))
#define VCORE_INIT_RO_PA	((unsigned long)__vcore_init_ro_start)
#define VCORE_INIT_RO_SZ_UNSAFE	((size_t)__vcore_init_ro_size)
#define VCORE_INIT_RO_SZ	((size_t)(__vcore_init_ro_end - \
					  __vcore_init_ro_start))

#define VCORE_START_VA		((vaddr_t)__text_start)

#define EMIT_SECTION_INFO_SYMBOLS(section_name) \
	extern const uint8_t __vcore_ ## section_name ## _start[]; \
	extern const uint8_t __vcore_ ## section_name ## _end[]; \
	extern const uint8_t __vcore_ ## section_name ## _size[]

#ifdef CFG_SERVICE_SLICE
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib1);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib2);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib3);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib4);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib5);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib6);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib7);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib8);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib9);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_lib10);
EMIT_SECTION_INFO_SYMBOLS(unpg_rx_others);
#endif
EMIT_SECTION_INFO_SYMBOLS(unpg_rx);
EMIT_SECTION_INFO_SYMBOLS(unpg_ro);
EMIT_SECTION_INFO_SYMBOLS(unpg_rw);
EMIT_SECTION_INFO_SYMBOLS(nex_rw);
EMIT_SECTION_INFO_SYMBOLS(init_ro);
EMIT_SECTION_INFO_SYMBOLS(init_rx);

#undef EMIT_SECTION_INFO_SYMBOLS

extern const uint8_t __text_start[];
extern const uint8_t __text_data_start[];
extern const uint8_t __text_data_end[];
extern const uint8_t __text_end[];
extern const uint8_t __end[];

extern const uint8_t __identity_map_init_start[];
extern const uint8_t __identity_map_init_end[];

extern uint8_t __data_start[];
extern const uint8_t __data_end[];
extern const uint8_t __rodata_start[];
extern const uint8_t __rodata_end[];
extern const uint8_t __bss_start[];
extern const uint8_t __bss_end[];
extern const uint8_t __nozi_start[];
extern const uint8_t __nozi_end[];
extern const uint8_t __nozi_stack_start[];
extern const uint8_t __nozi_stack_end[];
extern const uint8_t __init_start[];
extern const uint8_t __init_end[];
extern const uint8_t __sec_mem_start[];
extern const uint8_t __sec_mem_end[];

extern uint8_t __heap1_start[];
extern const uint8_t __heap1_end[];
extern uint8_t __heap2_start[];
extern const uint8_t __heap2_end[];

extern uint8_t __nex_heap_start[];
extern const uint8_t __nex_heap_end[];

extern const uint8_t __pageable_part_start[];
extern const uint8_t __pageable_part_end[];
extern const uint8_t __pageable_start[];
extern const uint8_t __pageable_end[];

extern const uint8_t __rodata_init_start[];
extern const uint8_t __rodata_init_end[];
extern const uint8_t __rodata_pageable_start[];
extern const uint8_t __rodata_pageable_end[];
extern const uint8_t __text_init_start[];
extern const uint8_t __text_init_end[];
extern const uint8_t __text_pageable_start[];
extern const uint8_t __text_pageable_end[];

#define ASAN_SHADOW_PA	((paddr_t)__asan_shadow_start)
#define ASAN_SHADOW_SZ	((size_t)__asan_shadow_size)
extern const uint8_t __asan_shadow_start[];
extern const uint8_t __asan_shadow_end[];
extern const uint8_t __asan_shadow_size[];

#define ASAN_MAP_PA	((paddr_t)__asan_map_start)
#define ASAN_MAP_SZ	((size_t)__asan_map_size)
extern const uint8_t __asan_map_start[];
extern const uint8_t __asan_map_end[];
extern const uint8_t __asan_map_size[];

extern const vaddr_t __ctor_list;
extern const vaddr_t __ctor_end;

/* Generated by core/arch/$(ARCH)/kernel/link.mk */
extern const char core_v_str[];

#endif /*__KERNEL_LINKER_H*/

