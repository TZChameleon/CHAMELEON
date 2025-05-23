/*
 * Copyright (c) 2014-2019, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Copyright (c) 2014, Linaro Limited. All rights reserved. */

#ifndef TEESMC_OPTEED_H
#define TEESMC_OPTEED_H

/*
 * This file specifies SMC function IDs used when returning from TEE to the
 * secure monitor.
 *
 * All SMC Function IDs indicates SMC32 Calling Convention but will carry
 * full 64 bit values in the argument registers if invoked from Aarch64
 * mode. This violates the SMC Calling Convention, but since this
 * convention only coveres API towards Normal World it's something that
 * only concerns the OP-TEE Dispatcher in Trusted Firmware-A and OP-TEE
 * OS at Secure EL1.
 */

/*
 * Issued when returning from initial entry.
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_ENTRY_DONE
 * r1/x1	Pointer to entry vector
 */
#define TEESMC_OPTEED_FUNCID_RETURN_ENTRY_DONE		0
#define TEESMC_OPTEED_RETURN_ENTRY_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_ENTRY_DONE)



/*
 * Issued when returning from "cpu_on" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_ON_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_OPTEED_FUNCID_RETURN_ON_DONE		1
#define TEESMC_OPTEED_RETURN_ON_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_ON_DONE)

/*
 * Issued when returning from "cpu_off" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_OFF_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_OPTEED_FUNCID_RETURN_OFF_DONE		2
#define TEESMC_OPTEED_RETURN_OFF_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_OFF_DONE)

/*
 * Issued when returning from "cpu_suspend" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_SUSPEND_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_OPTEED_FUNCID_RETURN_SUSPEND_DONE	3
#define TEESMC_OPTEED_RETURN_SUSPEND_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_SUSPEND_DONE)

/*
 * Issued when returning from "cpu_resume" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_RESUME_DONE
 * r1/x1	0 on success and anything else to indicate error condition
 */
#define TEESMC_OPTEED_FUNCID_RETURN_RESUME_DONE		4
#define TEESMC_OPTEED_RETURN_RESUME_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_RESUME_DONE)

/*
 * Issued when returning from "std_smc" or "fast_smc" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_CALL_DONE
 * r1-4/x1-4	Return value 0-3 which will passed to normal world in
 *		r0-3/x0-3
 */
#define TEESMC_OPTEED_FUNCID_RETURN_CALL_DONE		5
#define TEESMC_OPTEED_RETURN_CALL_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_CALL_DONE)

/*
 * Issued when returning from "fiq" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_FIQ_DONE
 */
#define TEESMC_OPTEED_FUNCID_RETURN_FIQ_DONE		6
#define TEESMC_OPTEED_RETURN_FIQ_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_FIQ_DONE)

/*
 * Issued when returning from "system_off" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE
 */
#define TEESMC_OPTEED_FUNCID_RETURN_SYSTEM_OFF_DONE	7
#define TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_SYSTEM_OFF_DONE)

/*
 * Issued when returning from "system_reset" vector
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_RETURN_SYSTEM_RESET_DONE
 */
#define TEESMC_OPTEED_FUNCID_RETURN_SYSTEM_RESET_DONE	8
#define TEESMC_OPTEED_RETURN_SYSTEM_RESET_DONE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_SYSTEM_RESET_DONE)

/*
 * Issued when slice service trap into atf
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_SLICE_TRAP
 */
#define TEESMC_OPTEED_FUNCID_SLICE_TRAP		9
#define TEESMC_OPTEED_SLICE_TRAP \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_SLICE_TRAP)

/*
 * Issued when slice service trap into atf
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_SLICE_UPDATE_MAPPING
 */
#define TEESMC_OPTEED_FUNCID_SLICE_UPDATE_MAPPING		10
#define TEESMC_OPTEED_SLICE_UPDATE_MAPPING \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_SLICE_UPDATE_MAPPING)

/*
 * Issued when slice service trap into atf
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_SLICE_SET_TTBR
 */
#define TEESMC_OPTEED_FUNCID_SLICE_SET_TTBR		11
#define TEESMC_OPTEED_SLICE_SET_TTBR \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_SLICE_SET_TTBR)

/*
 * Issued when slice service trap into atf
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_SLICE_NEW_TABLE
 */
#define TEESMC_OPTEED_FUNCID_SLICE_NEW_TABLE		12
#define TEESMC_OPTEED_SLICE_NEW_TABLE \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_SLICE_NEW_TABLE)

/*
 * Issued when slice service trap into atf
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_SLICE_CLEAR_ENTRY
 */
#define TEESMC_OPTEED_FUNCID_SLICE_CLEAR_ENTRY		13
#define TEESMC_OPTEED_SLICE_CLEAR_ENTRY \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_SLICE_CLEAR_ENTRY)

/*
 * Issued when slice service trap into atf
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_SLICE_START_COUNTER
 */
#define TEESMC_OPTEED_FUNCID_SLICE_START_COUNTER		14
#define TEESMC_OPTEED_SLICE_START_COUNTER \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_SLICE_START_COUNTER)

/*
 * Issued when slice service trap into atf
 *
 * Register usage:
 * r0/x0	SMC Function ID, TEESMC_OPTEED_SLICE_STOP_COUNTER
 */
#define TEESMC_OPTEED_FUNCID_SLICE_STOP_COUNTER		15
#define TEESMC_OPTEED_SLICE_STOP_COUNTER \
	TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_SLICE_STOP_COUNTER)

#endif /*TEESMC_OPTEED_H*/
