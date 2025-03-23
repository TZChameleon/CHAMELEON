/** \file
 *
 * \brief Entry point for hardware Bitcoin wallet.
 *
 * This file is licensed as described by the file LICENCE.
 */

#include "common.h"
#include "extern.h"
#include "hwinterface.h"
#include "test_helpers.h"
#include "test_performance.h"
#include "test_prandom.h"
#include "test_stream.h"
#include "test_transaction.h"
#include "test_wallet.h"
#include "rw_test.h"
#include "tz_functions.h"

#include <stdio.h>
#include <stdlib.h>

/** Entry point. This is the first thing which is called after startup code.
 * This never returns. */
int main(int argc, char const *argv[])
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

#ifdef TESTING
	statistics tests_stats;

	initialiseExternVariables();
	initialiseStats(&tests_stats);

	// initialiseTZ();
	// TestPerformance(&tests_stats);
	// terminateTZ();

	// initialiseTZ();
	// TestPerformanceStreams(&tests_stats);
	// terminateTZ();

	// initialiseTZ();
	// TestPrandom(&tests_stats);
	// terminateTZ();

	// initialiseTZ();
	// TestWallet(&tests_stats);
	// terminateTZ();

	initialiseTZ();
	TestTransaction(&tests_stats);
	terminateTZ();

	/* TODO REMOVE THIS TEST? IT IS THE SAME THING ALMOST */
	// TestStreams(&tests_stats);

	// // Our Tests
	// if (argc < 2 || argc > 6) {
	// 	fprintf(stderr, "Usage: %s [1|2|3|4|5]\n", argv[0]);
	// 	return -1;
	// }

	// bool do_create_master_key = false;
	// bool do_check_if_master_key_exists = false;
	// bool do_get_address = false;
	// bool do_sign_transaction = false;
	// bool do_delete_master_key = false;

	// for (int i = 1; i < argc; i++) {
	// 	if (atoi(argv[i]) == 1) {
	// 		do_create_master_key = true;
	// 	} else if (atoi(argv[i]) == 2) {
	// 		do_check_if_master_key_exists = true;
	// 	} else if (atoi(argv[i]) == 3) {
	// 		do_get_address = true;
	// 	} else if (atoi(argv[i]) == 4) {
	// 		do_sign_transaction = true;
	// 	} else if (atoi(argv[i]) == 5) {
	// 		do_delete_master_key = true;
	// 	}
	// }

	// initialiseTZ();
	// test_all(&tests_stats, do_create_master_key, do_check_if_master_key_exists, do_get_address, do_sign_transaction, do_delete_master_key);
	// terminateTZ();

	// printf("\n=====================================================================================================================================================\n");

	// printf("Global statistics\n\n");

	// printStatistics(tests_stats.passed, tests_stats.failed, tests_stats.total, tests_stats.time);

	// printf("=====================================================================================================================================================\n\n");

	// printf("\n");

#else

	initialiseExternVariables();
	initialiseTZ();

	while (true)
		processPacket();

	terminateTZ();

#endif

	return 0;
}
