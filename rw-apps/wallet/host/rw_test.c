#include "common.h"
#include "endian.h"
#include "extern.h"
#include "prandom.h"
#include "test_helpers.h"
#include "rw_test.h"
#include "tz_functions.h"
#include "user_interface.h"
#include "stream_comm.h"
#include "transaction.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void report_failure(void)
{
	tests_failed++;
	tests_total++;
	printf("\tTest %2d: FAILED\n", tests_total);
}

void report_success(void)
{
	tests_passed++;
	tests_total++;
	printf("\tTest %2d: PASSED\n", tests_total);
}

void create_master_key(statistics *stats)
{
	uint8_t temp[128];
	uint32_t version;
	uint8_t wallet_uuid[UUID_LENGTH];
    uint8_t name[NAME_LENGTH];

	is_test = true;
	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	start_time = clock();

    printf("[*] new a wallet to create a master key\n");
    memcpy(name, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", NAME_LENGTH);
    if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
		report_success();
	else
	{
		printf("Could not create new wallet\n");
		report_failure();
	}

	finish_time = clock();

	is_test = false;
	time_spent = ((double)(finish_time - start_time)) / CLOCKS_PER_SEC;

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;

	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
	{
		;
	}
	else
	{
		printf("getWalletInfo() failed after sanitiseNonVolatileStorage() was called\n");
	}
	printf("version: %d\n", version);
	printf("name: %s\n", temp);
	printf("wallet_uuid: ");
	for (int i = 0; i < UUID_LENGTH; i++)
	{
		printf("%02x", wallet_uuid[i]);
	}
	printf("\n");
}

void check_if_master_key_exists(statistics *stats)
{
    uint8_t chain_code[32];
    PointAffine master_public_key;

	is_test = true;
	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	start_time = clock();

    printf("[*] check if a master key exists\n");
	if (getMasterPublicKey(&master_public_key, chain_code) != WALLET_NO_ERROR)
	{
		printf("getMasterPublicKey() fails in the simplest case\n");
		report_failure();
	}
	else
    {
		report_success();
    }

	finish_time = clock();

	is_test = false;
	time_spent = ((double)(finish_time - start_time)) / CLOCKS_PER_SEC;

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;

	printf("master_public_key.x: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", master_public_key.x[i]);
	}
	printf("\n");
	printf("master_public_key.y: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", master_public_key.y[i]);
	}
	printf("\n");
}

void mnemonic_to_master_key(statistics *stats)
{
    uint8_t uuid[UUID_LENGTH] = {0x0};
    char *mnemonic = "THIS_IS_MY_MNEMONIC\x00";
    size_t mnemonic_length = strlen(mnemonic);

	is_test = true;
	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	start_time = clock();

	printf("[*] using mnemonic to create encryption key\n");
    deriveAndSetEncryptionKeyTZ(uuid, mnemonic, mnemonic_length);

	finish_time = clock();

	is_test = false;
	time_spent = ((double)(finish_time - start_time)) / CLOCKS_PER_SEC;

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}

void get_address(statistics *stats)
{
	AddressHandle ah;
	PointAffine public_key;
	PointAffine public_key_buffer;
	uint8_t address[20];
	uint8_t address_buffer[20];

	ah = makeNewAddress(address_buffer, &public_key_buffer);
	if (ah == BAD_ADDRESS_HANDLE)
	{
		printf("Couldn't create new address in new wallet\n");
	}

	is_test = true;
	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	start_time = clock();

	printf("[*] get a new address from tee\n");

	if (getAddressAndPublicKey(address, &public_key, ah) != WALLET_NO_ERROR)
	{
		printf("Couldn't obtain address in wallet\n");
		report_failure();
	}
	else
	{
		printf("address: ");
		for (int i = 0; i < 20; i++)
		{
			printf("%02x", address[i]);
		}
		printf("\n");
		report_success();
	}

	finish_time = clock();

	is_test = false;
	time_spent = ((double)(finish_time - start_time)) / CLOCKS_PER_SEC;

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;

	if ((memcmp(address, address_buffer, 20)) || (bigCompare(public_key.x, public_key_buffer.x) != BIGCMP_EQUAL) || (bigCompare(public_key.y, public_key_buffer.y) != BIGCMP_EQUAL))
	{
		printf("getAddressAndPublicKey() returned mismatching address or public key\n");
	}
}

void sign_transaction(statistics *stats)
{
	uint32_t test_hs[8];
	uint8_t sig_hash[32];
	uint8_t calculated_sig_hash[32];
	uint8_t transaction_hash[32];

	is_test = true;
	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	start_time = clock();

	printf("[*] signing a transaction\n");
	setTestInputStream(rw_good_full_transaction, sizeof(rw_good_full_transaction));
	parseTransaction(sig_hash, transaction_hash, sizeof(rw_good_full_transaction));

	sha256BeginTZ(1);

	sha256WriteTZ((uint8_t *)rw_good_main_transaction, (uint32_t)sizeof(rw_good_main_transaction), 1);

	sha256FinishDoubleTZ(test_hs, (uint32_t)32, 1);

	writeHashToByteArrayTZ(calculated_sig_hash, test_hs, false);

	if (memcmp(calculated_sig_hash, sig_hash, 32))
	{
		printf("parseTransaction() isn't calculating signature hash properly\n");
		report_failure();
	}
	else
    {
		report_success();
    }

	finish_time = clock();

	is_test = false;
	time_spent = ((double)(finish_time - start_time)) / CLOCKS_PER_SEC;

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}

void delete_master_key(statistics *stats)
{
	is_test = true;
	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	start_time = clock();

	printf("[*] delete the wallet to delete master key\n");
	if (deleteWallet(0) == WALLET_NO_ERROR)
		report_success();
	else
	{
		printf("deleteWallet() failed\n");
		report_failure();
	}

	finish_time = clock();

	is_test = false;
	time_spent = ((double)(finish_time - start_time)) / CLOCKS_PER_SEC;

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}

void test_all(statistics *stats, bool do_create_master_key, bool do_check_if_master_key_exists, 
				bool do_get_address, bool do_sign_transaction, bool do_delete_master_key)
{

    // init wallet storage
    createWalletStorage();
    openWalletStorage();
	initialiseDefaultEntropyPool();

	// suppress_set_entropy_pool = false;

    // do test
	if (do_create_master_key)
	    create_master_key(stats);
	if (do_check_if_master_key_exists)
		check_if_master_key_exists(stats);
    // mnemonic_to_master_key(stats);
	if (do_get_address)
		get_address(stats);
	if (do_sign_transaction)
		sign_transaction(stats);
	if (do_delete_master_key)
		delete_master_key(stats);

    // uninit wallet storage
    closeWalletStorage();
	deleteWalletStorage();
}
