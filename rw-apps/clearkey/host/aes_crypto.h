/*
 * Copyright (c) 2015, Linaro Limited
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

#ifndef OPTEE_AES_DECRYPT_HOST_H_
#define OPTEE_AES_DECRYPT_HOST_H_

#include <endian.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CTR_AES_BLOCK_SIZE  16
#define CTR_AES_IV_SIZE CTR_AES_BLOCK_SIZE
#define CTR_AES_KEY_SIZE CTR_AES_BLOCK_SIZE

/* sub_frame data desc struct */
typedef struct _sub_sample_t {
    uint32_t clear_bytes;
    uint32_t encrp_bytes;
} sub_sample_t;

/* Initialize OP TEE and allocate shared memory*/
int
TEE_crypto_init();

/* AES CTR 128 decryption/encryption */
int
TEE_AES_ctr128_encrypt(const unsigned char* in_data,
    unsigned char* out_data,
    uint32_t length, const char* key,
    unsigned char iv[CTR_AES_BLOCK_SIZE],
    unsigned char ecount_buf[CTR_AES_BLOCK_SIZE],
    unsigned int *num,
    uint32_t offset,
    bool secure);

/* AES CTR 128 decryption/encryption for secure buffer */
int
TEE_AES_ctr128_encrypt_secure(const unsigned char* in_data,
    unsigned char* out_data,
    const sub_sample_t* samples,
    uint32_t num_samples,
    const char* key,
    unsigned char iv[CTR_AES_BLOCK_SIZE],
    uint32_t *length);

/* Copy from source buffer to secure dest buffer */
int TEE_copy_secure_memory(const unsigned char* in_data,
    unsigned char* out_data,
    uint32_t length,
    uint32_t offset);

/* Close TEE session and close memory*/
int
TEE_crypto_close();

#ifdef __cplusplus
}
#endif

#endif
