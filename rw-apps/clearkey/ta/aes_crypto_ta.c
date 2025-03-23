/**
 * Copyright (C) STM 2016. Linaro LTD
 * Author: Zoltan Kuscsik <zoltan.kuscsik@linaro.org>
 *         Peter Griffin <peter.griffin@linaro.org>
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <aes_crypto_ta.h>

#define STR_TRACE_USER_TA "SECAES_DEMO"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define CHECK(res, name, action) do { \
    if ((res) != TEE_SUCCESS) { \
      EMSG(name ": 0x%08x", (res)); \
      action \
    } \
  } while(0)

static TEE_OperationHandle crypto_op = NULL;

/*==============================================================================
  SESSION DATA STRUCTURE
==============================================================================*/
/** Session data. The Trusted Application can attach an opaque void* context to
 * the session . This context is recalled in all subsequent TA calls within
 * the session.
 */
typedef struct session_data
{
  ;
} Session_data;

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
  return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */

void TA_DestroyEntryPoint(void)
{
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param  params[4], void **sess_ctx)
{
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
               TEE_PARAM_TYPE_NONE,
               TEE_PARAM_TYPE_NONE,
               TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  /* Unused parameters */
  (void)&params;
  (void)&sess_ctx;

  /*
   * The DMSG() macro is non-standard, TEE Internal API doesn't
   * specify any means to logging from a TA.
   */
  DMSG("Session created");
  /* If return value != TEE_SUCCESS the session will not be created. */
  return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
  (void)&sess_ctx; /* Unused parameter */

  if (crypto_op)
    TEE_FreeOperation(crypto_op);
  DMSG("Session closed");
}

static TEE_Result allocate_crypto_op(uint8_t *key, uint32_t key_size)
{
  TEE_Result res;
  TEE_ObjectHandle hkey;
  TEE_Attribute attr;

  res = TEE_AllocateOperation(&crypto_op, TEE_ALG_AES_CTR,
                              TEE_MODE_DECRYPT, 128);
  CHECK(res, "TEE_AllocateOperation", return res;);

  res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &hkey);
  CHECK(res, "TEE_AllocateTransientObject", return res;);

  attr.attributeID = TEE_ATTR_SECRET_VALUE;
  attr.content.ref.buffer = key;
  attr.content.ref.length = key_size;

  res = TEE_PopulateTransientObject(hkey, &attr, 1);
  CHECK(res, "TEE_PopulateTransientObject", return res;);

  res = TEE_SetOperationKey(crypto_op, hkey);
  CHECK(res, "TEE_SetOperationKey", return res;);

  TEE_FreeTransientObject(hkey);

  return res;
}

/* Decrypt chunk of data */
static TEE_Result decrypt_128_ctr_aes(void *in, uint32_t sz, /*input buffer and size */
        void *out, uint32_t *outsz, /*output buffer and size */
        uint8_t* aes_key, uint32_t aes_key_size, /* AES key */
        uint8_t* iv, uint8_t iv_size /*AES IV */
    )
{
  TEE_Result res;

  if (!crypto_op) {
    res = allocate_crypto_op(aes_key, aes_key_size);
    CHECK(res, "allocate_crypto_op", return res;);
  }

  TEE_CipherInit(crypto_op, iv, iv_size);
  res = TEE_CipherDoFinal(crypto_op, in, sz, out, outsz);
  CHECK(res, "TEE_CipherDoFinal", return res;);
  if(*outsz != sz) {
    EMSG("FXIME: output buffer size does not match the input buffer size");
    return TEE_ERROR_GENERIC;
  }
  return TEE_SUCCESS;
}

static TEE_Result aes_Ctr128_Encrypt(uint32_t param_types, TEE_Param params[4])
{
  TEE_Result res;
  void *buf, *outbuf, *iv, *key;
  uint32_t sz, outsz,  iv_size, key_size;

  uint32_t exp_param_types = AES_CTR128_ENCRYPT_TEE_PARAM_TYPES;

  if (param_types != exp_param_types) {
    EMSG("%s: bad parameters\n",__func__);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  /* Input buffer */
  buf = params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.buffer;
  sz = params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.size;

  outbuf = params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.buffer;
  outsz = params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.size;

  /* AES IV */
  iv = params[PARAM_AES_IV_IDX].memref.buffer;
  iv_size = params[PARAM_AES_IV_IDX].memref.size;

  /* AES KEY
   *
   * Here we are passing clearkey only. For non-clear key implementation
   * we have to add a flag on setting the key type and use a key Id instead
   * of passing around the key in open.
   *
   * */
  key = params[PARAM_AES_KEY].memref.buffer;
  key_size = params[PARAM_AES_KEY].memref.size;

  if (key_size == 0 || sz == 0 || outsz == 0 || sz > outsz
      || buf == NULL || outbuf == NULL) {
    EMSG("%s: buffer too short\n", __func__);
    return TEE_ERROR_SHORT_BUFFER;
  }

#ifdef CFG_SECURE_DATA_PATH
  /* Validate that the destination buffer is actually in secure memory.
   * This is mandatory to protect against a malicious REE application
   * sending a shared (non-secure) memory buffer but identifying it as
   * a 'Secure' buffer type. */
  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
				    TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_SECURE,
				    outbuf, outsz);

  if (res != TEE_SUCCESS) {
    EMSG("%s: WARNING: output buffer is not in secure memory", __func__);
    return TEE_ERROR_SECURITY;
  }
#else
  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
				    TEE_MEMORY_ACCESS_WRITE,
				    outbuf, outsz);

  if (res != TEE_SUCCESS) {
    EMSG("%s: WARNING: output buffer is not writeable", __func__);
    return TEE_ERROR_ACCESS_DENIED;
  }
#endif

#ifdef CFG_CACHE_API
  res = TEE_CacheFlush((char *)outbuf, outsz);
  CHECK(res, "TEE_CacheFlush", return res;);
#endif

  res = decrypt_128_ctr_aes(buf, sz, outbuf, &outsz,
            (uint8_t*) key, key_size,
            (uint8_t*) iv,  iv_size
           );

  if (res != TEE_SUCCESS) {
      EMSG("%s: decrypt_128_ctr_aes failed\n", __func__);
      return res;
  }

#ifdef CFG_CACHE_API
  res = TEE_CacheFlush((char *)outbuf, outsz);
  CHECK(res, "TEE_CacheFlush", return res;);
#endif

  return TEE_SUCCESS;
}

static TEE_Result copy_secure_memory(uint32_t param_types, TEE_Param params[4])
{
  TEE_Result res;
  void *inbuf, *outbuf;
  uint32_t insz, outsz;

  uint32_t exp_param_types = COPY_SECURE_MEMORY_TEE_PARAM_TYPES;

  if (param_types != exp_param_types) {
    EMSG("%s: incorrect parameters", __func__);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  /* Input buffer */
  inbuf = params[PARAM_COPY_SECURE_MEMORY_SOURCE].memref.buffer;
  insz = params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.size;

  outbuf = params[PARAM_COPY_SECURE_MEMORY_DESTINATION].memref.buffer;
  outsz = params[PARAM_COPY_SECURE_MEMORY_DESTINATION].memref.size;

  if (!inbuf || insz == 0 || outsz == 0 || !outbuf) {
    EMSG("%s: incorrect parameters", __func__);
    return TEE_ERROR_BAD_FORMAT;
  }

  if (insz > outsz) {
    EMSG("%s: output buffer too small", __func__);
    return TEE_ERROR_BAD_FORMAT;
  }

#ifdef CFG_SECURE_DATA_PATH
  /* Validate that the destination buffer is actually in secure memory.
   * This is mandatory to protect against a malicious REE application
   * sending a shared (non-secure) memory buffer but identifying it as
   * a 'Secure' buffer type. */
  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
				    TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_SECURE,
				    outbuf, outsz);

  if (res != TEE_SUCCESS) {
    EMSG("%s: WARNING: output buffer is not in secure memory", __func__);
    return TEE_ERROR_SECURITY;
  }
#else
  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
				    TEE_MEMORY_ACCESS_WRITE,
				    outbuf, outsz);

  if (res != TEE_SUCCESS) {
    EMSG("%s: WARNING: output buffer is not writeable", __func__);
    return TEE_ERROR_ACCESS_DENIED;
  }
#endif

#ifdef CFG_CACHE_API
  res = TEE_CacheFlush((char *)outbuf, outsz);
  CHECK(res, "TEE_CacheFlush", return res;);
#endif

  /* inject data */
  TEE_MemMove(outbuf, inbuf, insz);

#ifdef CFG_CACHE_API
  res = TEE_CacheFlush((char *)outbuf, outsz);
  CHECK(res, "TEE_CacheFlush", return res;);
#endif

  return TEE_SUCCESS;
}

#define CTR_AES_BLOCK_SIZE  16
#define CTR_AES_IV_SIZE CTR_AES_BLOCK_SIZE
#define CTR_AES_KEY_SIZE CTR_AES_BLOCK_SIZE

struct sub_sample_t {
    uint32_t clear_bytes;
    uint32_t encrp_bytes;
};

static TEE_Result aes_Ctr128_Encrypt_secure(uint32_t param_types,
                                     TEE_Param params[TEE_NUM_PARAMS])
{
  TEE_Result res = TEE_SUCCESS;
  void *key, *iv, *inbuf, *outbuf, *iter_in, *iter_out;
  uint32_t insz, outsz, offset = 0;
  struct sub_sample_t *sub_samples;
  uint8_t *samples_end;
  uint32_t  exp_param_types = AES_CTR128_ENCRYPT_SECURE_TEE_PARAM_TYPES;

  if (param_types != exp_param_types) {
    EMSG("%s: incorrect parameters", __func__);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  if (params[0].memref.buffer == NULL || params[0].memref.size == 0)
    return TEE_ERROR_BAD_PARAMETERS;

  if (params[1].memref.buffer == NULL || params[1].memref.size == 0)
    return TEE_ERROR_BAD_PARAMETERS;

  if (params[2].memref.buffer == NULL ||
      params[2].memref.size < sizeof(struct sub_sample_t))
    return TEE_ERROR_BAD_PARAMETERS;

  if (params[3].memref.buffer == NULL ||
      params[3].memref.size < CTR_AES_KEY_SIZE + CTR_AES_IV_SIZE)
    return TEE_ERROR_BAD_PARAMETERS;

  inbuf = params[0].memref.buffer;
  insz = params[0].memref.size;
  outbuf = params[1].memref.buffer;
  outsz = params[1].memref.size;
  sub_samples = (struct sub_sample_t *)params[2].memref.buffer;
  samples_end = ((uint8_t *)params[2].memref.buffer + params[2].memref.size);

  /*Encrypt_secure function only be called in 'CFG_SECURE_DATA_PATH=y' case */
  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
                                    TEE_MEMORY_ACCESS_WRITE |
                                    TEE_MEMORY_ACCESS_SECURE,
                                    outbuf, outsz);
  if (res != TEE_SUCCESS) {
    EMSG("%s: WARNING: output buffer is not in secure memory", __func__);
    return TEE_ERROR_SECURITY;
  }

  key = params[3].memref.buffer;
  iv = (uint8_t*)key + CTR_AES_KEY_SIZE;
  iter_in = inbuf;
  iter_out = outbuf;

  while ((uint8_t *)sub_samples < samples_end && 
         sub_samples->clear_bytes != 0xFFFFFFFF) {
    if (sub_samples->clear_bytes) {
      /*
       * Buffer overflow checking. Offset starts from ZERO;
       * use minus here for size checking in case integer overflow.
       */
      if (insz - offset < sub_samples->clear_bytes ||
          outsz - offset < sub_samples->clear_bytes)
        return TEE_ERROR_BAD_PARAMETERS;

      TEE_MemMove(iter_out, iter_in, sub_samples->clear_bytes);
                  offset += sub_samples->clear_bytes;
      iter_out = (uint8_t *)outbuf + offset;
      iter_in = (uint8_t *)inbuf + offset;
    }
    if (sub_samples->encrp_bytes) {
      if (!crypto_op) {
        res = allocate_crypto_op(key, CTR_AES_KEY_SIZE);
        CHECK(res, "allocate_crypto_op", return res;);
      }
      /*
       * Buffer overflow checking. Offset starts from ZERO;
       * use minus here for size checking in case integer overflow.
       */
      if (insz - offset < sub_samples->encrp_bytes ||
          outsz - offset < sub_samples->encrp_bytes)
        return TEE_ERROR_BAD_PARAMETERS;

      TEE_CipherInit(crypto_op, iv, CTR_AES_IV_SIZE);
      res = TEE_CipherDoFinal(crypto_op,
                              iter_in, sub_samples->encrp_bytes,
                              iter_out, &sub_samples->encrp_bytes);
      offset += sub_samples->encrp_bytes;
      iter_out = (uint8_t *)outbuf + offset;
      iter_in = (uint8_t *)inbuf + offset;
    }
    sub_samples++;
  }

#ifdef CFG_CACHE_API
  res = TEE_CacheFlush((char *)outbuf, offset);
#endif

  return res;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
      uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
  (void)&sess_ctx; /* Unused parameter */

  switch (cmd_id)
  {
  case TA_AES_CTR128_ENCRYPT:
    return aes_Ctr128_Encrypt(param_types, params);
  case TA_COPY_SECURE_MEMORY:
    return copy_secure_memory(param_types, params);
  case TA_AES_CTR128_SECURE_ENCRYPT:
    return aes_Ctr128_Encrypt_secure(param_types, params);
  default:
    return TEE_ERROR_BAD_PARAMETERS;
  }
}
