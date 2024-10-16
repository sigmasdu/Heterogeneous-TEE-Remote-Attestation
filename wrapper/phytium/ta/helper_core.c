#include "helper_core.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_csr.h>
#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

typedef struct sess_ctx_t {
  TEE_ObjectHandle obj1;
  TEE_ObjectHandle obj2;
} Sess_ctx_t;

static const char object1_id[] = "helper_core_sm4_key";
static const char object2_id[] = "helper_core_sm3_key";

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4] __unused,
                                    void **sess_ctx) {
  uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  *sess_ctx = TEE_Malloc(sizeof(Sess_ctx_t), TEE_MALLOC_FILL_ZERO);
  if (*sess_ctx == NULL)
    return TEE_ERROR_OUT_OF_MEMORY;

  return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
  Sess_ctx_t *ctx = (Sess_ctx_t *)sess_ctx;

  if (ctx) {
    if (ctx->obj1 != TEE_HANDLE_NULL) {
      TEE_FreeTransientObject(ctx->obj1);
      ctx->obj1 = TEE_HANDLE_NULL;
    }

    if (ctx->obj2 != TEE_HANDLE_NULL) {
      TEE_FreeTransientObject(ctx->obj2);
      ctx->obj2 = TEE_HANDLE_NULL;
    }
    TEE_Free(ctx);
  }
}

static TEE_Result helper_init(Sess_ctx_t *ctx, uint32_t param_types __unused,
                              TEE_Param params[4] __unused) {
  TEE_Result res = TEE_ERROR_GENERIC;
  TEE_ObjectHandle key1 = TEE_HANDLE_NULL;
  TEE_ObjectHandle key2 = TEE_HANDLE_NULL;

  uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
                   TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE |
                   TEE_DATA_FLAG_OVERWRITE;

  size_t key1_size = 128;
  size_t key2_size = 80;

  // Create key for SM4.
  res = TEE_AllocateTransientObject(TEE_TYPE_SM4, key1_size, &key1);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateTransientObject failed, ret %d.", res);
    return -1;
  }

  res = TEE_GenerateKey(key1, key1_size, NULL, 0);
  if (res != TEE_SUCCESS) {
    TEE_FreeTransientObject(key1);
    EMSG("TEE_GenerateKey failed, ret %d.", res);
    return -1;
  }

  res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_REE, object1_id,
                                   sizeof(object1_id), flags, key1, NULL, 0,
                                   &(ctx->obj1));
  if (res != TEE_SUCCESS) {
    TEE_FreeTransientObject(key1);
    EMSG("TEE_CreatePersistentObject failed, ret %d.", res);
    return -1;
  }

  TEE_FreeTransientObject(key1);

  TEE_CloseObject(ctx->obj1);
  ctx->obj1 = TEE_HANDLE_NULL;

  // Create key for SM3.
  res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SM3, key2_size, &key2);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_AllocateTransientObject failed, ret %d.", res);
    return -1;
  }

  res = TEE_GenerateKey(key2, key2_size, NULL, 0);
  if (res != TEE_SUCCESS) {
    TEE_FreeTransientObject(key2);
    EMSG("TEE_AllocateTransientObject failed, ret %d.", res);
    return -1;
  }

  res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_REE, object2_id,
                                   sizeof(object2_id), flags, key2, NULL, 0,
                                   &(ctx->obj2));
  if (res != TEE_SUCCESS) {
    TEE_FreeTransientObject(key2);
    EMSG("TEE_AllocateTransientObject failed, ret %d.", res);
    return -1;
  }

  TEE_FreeTransientObject(key2);

  TEE_CloseObject(ctx->obj2);
  ctx->obj2 = TEE_HANDLE_NULL;

  IMSG("Helper init finish.");
  return 0;
}

static int f_entropy(void *data, unsigned char *output, size_t size) {
  ((void)data);
  TEE_GenerateRandom(output, size);
  return 0;
}

static int generate_rsa_key(mbedtls_pk_context *key) {
  int ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) {
    return ret;
  }

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*key);
  mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  const char *pers = "rsa_gen";

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, f_entropy, &entropy,
                                   (const unsigned char *)pers,
                                   strlen(pers))) != 0) {
    EMSG("mbedtls_ctr_drbg_seed failed, ret %d.", ret);
    ret = -1;
    goto gen_key_out;
  }

  if ((ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048,
                                 65537)) != 0) {
    EMSG("mbedtls_rsa_gen_key failed, ret %d.", ret);
    ret = -1;
    goto gen_key_out;
  }

  ret = 0;

gen_key_out:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  return ret;
}

static TEE_Result gen_csr(mbedtls_pk_context *key, unsigned char *output_buf,
                          uint32_t buf_size) {
  TEE_Result ret = 0;
  mbedtls_x509write_csr req;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_x509write_csr_init(&req);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);

  const char *pers = "csr example app";
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, f_entropy, &entropy,
                                   (const unsigned char *)pers,
                                   strlen(pers))) != 0) {
    EMSG("mbedtls_ctr_drbg_seed failed, ret %d", ret);
    ret = -1;
    goto gen_csr_out;
  }

  char subject[1024];
  snprintf(subject, 1024, "C=%s,ST=%s,L=%s,O=%s,CN=%s", "CN", "Beijing",
           "Haidian", "Phytium", "Phytium");

  if ((ret = mbedtls_x509write_csr_set_subject_name(&req, subject)) != 0) {

    EMSG("mbedtls_x509write_csr_set_subject_name failed, ret %d", ret);
    ret = -1;
    goto gen_csr_out;
  }

  mbedtls_x509write_csr_set_key(&req, key);
  memset(output_buf, 0, buf_size);

  if ((ret = mbedtls_x509write_csr_pem(&req, output_buf, buf_size, f_entropy,
                                       &ctr_drbg)) != 0) {
    EMSG("mbedtls_x509write_csr_pem failed, ret %d.", ret);
    ret = -1;
    goto gen_csr_out;
  }

  ret = 0;

gen_csr_out:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_x509write_csr_free(&req);

  return ret;
}

static TEE_Result convert_key_to_string(mbedtls_pk_context *pk,
                                        unsigned char *pubkey,
                                        uint32_t pubkey_size,
                                        unsigned char *privkey,
                                        uint32_t privkey_size) {
  int ret = 0;
  ret = mbedtls_pk_write_key_pem(pk, privkey, privkey_size);
  if (ret != 0) {
    EMSG("mbedtls_pk_write_key_pem failed, ret %d.", ret);
    return ret;
  }

  ret = mbedtls_pk_write_pubkey_pem(pk, pubkey, pubkey_size);
  if (ret != 0) {
    EMSG("mbedtls_pk_write_pubkey_pem failed, ret %d.", ret);
    return ret;
  }

  return 0;
}

static TEE_Result seal_private_key(Sess_ctx_t *ctx, unsigned char *privkey,
                                   uint32_t key_size, unsigned char *seal_buf,
                                   uint32_t *seal_size, unsigned char *mac_buf,
                                   uint32_t *mac_size) {
  TEE_OperationHandle op1;
  TEE_OperationHandle op2;

  uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
                   TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE;

  TEE_Result res =
      TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE, object1_id,
                               sizeof(object1_id), flags, &(ctx->obj1));
  if (res != TEE_SUCCESS) {
    EMSG("TEE_OpenPersistentObject failed, ret %d.", res);
    return res;
  }

  res =
      TEE_AllocateOperation(&op1, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_ENCRYPT, 128);
  if (res != TEE_SUCCESS) {
    TEE_CloseObject(ctx->obj1);
    ctx->obj1 = TEE_HANDLE_NULL;
    EMSG("TEE_AllocateOperation failed, ret %d.", res);
    return res;
  }

  if (ctx->obj1 == NULL) {
    EMSG("Invalid ptr.");
    return -1;
  }

  res = TEE_SetOperationKey(op1, ctx->obj1);
  if (res != TEE_SUCCESS) {
    TEE_FreeOperation(op1);
    TEE_CloseObject(ctx->obj1);
    ctx->obj1 = TEE_HANDLE_NULL;
    EMSG("TEE_SetOperationKey failed, ret %d.", res);
    return res;
  }

  TEE_CipherInit(op1, NULL, 0);

  res = TEE_CipherUpdate(op1, privkey, key_size, seal_buf, seal_size);
  if (res != TEE_SUCCESS) {
    TEE_FreeOperation(op1);
    TEE_CloseObject(ctx->obj1);
    ctx->obj1 = TEE_HANDLE_NULL;
    EMSG("TEE_CipherUpdate failed, ret %d.", res);
    return res;
  }

  TEE_FreeOperation(op1);

  TEE_CloseObject(ctx->obj1);
  ctx->obj1 = TEE_HANDLE_NULL;

  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE, object2_id,
                                 sizeof(object2_id), flags, &(ctx->obj2));
  if (res != TEE_SUCCESS) {
    EMSG("TEE_OpenPersistentObject failed, ret %d.", res);
    return -1;
  }

  res = TEE_AllocateOperation(&op2, TEE_ALG_HMAC_SM3, TEE_MODE_MAC, 80);
  if (res != TEE_SUCCESS) {
    TEE_CloseObject(ctx->obj2);
    ctx->obj2 = TEE_HANDLE_NULL;
    EMSG("TEE_AllocateOperation failed, ret %d.", res);
    return -1;
  }

  res = TEE_SetOperationKey(op2, ctx->obj2);
  if (res != TEE_SUCCESS) {
    TEE_FreeOperation(op2);
    TEE_CloseObject(ctx->obj2);
    ctx->obj2 = TEE_HANDLE_NULL;
    EMSG("TEE_SetOperationKey failed, ret %d.", res);
    return -1;
  }

  TEE_MACInit(op2, NULL, 0);
  TEE_MACUpdate(op2, seal_buf, *seal_size);

  res = TEE_MACComputeFinal(op2, NULL, 0, mac_buf, mac_size);
  if (res) {
    EMSG("TEE_MACComputeFinal failed, ret %d.", res);
    return -1;
  }

  TEE_FreeOperation(op2);

  TEE_CloseObject(ctx->obj2);
  ctx->obj2 = TEE_HANDLE_NULL;

  return 0;
}

static TEE_Result helper_gen_key_and_csr(Sess_ctx_t *ctx,
                                         uint32_t param_types __unused,
                                         TEE_Param params[4]) {
  int ret = 0;

  // Generate RSA key.
  mbedtls_pk_context key;
  mbedtls_pk_init(&key);

  if ((ret = generate_rsa_key(&key)) != 0) {
    EMSG("Failed to generate RSA key: -0x%04X\n", -ret);
    return 1;
  }

  IMSG("Generate RSA key finish.");

  // Generate certificate signing request.
  if (params[0].memref.size < 1024) {
    EMSG("Buffer size is too small to save the csr content.");
    mbedtls_pk_free(&key);
    return -1;
  }

  unsigned char csr_content[1024];
  if (gen_csr(&key, csr_content, 1024) != 0) {
    EMSG("Generate certificate signing request failed.");
    mbedtls_pk_free(&key);
    return -1;
  }

  IMSG("Length of CSR content is %zu.", strlen((char *)csr_content));

  // Convert RSA key to string.
  if (params[1].memref.size < 2048) {
    EMSG("Buffer size is too small to save the public key string.");
    mbedtls_pk_free(&key);
    return -1;
  }

  unsigned char privkey[2048];
  unsigned char pubkey[2048];

  if (convert_key_to_string(&key, pubkey, 2048, privkey, 2048)) {
    EMSG("Convert RSA key to string failed.");
    mbedtls_pk_free(&key);
    return -1;
  }

  IMSG("Length of private key is %zu.", strlen((char *)privkey));
  IMSG("Length of public key is %zu.", strlen((char *)pubkey));

  // Seal the private key.
  if (params[2].memref.size < 2048) {
    EMSG("Buffer size is too small to save the sealed private key string.");
    mbedtls_pk_free(&key);
    return -1;
  }

  if (params[3].memref.size < 32) {
    EMSG("Buffer size is too small to save the mac result.");
    mbedtls_pk_free(&key);
    return -1;
  }

  unsigned char seal_key[2048];
  unsigned char mac[1024];
  uint32_t seal_size = 2048;
  uint32_t mac_size = 1024;
  if (seal_private_key(ctx, privkey, 2048, seal_key, &seal_size, mac,
                       &mac_size)) {
    mbedtls_pk_free(&key);
    EMSG("Seal private key failed.");
    return -1;
  }

  IMSG("Sizeof sealed private key is %u.", seal_size);
  IMSG("Sizeof mac result is %u.", mac_size);

  // Copy result.
  memcpy(params[0].memref.buffer, csr_content, strlen((char *)csr_content));
  memcpy(params[1].memref.buffer, pubkey, strlen((char *)pubkey));
  memcpy(params[2].memref.buffer, seal_key, seal_size);
  memcpy(params[3].memref.buffer, mac, mac_size);

  IMSG("Generate RSA key and certificate signing key then export them to "
       "outside finish.");

  mbedtls_pk_free(&key);
  return 0;
}

static TEE_Result unseal_private_key(Sess_ctx_t *ctx, unsigned char *ciphertext,
                                     unsigned char *mac,
                                     unsigned char *plaintext) {
  TEE_Result res;
  TEE_OperationHandle op1;
  TEE_OperationHandle op2;

  uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
                   TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE;

  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE, object2_id,
                                 sizeof(object2_id), flags, &(ctx->obj2));
  if (res != TEE_SUCCESS) {
    EMSG("TEE_OpenPersistentObject failed, ret %d.", res);
    return -1;
  }

  res = TEE_AllocateOperation(&op2, TEE_ALG_HMAC_SM3, TEE_MODE_MAC, 80);
  if (res != TEE_SUCCESS) {
    TEE_CloseObject(ctx->obj2);
    ctx->obj2 = TEE_HANDLE_NULL;
    EMSG("TEE_AllocateOperation failed, ret %d.", res);
    return -1;
  }

  res = TEE_SetOperationKey(op2, ctx->obj2);
  if (res != TEE_SUCCESS) {
    TEE_FreeOperation(op2);
    TEE_CloseObject(ctx->obj2);
    ctx->obj2 = TEE_HANDLE_NULL;
    EMSG("TEE_SetOperationKey failed, ret %d.", res);
    return -1;
  }

  TEE_MACInit(op2, NULL, 0);
  TEE_MACUpdate(op2, ciphertext, 2048);

  res = TEE_MACCompareFinal(op2, NULL, 0, mac, 32);
  if (res != TEE_SUCCESS) {
    TEE_FreeOperation(op2);
    TEE_CloseObject(ctx->obj2);
    ctx->obj2 = TEE_HANDLE_NULL;
    EMSG("TEE_MACCompareFinal failed, ret %d.", res);
    return -1;
  }

  TEE_FreeOperation(op2);
  TEE_CloseObject(ctx->obj2);

  ctx->obj2 = TEE_HANDLE_NULL;

  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE, object1_id,
                                 sizeof(object1_id), flags, &(ctx->obj1));
  if (res != TEE_SUCCESS) {
    EMSG("TEE_OpenPersistentObject failed, ret %d.", res);
    return -1;
  }

  res =
      TEE_AllocateOperation(&op1, TEE_ALG_SM4_ECB_NOPAD, TEE_MODE_DECRYPT, 128);
  if (res != TEE_SUCCESS) {
    TEE_CloseObject(ctx->obj1);
    ctx->obj1 = TEE_HANDLE_NULL;
    EMSG("TEE_AllocateOperation failed, ret %d.", res);
    return -1;
  }

  res = TEE_SetOperationKey(op1, ctx->obj1);
  if (res != TEE_SUCCESS) {
    TEE_FreeOperation(op1);
    TEE_CloseObject(ctx->obj1);
    ctx->obj1 = TEE_HANDLE_NULL;
    EMSG("TEE_SetOperationKey failed, ret %d.", res);
    return -1;
  }

  /* Unseal with SM4 algorithm */
  TEE_CipherInit(op1, NULL, 0);

  uint32_t plain_size = 2048;
  TEE_CipherUpdate(op1, ciphertext, 2048, plaintext, &plain_size);

  TEE_FreeOperation(op1);

  TEE_CloseObject(ctx->obj1);
  ctx->obj1 = TEE_HANDLE_NULL;

  return 0;
}

static TEE_Result import_key(unsigned char *key_str,
                             mbedtls_pk_context *pk_ctx) {
  TEE_Result ret = mbedtls_pk_parse_key(pk_ctx, key_str,
                                        strlen((char *)key_str) + 1, NULL, 0);
  if (ret != TEE_SUCCESS) {
    mbedtls_pk_free(pk_ctx);
    EMSG("Parse key from string failed.");
    return -1;
  }

  return 0;
}

static TEE_Result gen_sig(mbedtls_pk_context *pk_ctx, unsigned char *msg,
                          uint32_t msg_len, unsigned char *sig_buf,
                          size_t *buf_size) {
  unsigned char hash[MBEDTLS_MD_MAX_SIZE];
  mbedtls_md_context_t md_ctx;
  mbedtls_md_init(&md_ctx);
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  int ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 0);
  if (ret != 0) {
    EMSG("mbedtls_md_setup failed, ret %d.", ret);
    return -1;
  }

  ret = mbedtls_md_starts(&md_ctx);
  ret |= mbedtls_md_update(&md_ctx, msg, msg_len);
  ret |= mbedtls_md_finish(&md_ctx, hash);
  mbedtls_md_free(&md_ctx);

  ret = mbedtls_pk_sign(pk_ctx, MBEDTLS_MD_SHA256, hash, 0, sig_buf, buf_size,
                        NULL, NULL);
  if (ret != 0) {
    EMSG("mbedtls_pk_sign failed, ret %d.", ret);
    return -1;
  }

  return 0;
}

static void bin_to_hex(const unsigned char *s, size_t l, char *d) {
  static const char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                   '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  while (l--) {
    *(d + 2 * l + 1) = hex_table[(*(s + l)) & 0x0f];
    *(d + 2 * l) = hex_table[(*(s + l)) >> 4];
  }
}

static TEE_Result helper_gen_sig(Sess_ctx_t *ctx, uint32_t param_types __unused,
                                 TEE_Param params[4]) {
  if (params[0].memref.size != 2048) {
    EMSG("Sizeof sealed private key must be 2048 bytes, but gives %u.",
         params[0].memref.size);
    return -1;
  }

  if (params[1].memref.size != 32) {
    EMSG("Sizeof MAC must be 32 bytes, but gives %u.", params[1].memref.size);
    return -1;
  }

  unsigned char private_key[2048];
  memset(private_key, 0, 2048);
  if (unseal_private_key(ctx, params[0].memref.buffer, params[1].memref.buffer,
                         private_key) != TEE_SUCCESS) {
    EMSG("Unseal private key string failed.");
    return -1;
  }

  IMSG("Unseal private key finish, sizeof private key is %zu.",
       strlen((char *)private_key));

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  if (import_key(private_key, &pk) != TEE_SUCCESS) {
    EMSG("Recover private key from string failed.");
    mbedtls_pk_free(&pk);
    return -1;
  }

  IMSG("Import private key from string finish.");

  unsigned char sig_buf[2048];
  size_t buf_size = 2048;

  if (gen_sig(&pk, params[2].memref.buffer, params[2].memref.size, sig_buf,
              &buf_size) != TEE_SUCCESS) {
    EMSG("Generate digital signature failed.");
    mbedtls_pk_free(&pk);
    return -1;
  }

  IMSG("Sizeof signature is %zu.", buf_size);

  char sig_hex[4096];
  memset(sig_hex, 0, 4096);
  bin_to_hex(sig_buf, buf_size, sig_hex);

  IMSG("Sizeof hex string of signature result is %zu.",
       strlen((char *)sig_hex));

  if (params[3].memref.size < buf_size * 2 + 1) {
    EMSG("Too small buf size to save the hex string of signature result.");
    mbedtls_pk_free(&pk);
    return -1;
  }

  memcpy(params[3].memref.buffer, sig_hex, strlen((char *)sig_hex));

  mbedtls_pk_free(&pk);
  return 0;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4]) {
  Sess_ctx_t *ctx = (Sess_ctx_t *)sess_ctx;

  switch (cmd_id) {
  case HELPER_INIT:
    return helper_init(ctx, param_types, params);
  case HELPER_GEN_KEY_AND_CSR:
    return helper_gen_key_and_csr(ctx, param_types, params);
  case HELPER_DIGITAL_SIGNATURE:
    return helper_gen_sig(ctx, param_types, params);
  default:
    return TEE_ERROR_BAD_PARAMETERS;
  }

  return TEE_SUCCESS;
}
