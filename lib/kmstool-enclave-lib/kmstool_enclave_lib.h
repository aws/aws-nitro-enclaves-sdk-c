#ifndef KMSTOOL_ENCLAVE_LIB_H
#define KMSTOOL_ENCLAVE_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Enum to represent the result of KMS operations. */
enum RESULT {
    ENCLAVE_KMS_ERROR = -1,  /* Operation failed. */
    ENCLAVE_KMS_SUCCESS = 0, /* Operation succeeded. */
};

/* Struct to hold initialization parameters for the KMS tool enclave. */
struct kmstool_init_params {
    const unsigned int with_logs;

    /* vsock port on which vsock-proxy is available in parent. */
    const unsigned int proxy_port;

    /* KMS region to use. */
    const char *region;

    /* KMS credentials */
    const char *aws_access_key_id;
    const char *aws_secret_access_key;
    const char *aws_session_token;

    /* KMS key */
    const char *key_id;
    const char *encryption_algorithm;
};

/**
 * Initializes the enclave with the given KMS parameters.
 *
 * @param param Pointer to the enclave initialization parameters.
 * @return ENCLAVE_KMS_SUCCESS on success, ENCLAVE_KMS_ERROR on failure.
 */
int kmstool_enclave_init(const struct kmstool_init_params *params);

/**
 * Stops the enclave and cleans up any allocated resources.
 *
 * @return ENCLAVE_KMS_SUCCESS on success, ENCLAVE_KMS_ERROR on failure.
 */
int kmstool_enclave_stop(void);

struct kmstool_update_aws_key_params {
    /* KMS credentials (optional if already set) */
    const char *aws_access_key_id;
    const char *aws_secret_access_key;
    const char *aws_session_token;
};

/**
 * Updates the AWS KMS key credentials inside the enclave.
 *
 * @param param Pointer to the AWS key parameters.
 * @return ENCLAVE_KMS_SUCCESS on success, ENCLAVE_KMS_ERROR on failure.
 */
int kmstool_enclave_update_aws_key(const struct kmstool_update_aws_key_params *params);

struct kmstool_encrypt_params {
    /* Plaintext to encrypt */
    const uint8_t *plaintext;
    const size_t plaintext_len;
};

int kmstool_enclave_encrypt(
    const struct kmstool_encrypt_params *params,
    uint8_t **ciphertext_out,
    size_t *ciphertext_out_len);

struct kmstool_decrypt_params {
    /* Ciphertext to decrypt */
    const uint8_t *ciphertext;
    const size_t ciphertext_len;
};

/**
 * Decrypts the given ciphertext using the enclave KMS.
 *
 * @param param Pointer to the decryption parameters.
 * @param plaintext_b64_out Pointer to store the decrypted plaintext (must be freed by caller).
 * @return ENCLAVE_KMS_SUCCESS on success, ENCLAVE_KMS_ERROR on failure.
 */
int kmstool_enclave_decrypt(
    const struct kmstool_decrypt_params *params,
    uint8_t **plaintext_out,
    size_t *plaintext_out_len);

#ifdef __cplusplus
}
#endif

#endif /* KMSTOOL_ENCLAVE_LIB_H */