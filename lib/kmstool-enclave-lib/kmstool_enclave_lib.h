#ifndef KMSTOOL_ENCLAVE_LIB_H
#define KMSTOOL_ENCLAVE_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

/* Enum to represent the result of KMS operations. */
enum RESULT {
    ENCLAVE_KMS_ERROR = -1,  /* Operation failed. */
    ENCLAVE_KMS_SUCCESS = 0, /* Operation succeeded. */
};

/* Struct to hold initialization parameters for the KMS tool enclave. */
struct kmstool_init_params {
    /* KMS region to use. */
    const char *region;
    /* vsock port on which vsock-proxy is available in parent. */
    const unsigned int proxy_port;

    /* KMS credentials */
    const char *aws_access_key_id;
    const char *aws_secret_access_key;
    const char *aws_session_token;

    /* KMS key */
    const char *key_id;
    const char *encryption_algorithm;

    const unsigned int with_logs;
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
    /* Plaintext to encrypt (must be base64-encoded) */
    const char *plaintext_b64;
};

int kmstool_enclave_encrypt(const struct kmstool_encrypt_params *params, char **ciphertext_b64_out);

struct kmstool_decrypt_params {
    /* Ciphertext to decrypt (must be base64-encoded) */
    const char *ciphertext_b64;
};

/**
 * Decrypts the given ciphertext using the enclave KMS.
 *
 * @param param Pointer to the decryption parameters.
 * @param plaintext_b64_out Pointer to store the decrypted plaintext (must be freed by caller).
 * @return ENCLAVE_KMS_SUCCESS on success, ENCLAVE_KMS_ERROR on failure.
 */
int kmstool_enclave_decrypt(const struct kmstool_decrypt_params *params, char **plaintext_b64_out);

#ifdef __cplusplus
}
#endif

#endif /* KMSTOOL_ENCLAVE_LIB_H */