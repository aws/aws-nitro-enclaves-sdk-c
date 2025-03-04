#ifndef KMSTOOL_ENCLAVE_LIB_H
#define KMSTOOL_ENCLAVE_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @file kmstool_enclave_lib.h
 * @brief Public interface for the AWS KMS Tool Enclave Library
 *
 * This library provides a secure interface for AWS KMS operations within Nitro Enclaves.
 * It handles encryption, decryption, and key management operations using AWS KMS,
 * while maintaining the security guarantees provided by the enclave environment.
 */

/**
 * @brief Status codes for KMS Tool operations
 *
 * These status codes indicate the result of KMS Tool operations.
 * All functions in this library return one of these values.
 */
enum kmstool_status {
    KMSTOOL_ERROR = -1,  /* Operation failed */
    KMSTOOL_SUCCESS = 0, /* Operation succeeded */
};

/**
 * @brief Initialization parameters for the KMS Tool enclave
 *
 * This structure contains all the necessary parameters to initialize
 * the KMS Tool enclave, including AWS credentials, region settings,
 * and encryption parameters.
 */
struct kmstool_init_params {
    const unsigned int enable_logging; /* Enable logging if set to 1 */

    /* vsock port on which vsock-proxy is available in parent */
    const unsigned int proxy_port;

    /* AWS configuration */
    const char *aws_region;            /* AWS region for KMS operations */
    const char *aws_access_key_id;     /* AWS access key ID */
    const char *aws_secret_access_key; /* AWS secret access key */
    const char *aws_session_token;     /* AWS session token */

    /* KMS configuration */
    const char *kms_key_id;    /* KMS key ID to use for operations */
    const char *kms_algorithm; /* KMS encryption algorithm to use */
};

/**
 * @brief Parameters for updating AWS credentials
 *
 * This structure contains the parameters needed to update the AWS credentials
 * for an already initialized KMS Tool enclave.
 */
struct kmstool_update_aws_key_params {
    const char *aws_access_key_id;     /* New AWS access key ID */
    const char *aws_secret_access_key; /* New AWS secret access key */
    const char *aws_session_token;     /* New AWS session token */
};

/**
 * @brief Parameters for encryption operation
 *
 * This structure contains the data to be encrypted using KMS.
 */
struct kmstool_encrypt_params {
    const uint8_t *plaintext;   /* Data to encrypt */
    const size_t plaintext_len; /* Length of data to encrypt */
};

/**
 * @brief Parameters for decryption operation
 *
 * This structure contains the data to be decrypted using KMS.
 */
struct kmstool_decrypt_params {
    const uint8_t *ciphertext;   /* Data to decrypt */
    const size_t ciphertext_len; /* Length of data to decrypt */
};

/**
 * @brief Initialize the KMS Tool enclave with the given parameters
 *
 * This function must be called before performing any KMS operations.
 * It sets up the AWS credentials, KMS client, and other necessary resources.
 *
 * @param params Pointer to initialization parameters
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
int kmstool_enclave_init(const struct kmstool_init_params *params);

/**
 * @brief Clean up and stop the KMS Tool enclave
 *
 * This function releases all resources associated with the KMS Tool enclave.
 * It should be called when the enclave is no longer needed.
 *
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
int kmstool_enclave_stop(void);

/**
 * @brief Update AWS credentials for the KMS Tool enclave
 *
 * This function updates the AWS credentials used by the KMS Tool enclave.
 * The enclave must be initialized before calling this function.
 *
 * @param params Pointer to the new AWS credentials
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
int kmstool_enclave_update_aws_key(const struct kmstool_update_aws_key_params *params);

/**
 * @brief Encrypt data using KMS
 *
 * This function encrypts the provided plaintext using the configured KMS key
 * and encryption algorithm.
 *
 * @param params Pointer to encryption parameters
 * @param ciphertext_out Pointer to store the encrypted data (caller must free)
 * @param ciphertext_out_len Pointer to store the length of encrypted data
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
int kmstool_enclave_encrypt(
    const struct kmstool_encrypt_params *params,
    uint8_t **ciphertext_out,
    size_t *ciphertext_out_len);

/**
 * @brief Decrypt data using KMS
 *
 * This function decrypts the provided ciphertext using the configured KMS key
 * and encryption algorithm.
 *
 * @param params Pointer to decryption parameters
 * @param plaintext_out Pointer to store the decrypted data (caller must free)
 * @param plaintext_out_len Pointer to store the length of decrypted data
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
int kmstool_enclave_decrypt(
    const struct kmstool_decrypt_params *params,
    uint8_t **plaintext_out,
    size_t *plaintext_out_len);

#ifdef __cplusplus
}
#endif

#endif /* KMSTOOL_ENCLAVE_LIB_H */