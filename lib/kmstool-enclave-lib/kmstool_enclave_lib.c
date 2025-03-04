#include "kmstool_enclave_lib.h"
#include "include/kmstool_decrypt.h"
#include "include/kmstool_encrypt.h"
#include "include/kmstool_init.h"

/**
 * @file kmstool_enclave_lib.c
 * @brief Implementation of the AWS KMS Tool Enclave Library
 *
 * This file implements the public interface for the AWS KMS Tool Enclave Library.
 * It provides a secure way to perform KMS operations within Nitro Enclaves by
 * managing a global application context and delegating operations to the
 * appropriate internal modules.
 */

/* Global static application context for managing KMS operations */
static struct app_ctx g_ctx = {0};

/* Define API export macro for different platforms */
#ifdef _WIN32
#    define API_EXPORT __declspec(dllexport)
#else
#    define API_EXPORT __attribute__((visibility("default")))
#endif

/**
 * @brief Initialize the KMS Tool enclave
 *
 * Initializes the global application context with the provided parameters
 * and sets up all necessary resources for KMS operations.
 *
 * @param params Configuration parameters including AWS credentials and settings
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
API_EXPORT int kmstool_enclave_init(const struct kmstool_init_params *params) {
    return app_lib_init(&g_ctx, params);
}

/**
 * @brief Stop and clean up the KMS Tool enclave
 *
 * Releases all resources associated with the global application context
 * and performs necessary cleanup operations.
 *
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
API_EXPORT int kmstool_enclave_stop() {
    return app_lib_clean_up(&g_ctx);
}

/**
 * @brief Update AWS credentials
 *
 * Updates the AWS credentials in the global application context and
 * reinitializes the KMS client with the new credentials.
 *
 * @param params New AWS credentials to use
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
API_EXPORT int kmstool_enclave_update_aws_key(const struct kmstool_update_aws_key_params *params) {
    return app_lib_update_aws_key(&g_ctx, params);
}

/**
 * @brief Encrypt data using KMS
 *
 * Encrypts the provided plaintext using the configured KMS key and algorithm.
 * The encrypted data is allocated and must be freed by the caller.
 *
 * @param params Encryption parameters including plaintext data
 * @param ciphertext_out Pointer to store the encrypted data
 * @param ciphertext_out_len Pointer to store the length of encrypted data
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
API_EXPORT int kmstool_enclave_encrypt(
    const struct kmstool_encrypt_params *params,
    uint8_t **ciphertext_out,
    size_t *ciphertext_out_len) {
    return app_lib_encrypt(&g_ctx, params, ciphertext_out, ciphertext_out_len);
}

/**
 * @brief Decrypt data using KMS
 *
 * Decrypts the provided ciphertext using the configured KMS key and algorithm.
 * The decrypted data is allocated and must be freed by the caller.
 *
 * @param params Decryption parameters including ciphertext data
 * @param plaintext_out Pointer to store the decrypted data
 * @param plaintext_out_len Pointer to store the length of decrypted data
 * @return KMSTOOL_SUCCESS on success, KMSTOOL_ERROR on failure
 */
API_EXPORT int kmstool_enclave_decrypt(
    const struct kmstool_decrypt_params *params,
    uint8_t **plaintext_out,
    size_t *plaintext_out_len) {
    return app_lib_decrypt(&g_ctx, params, plaintext_out, plaintext_out_len);
}
