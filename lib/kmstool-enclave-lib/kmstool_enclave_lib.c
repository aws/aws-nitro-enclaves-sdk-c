#include "kmstool_enclave_lib.h"
#include "include/kmstool_decrypt.h"
#include "include/kmstool_encrypt.h"
#include "include/kmstool_init.h"

/* Global static application context */
static struct app_ctx g_ctx = {0};

#ifdef _WIN32
#    define API_EXPORT __declspec(dllexport)
#else
#    define API_EXPORT __attribute__((visibility("default")))
#endif

API_EXPORT int kmstool_enclave_init(const struct kmstool_init_params *params) {
    return app_lib_init(&g_ctx, params);
}

API_EXPORT int kmstool_enclave_stop() {
    return app_lib_clean_up(&g_ctx);
}

API_EXPORT int kmstool_enclave_update_aws_key(const struct kmstool_update_aws_key_params *params) {
    return app_lib_update_aws_key(&g_ctx, params);
}

API_EXPORT int kmstool_enclave_encrypt(
    const struct kmstool_encrypt_params *params,
    uint8_t **ciphertext_out,
    size_t *ciphertext_out_len) {
    return app_lib_encrypt(&g_ctx, params, ciphertext_out, ciphertext_out_len);
}

API_EXPORT int kmstool_enclave_decrypt(
    const struct kmstool_decrypt_params *params,
    uint8_t **plaintext_out,
    size_t *plaintext_out_len) {
    return app_lib_decrypt(&g_ctx, params, plaintext_out, plaintext_out_len);
}
