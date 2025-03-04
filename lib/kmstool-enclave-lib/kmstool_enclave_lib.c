#include "kmstool_enclave_lib.h"
#include "include/kmstool_init.h"
#include "include/kmstool_encrypt.h"
#include "include/kmstool_decrypt.h"

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

API_EXPORT int kmstool_enclave_encrypt(const struct kmstool_encrypt_params *params, char **ciphertext_b64_out){
    return app_lib_encrypt(&g_ctx, params, ciphertext_b64_out);
}

API_EXPORT int kmstool_enclave_decrypt(const struct kmstool_decrypt_params *params, char **plaintext_b64_out) {
    return app_lib_decrypt(&g_ctx, params, plaintext_b64_out);
}

