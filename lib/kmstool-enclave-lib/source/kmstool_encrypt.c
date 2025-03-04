#include "../include/kmstool_encrypt.h"

/* Decrypt the given base64 encoded ciphertext via KMS and output its base64 encoded result */
static int encrypt_from_kms(const struct app_ctx *ctx, const char *plaintext_str, struct aws_byte_buf *ciphertext) {
    ssize_t rc = AWS_OP_ERR;

    struct aws_byte_buf plaintext = aws_byte_buf_from_c_str(plaintext_str);

    /* Encrypt the data with KMS. */
    rc = aws_kms_encrypt_blocking(ctx->kms_client, ctx->key_id, &plaintext, ciphertext);
    aws_byte_buf_clean_up_secure(&plaintext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encrypt plaintext\n");
        return rc;
    }

    return AWS_OP_SUCCESS;
}

int app_lib_encrypt(const struct app_ctx *ctx, const struct kmstool_encrypt_params *params, char **ciphertext_b64_out) {
    ssize_t rc = AWS_OP_ERR;
    char buffer[8192];
    buffer[0] = '\0';

    if (params->plaintext_b64 == NULL || strlen(params->plaintext_b64) == 0) {
        fprintf(stderr, "plaintext should not be NULL\n");
        *ciphertext_b64_out = NULL;
        return ENCLAVE_KMS_ERROR;
    }

    struct aws_byte_buf ciphertext;
    rc = encrypt_from_kms(ctx, params->plaintext_b64, &ciphertext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed to encrypt\n");
        *ciphertext_b64_out = NULL;
        return rc;
    }

    snprintf(buffer, sizeof(buffer), "%s", (const char *)ciphertext.buffer);
    *ciphertext_b64_out = strdup(buffer);
    aws_byte_buf_clean_up_secure(&ciphertext);
    return ENCLAVE_KMS_SUCCESS;
}
