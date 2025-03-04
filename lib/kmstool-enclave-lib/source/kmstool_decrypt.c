#include "../include/kmstool_decrypt.h"

/* Decrypt the given base64 encoded ciphertext via KMS and output its base64 encoded result */
static int decrypt_from_kms(const struct app_ctx *ctx, const char *ciphertext_str, struct aws_byte_buf *plaintext) {
    ssize_t rc = AWS_OP_ERR;

    struct aws_byte_buf ciphertext = aws_byte_buf_from_c_str(ciphertext_str);

    /* Decrypt the data with KMS. */
    rc = aws_kms_decrypt_blocking(ctx->kms_client, ctx->key_id, ctx->encryption_algorithm, &ciphertext, &plaintext);
    aws_byte_buf_clean_up_secure(&ciphertext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not decrypt ciphertext\n");
        return rc;
    }

    return AWS_OP_SUCCESS;
}

int app_lib_decrypt(const struct app_ctx *ctx, const struct kmstool_decrypt_params *params, char **plaintext_b64_out) {
    ssize_t rc = AWS_OP_ERR;
    char buffer[8192];
    buffer[0] = '\0';

    if (params->ciphertext_b64 == NULL || strlen(params->ciphertext_b64) == 0) {
        fprintf(stderr, "ciphertext should not be NULL\n");
        *plaintext_b64_out = NULL;
        return ENCLAVE_KMS_ERROR;
    }

    struct aws_byte_buf plaintext;
    rc = decrypt_from_kms(ctx, params->ciphertext_b64, &plaintext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed to decrypt\n");
        *plaintext_b64_out = NULL;
        return rc;
    }

    snprintf(buffer, sizeof(buffer), "%s", (const char *)plaintext.buffer);
    *plaintext_b64_out = strdup(buffer);
    aws_byte_buf_clean_up_secure(&plaintext);
    return ENCLAVE_KMS_SUCCESS;
}