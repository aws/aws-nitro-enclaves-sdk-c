#include "../include/kmstool_decrypt.h"

/* Decrypt the given base64 encoded ciphertext via KMS and output its base64 encoded result */
static int decrypt_from_kms(
    const struct app_ctx *ctx,
    const struct kmstool_encrypt_params *params,
    struct aws_byte_buf *plaintext) {
    ssize_t rc = AWS_OP_ERR;

    struct aws_byte_buf ciphertext = aws_byte_buf_from_array(params->plaintext, params->plaintext_len);

    /* Decrypt the data with KMS. */
    rc = aws_kms_decrypt_blocking(ctx->kms_client, ctx->key_id, ctx->encryption_algorithm, &ciphertext, plaintext);
    aws_byte_buf_clean_up_secure(&ciphertext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not decrypt ciphertext\n");
        return rc;
    }

    return AWS_OP_SUCCESS;
}

int app_lib_decrypt(
    const struct app_ctx *ctx,
    const struct kmstool_decrypt_params *params,
    uint8_t **plaintext_out,
    size_t *plaintext_out_len) {
    ssize_t rc = AWS_OP_ERR;

    if (params->ciphertext == NULL || params->ciphertext_len == 0) {
        fprintf(stderr, "ciphertext should not be NULL\n");
        *plaintext_out = NULL;
        *plaintext_out_len = 0;
        return ENCLAVE_KMS_ERROR;
    }

    struct aws_byte_buf plaintext_buf;
    rc = decrypt_from_kms(ctx, params, &plaintext_buf);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed to decrypt\n");
        *plaintext_out = NULL;
        *plaintext_out_len = 0;
        return rc;
    }

    uint8_t *plaintext_out = malloc(plaintext_buf.len);
    memcpy(*plaintext_out, plaintext_buf.buffer, plaintext_buf.len);
    *plaintext_out_len = plaintext_buf.len;
    aws_byte_buf_clean_up_secure(&plaintext_buf);
    return ENCLAVE_KMS_SUCCESS;
}