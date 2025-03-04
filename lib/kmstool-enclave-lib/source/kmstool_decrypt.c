#include "../include/kmstool_decrypt.h"

/* Decrypt the given ciphertext using KMS and store the result in the plaintext buffer */
static int decrypt_from_kms(
    const struct app_ctx *ctx,
    const struct kmstool_decrypt_params *params,
    struct aws_byte_buf *plaintext) {
    ssize_t rc = AWS_OP_ERR;

    struct aws_byte_buf ciphertext = aws_byte_buf_from_array(params->ciphertext, params->ciphertext_len);

    /* Decrypt the data with KMS using the configured key and algorithm */
    rc = aws_kms_decrypt_blocking(ctx->kms_client, ctx->kms_key_id, ctx->kms_algorithm, &ciphertext, plaintext);
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
        fprintf(stderr, "ciphertext should not be NULL or empty\n");
        *plaintext_out = NULL;
        *plaintext_out_len = 0;
        return KMSTOOL_ERROR;
    }

    struct aws_byte_buf plaintext_buf = {0};
    rc = decrypt_from_kms(ctx, params, &plaintext_buf);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "KMS decryption failed: %s\n", aws_error_str(aws_last_error()));
        *plaintext_out = NULL;
        *plaintext_out_len = 0;
        return rc;
    }

    uint8_t *output = malloc(plaintext_buf.len);
    if (output == NULL) {
        fprintf(stderr, "Failed to allocate memory for plaintext output\n");
        aws_byte_buf_clean_up_secure(&plaintext_buf);
        *plaintext_out = NULL;
        *plaintext_out_len = 0;
        return KMSTOOL_ERROR;
    }

    memcpy(output, plaintext_buf.buffer, plaintext_buf.len);
    *plaintext_out = output;
    *plaintext_out_len = plaintext_buf.len;
    aws_byte_buf_clean_up_secure(&plaintext_buf);
    return KMSTOOL_SUCCESS;
}