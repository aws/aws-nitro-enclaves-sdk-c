#include "../include/kmstool_encrypt.h"

#define MAX_ENCRYPT_DATA_SIZE 4096

/* Encrypt the given plaintext using KMS and store the result in the ciphertext buffer */
static int encrypt_from_kms(
    const struct app_ctx *ctx,
    const struct kmstool_encrypt_params *params,
    struct aws_byte_buf *ciphertext) {
    ssize_t rc = AWS_OP_ERR;

    struct aws_byte_buf plaintext = aws_byte_buf_from_array(params->plaintext, params->plaintext_len);

    /* Encrypt the data with KMS using the configured key and algorithm */
    rc = aws_kms_encrypt_blocking(ctx->kms_client, ctx->kms_key_id, &plaintext, ciphertext);
    aws_byte_buf_clean_up_secure(&plaintext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encrypt plaintext\n");
        return rc;
    }

    return AWS_OP_SUCCESS;
}

int app_lib_encrypt(
    const struct app_ctx *ctx,
    const struct kmstool_encrypt_params *params,
    uint8_t **ciphertext_out,
    size_t *ciphertext_out_len) {
    ssize_t rc = AWS_OP_ERR;

    if (params->plaintext == NULL || params->plaintext_len == 0) {
        fprintf(stderr, "plaintext should not be NULL or empty\n");
        *ciphertext_out = NULL;
        *ciphertext_out_len = 0;
        return KMSTOOL_ERROR;
    }

    if (params->plaintext_len > MAX_ENCRYPT_DATA_SIZE) {
        fprintf(stderr, "plaintext too large (max size: %d bytes)\n", MAX_ENCRYPT_DATA_SIZE);
        *ciphertext_out = NULL;
        *ciphertext_out_len = 0;
        return KMSTOOL_ERROR;
    }

    struct aws_byte_buf ciphertext_buf = {0};
    rc = encrypt_from_kms(ctx, params, &ciphertext_buf);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "KMS encryption failed: %s\n", aws_error_str(aws_last_error()));
        *ciphertext_out = NULL;
        *ciphertext_out_len = 0;
        return rc;
    }

    uint8_t *output = malloc(ciphertext_buf.len);
    if (output == NULL) {
        fprintf(stderr, "Failed to allocate memory for ciphertext output\n");
        aws_byte_buf_clean_up_secure(&ciphertext_buf);
        *ciphertext_out = NULL;
        *ciphertext_out_len = 0;
        return KMSTOOL_ERROR;
    }

    memcpy(output, ciphertext_buf.buffer, ciphertext_buf.len);
    *ciphertext_out = output;
    *ciphertext_out_len = ciphertext_buf.len;
    aws_byte_buf_clean_up_secure(&ciphertext_buf);
    return KMSTOOL_SUCCESS;
}
