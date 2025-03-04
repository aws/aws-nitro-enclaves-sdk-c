#include "../include/kmstool_encrypt.h"

#define MAX_ENCRYPT_DATA_SIZE 4096

/* Decrypt the given base64 encoded ciphertext via KMS and output its base64 encoded result */
static int encrypt_from_kms(
    const struct app_ctx *ctx,
    const struct kmstool_encrypt_params *params,
    struct aws_byte_buf *ciphertext) {
    ssize_t rc = AWS_OP_ERR;

    struct aws_byte_buf plaintext = aws_byte_buf_from_array(params->plaintext, params->plaintext_len);

    /* Encrypt the data with KMS. */
    rc = aws_kms_encrypt_blocking(ctx->kms_client, ctx->key_id, &plaintext, ciphertext);
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
        fprintf(stderr, "plaintext should not be NULL\n");
        *ciphertext_out = NULL;
        *ciphertext_out_len = 0;
        return ENCLAVE_KMS_ERROR;
    }

    if (strlen(params->plaintext) > MAX_ENCRYPT_DATA_SIZE) {
        fprintf(stderr, "plaintext too large\n");
        *ciphertext_out = NULL;
        *ciphertext_out_len = 0;
        return ENCLAVE_KMS_ERROR;
    }

    struct aws_byte_buf ciphertext_buf;
    rc = encrypt_from_kms(ctx, params, &ciphertext_buf);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed to encrypt\n");
        *ciphertext_out = NULL;
        *ciphertext_out_len = 0;
        return rc;
    }

    *ciphertext_out = malloc(ciphertext_buf.len);
    memcpy(*ciphertext_out, ciphertext_buf.buffer, ciphertext_buf.len);
    *ciphertext_out_len = ciphertext_buf.len;
    aws_byte_buf_clean_up_secure(&ciphertext_buf);
    return ENCLAVE_KMS_SUCCESS;
}
