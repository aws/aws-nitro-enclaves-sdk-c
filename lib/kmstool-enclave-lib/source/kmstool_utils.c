#include "../include/kmstool_utils.h"

/* Encode the given text buffer to base64 and store it in text_b64 */
int encode_b64(const struct app_ctx *ctx, const struct aws_byte_buf *text, struct aws_byte_buf *text_b64) {
    ssize_t rc = AWS_OP_ERR;
    size_t text_b64_len;

    aws_base64_compute_encoded_len(text->len, &text_b64_len);
    rc = aws_byte_buf_init(text_b64, ctx->allocator, text_b64_len + 1);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Memory allocation error\n");
        return rc;
    }

    struct aws_byte_cursor text_cursor = aws_byte_cursor_from_buf(text);
    rc = aws_base64_encode(&text_cursor, text_b64);
    if (rc != AWS_OP_SUCCESS) {
        aws_byte_buf_clean_up_secure(text_b64);
        fprintf(stderr, "Base64 encoding error\n");
        return rc;
    }

    aws_byte_buf_append_null_terminator(text_b64);
    return AWS_OP_SUCCESS;
}

/* Decord the given text buffer from base64 and store it in text */
int decode_b64(const struct app_ctx *ctx, const struct aws_string *text_b64, struct aws_byte_buf *text) {
    ssize_t rc = AWS_OP_ERR;
    size_t text_len;

    struct aws_byte_cursor text_b64_cursor = aws_byte_cursor_from_c_str((const char *)text_b64->bytes);
    rc = aws_base64_compute_decoded_len(&text_b64_cursor, &text_len);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "text not a base64 string\n");
        return rc;
    }

    rc = aws_byte_buf_init(text, ctx->allocator, text_len);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed init ciphertext\n");
        return rc;
    }

    rc = aws_base64_decode(&text_b64_cursor, text);
    if (rc != AWS_OP_SUCCESS) {
        aws_byte_buf_clean_up_secure(text);
        fprintf(stderr, "Ciphertext not a base64 string\n");
        return rc;
    }

    return AWS_OP_SUCCESS;
}