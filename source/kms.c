/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/kms.h>

struct aws_kms_decrypt_request *aws_kms_decrypt_request_new(struct aws_allocator *allocator) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_decrypt_request *request = aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_decrypt_request));
    if (request == NULL) {
        return NULL;
    }

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&request->allocator) = allocator;

    return request;
}

void aws_kms_decrypt_request_destroy(struct aws_kms_decrypt_request *req) {
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));

    if (aws_byte_buf_is_valid(&req->ciphertext_blob)) {
        aws_byte_buf_clean_up_secure(&req->ciphertext_blob);
    }

    if (aws_string_is_valid(req->encryption_algorithm)) {
        aws_string_destroy(req->encryption_algorithm);
    }

    if (aws_string_is_valid(req->key_id)) {
        aws_string_destroy(req->key_id);
    }

    if (aws_hash_table_is_valid(&req->encryption_context)) {
        aws_hash_table_clean_up(&req->encryption_context);
    }

    if (aws_array_list_is_valid(&req->grant_tokens)) {
        for (size_t i = 0; i < aws_array_list_length(&req->grant_tokens); i++) {
            struct aws_string *elem = NULL;
            AWS_FATAL_ASSERT(aws_array_list_get_at(&req->grant_tokens, &elem, i) == AWS_OP_SUCCESS);

            aws_string_destroy(elem);
        }

        aws_array_list_clean_up(&req->grant_tokens);
    }

    aws_mem_release(req->allocator, req);
}
