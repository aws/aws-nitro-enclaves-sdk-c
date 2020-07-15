/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/kms.h>
#include <aws/testing/aws_test_harness.h>

/**
 * Data used for JSON serialization and deserialization.
 *
 * TODO: Ensure more appropriate values from a dummy REST request.
 */
#define KEY_ID "1234abcd-12ab-34cd-56ef-1234567890ab"
#define ENCRYPTION_ALGORITHM "SYMMETRIC_DEFAULT"
#define CIPHERTEXT_BLOB_DATA "Hello"
#define CIPHERTEXT_BLOB_BASE64 "SGVsbG8="
#define TOKEN_FIRST "TokenFirst"
#define TOKEN_SECOND "TokenSecond"
#define ENCRYPTION_CONTEXT_KEY "EncryptionContextKey"
#define ENCRYPTION_CONTEXT_VALUE "EncryptionContextValue"
#define ENCRYPTION_CONTEXT_SUFIX "Sufix"

AWS_TEST_CASE(test_kms_decrypt_request_cipher_to_json, s_test_kms_decrypt_request_cipher_to_json)
static int s_test_kms_decrypt_request_cipher_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_new(allocator);
    ASSERT_NOT_NULL(request);

    /* Missing required Ciphertext Blob. */
    struct aws_string *json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NULL(json);

    /* Ensure required Ciphertext Blob is encoded. */
    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &request->ciphertext_blob, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));
    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected =
        aws_string_new_from_c_str(allocator, "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_ea_to_json, s_test_kms_decrypt_request_ea_to_json)
static int s_test_kms_decrypt_request_ea_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_new(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &request->ciphertext_blob, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    /* Add Encryption Algorithm to the KMS Decrypt Request. */
    request->encryption_algorithm = aws_string_new_from_c_str(allocator, ENCRYPTION_ALGORITHM);
    ASSERT_NOT_NULL(request->encryption_algorithm);

    struct aws_string *json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_context_to_json, s_test_kms_decrypt_request_context_to_json)
static int s_test_kms_decrypt_request_context_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_new(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &request->ciphertext_blob, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    /* Add Encryption Context to the KMS Decrypt Request. */
    ASSERT_SUCCESS(aws_hash_table_init(
        &request->encryption_context,
        allocator,
        2,
        aws_hash_string,
        aws_hash_callback_string_eq,
        aws_hash_callback_string_destroy,
        aws_hash_callback_string_destroy));

    /* Empty map. */
    struct aws_string *json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected =
        aws_string_new_from_c_str(allocator, "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    /* Map of one element. */
    AWS_STATIC_STRING_FROM_LITERAL(context_key, ENCRYPTION_CONTEXT_KEY);
    AWS_STATIC_STRING_FROM_LITERAL(context_value, ENCRYPTION_CONTEXT_VALUE);
    ASSERT_SUCCESS(aws_hash_table_put(&request->encryption_context, context_key, (void *)context_value, NULL));

    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionContext\": { \"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" } }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    /* Map of multiple elements. */
    AWS_STATIC_STRING_FROM_LITERAL(context_key_second, ENCRYPTION_CONTEXT_KEY ENCRYPTION_CONTEXT_SUFIX);
    AWS_STATIC_STRING_FROM_LITERAL(context_value_second, ENCRYPTION_CONTEXT_VALUE ENCRYPTION_CONTEXT_SUFIX);
    ASSERT_SUCCESS(
        aws_hash_table_put(&request->encryption_context, context_key_second, (void *)context_value_second, NULL));

    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionContext\": { \"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\", "
        "\"" ENCRYPTION_CONTEXT_KEY ENCRYPTION_CONTEXT_SUFIX "\": "
        "\"" ENCRYPTION_CONTEXT_VALUE ENCRYPTION_CONTEXT_SUFIX "\" } }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_tokens_to_json, s_test_kms_decrypt_request_tokens_to_json)
static int s_test_kms_decrypt_request_tokens_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_new(allocator);
    ASSERT_NOT_NULL(request);
    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &request->ciphertext_blob, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    /* Add Grant Tokens to the KMS Decrypt Request. */
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&request->grant_tokens, allocator, 2, sizeof(struct aws_string *)));

    /* Empty list. */
    struct aws_string *json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected =
        aws_string_new_from_c_str(allocator, "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    /* List of one element. */
    struct aws_string *token_first = aws_string_new_from_c_str(allocator, TOKEN_FIRST);
    ASSERT_NOT_NULL(token_first);
    ASSERT_SUCCESS(aws_array_list_push_back(&request->grant_tokens, &token_first));

    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\" ] }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    /* List of multiple elements. */
    struct aws_string *token_second = aws_string_new_from_c_str(allocator, TOKEN_SECOND);
    ASSERT_NOT_NULL(token_second);
    ASSERT_SUCCESS(aws_array_list_push_back(&request->grant_tokens, &token_second));

    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ] }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_to_json, s_test_kms_decrypt_request_to_json)
static int s_test_kms_decrypt_request_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_new(allocator);
    ASSERT_NOT_NULL(request);

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &request->ciphertext_blob, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    request->encryption_algorithm = aws_string_new_from_c_str(allocator, ENCRYPTION_ALGORITHM);

    ASSERT_NOT_NULL(request->encryption_algorithm);
    ASSERT_SUCCESS(aws_hash_table_init(
        &request->encryption_context,
        allocator,
        1,
        aws_hash_string,
        aws_hash_callback_string_eq,
        aws_hash_callback_string_destroy,
        aws_hash_callback_string_destroy));
    AWS_STATIC_STRING_FROM_LITERAL(context_key, ENCRYPTION_CONTEXT_KEY);
    AWS_STATIC_STRING_FROM_LITERAL(context_value, ENCRYPTION_CONTEXT_VALUE);
    ASSERT_SUCCESS(aws_hash_table_put(&request->encryption_context, context_key, (void *)context_value, NULL));

    ASSERT_SUCCESS(aws_array_list_init_dynamic(&request->grant_tokens, allocator, 2, sizeof(struct aws_string *)));
    struct aws_string *token_first = aws_string_new_from_c_str(allocator, TOKEN_FIRST);
    ASSERT_NOT_NULL(token_first);
    struct aws_string *token_second = aws_string_new_from_c_str(allocator, TOKEN_SECOND);
    ASSERT_NOT_NULL(token_second);
    ASSERT_SUCCESS(aws_array_list_push_back(&request->grant_tokens, &token_first));
    ASSERT_SUCCESS(aws_array_list_push_back(&request->grant_tokens, &token_second));

    request->key_id = aws_string_new_from_c_str(allocator, KEY_ID);
    ASSERT_NOT_NULL(request->key_id);

    struct aws_string *json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\", "
        "\"EncryptionContext\": { "
        "\"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" }, "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ], "
        "\"KeyId\": \"" KEY_ID "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}
