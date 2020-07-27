/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/kms.h>
#include <aws/testing/aws_test_harness.h>

/**
 * Data used for JSON serialization and deserialization.
 */
#define KEY_ID "1234abcd-12ab-34cd-56ef-1234567890ab"
#define ENCRYPTION_ALGORITHM "SYMMETRIC_DEFAULT"
#define ENCRYPTION_ALGORITHM_SHA_1 "RSAES_OAEP_SHA_1"
#define ENCRYPTION_ALGORITHM_SHA_256 "RSAES_OAEP_SHA_256"
#define CIPHERTEXT_BLOB_DATA "Hello"
#define CIPHERTEXT_BLOB_BASE64 "SGVsbG8="
#define TOKEN_FIRST "TokenFirst"
#define TOKEN_SECOND "TokenSecond"
#define ENCRYPTION_CONTEXT_KEY "EncryptionContextKey"
#define ENCRYPTION_CONTEXT_VALUE "EncryptionContextValue"
#define SUFIX "Sufix"
#define KEA_RSAES_PKCS1_V1_5 "RSAES_PKCS1_V1_5"
#define KEA_RSAES_OAEP_SHA_1 "RSAES_OAEP_SHA_1"
#define KEA_RSAES_OAEP_SHA_256 "RSAES_OAEP_SHA_256"
#define KS_AES_256 "AES_256"

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
    request->encryption_algorithm = AWS_EA_SYMMETRIC_DEFAULT;

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

    request->encryption_algorithm = AWS_EA_RSAES_OAEP_SHA_1;
    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM_SHA_1 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    request->encryption_algorithm = AWS_EA_RSAES_OAEP_SHA_256;
    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM_SHA_256 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    request->encryption_algorithm = AWS_EA_RSAES_OAEP_SHA_256 + 1;
    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NULL(json);

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
    AWS_STATIC_STRING_FROM_LITERAL(context_key_second, ENCRYPTION_CONTEXT_KEY SUFIX);
    AWS_STATIC_STRING_FROM_LITERAL(context_value_second, ENCRYPTION_CONTEXT_VALUE SUFIX);
    ASSERT_SUCCESS(
        aws_hash_table_put(&request->encryption_context, context_key_second, (void *)context_value_second, NULL));

    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionContext\": { \"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\", "
        "\"" ENCRYPTION_CONTEXT_KEY SUFIX "\": "
        "\"" ENCRYPTION_CONTEXT_VALUE SUFIX "\" } }");
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

    request->encryption_algorithm = AWS_EA_SYMMETRIC_DEFAULT;
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

    struct aws_string *json = aws_string_new_from_c_str(allocator, "{ \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);
    request->recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NOT_NULL(request->recipient);
    aws_string_destroy(json);

    json = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\", "
        "\"EncryptionContext\": { "
        "\"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" }, "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ], "
        "\"KeyId\": \"" KEY_ID "\", "
        "\"Recipient\": { \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" } }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_cipher_from_json, s_test_kms_decrypt_request_cipher_from_json)
static int s_test_kms_decrypt_request_cipher_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Validate an invalid JSON. */
    struct aws_string *json = aws_string_new_from_c_str(allocator, "{");
    ASSERT_NOT_NULL(json);

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NULL(request);
    aws_string_destroy(json);

    /* Validate an empty JSON. */
    json = aws_string_new_from_c_str(allocator, "{}");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NULL(request);
    aws_string_destroy(json);

    /* Validate a non empty JSON without Ciphertext Blob. */
    json = aws_string_new_from_c_str(allocator, "{ \"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\" }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NULL(request);
    aws_string_destroy(json);

    /* Ensure required Ciphertext Blob is decoded. */
    json = aws_string_new_from_c_str(allocator, "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->ciphertext_blob.buffer,
        request->ciphertext_blob.len);
    aws_kms_decrypt_request_destroy(request);

    /* No key duplicates are allowed. */
    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"CiphertextBlob\": \"" CIPHERTEXT_BLOB_DATA "\" }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NULL(request);
    aws_string_destroy(json);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_ea_from_json, s_test_kms_decrypt_request_ea_from_json)
static int s_test_kms_decrypt_request_ea_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *json =
        aws_string_new_from_c_str(allocator, "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(request->encryption_algorithm, AWS_EA_UNINITIALIZED);
    aws_kms_decrypt_request_destroy(request);

    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NULL(request);
    aws_string_destroy(json);

    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\" }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->ciphertext_blob.buffer,
        request->ciphertext_blob.len);
    ASSERT_INT_EQUALS(request->encryption_algorithm, AWS_EA_SYMMETRIC_DEFAULT);
    aws_kms_decrypt_request_destroy(request);

    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM_SHA_1 "\" }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->ciphertext_blob.buffer,
        request->ciphertext_blob.len);
    ASSERT_INT_EQUALS(request->encryption_algorithm, AWS_EA_RSAES_OAEP_SHA_1);
    aws_kms_decrypt_request_destroy(request);

    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM_SHA_256 "\" }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->ciphertext_blob.buffer,
        request->ciphertext_blob.len);
    ASSERT_INT_EQUALS(request->encryption_algorithm, AWS_EA_RSAES_OAEP_SHA_256);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_context_from_json, s_test_kms_decrypt_request_context_from_json)
static int s_test_kms_decrypt_request_context_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* No Encryption Context. */
    struct aws_string *json =
        aws_string_new_from_c_str(allocator, "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(false, aws_hash_table_is_valid(&request->encryption_context));
    aws_kms_decrypt_request_destroy(request);

    /* Map of one element. */
    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionContext\": { "
        "\"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" } }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->ciphertext_blob.buffer,
        request->ciphertext_blob.len);
    for (struct aws_hash_iter iter = aws_hash_iter_begin(&request->encryption_context); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_KEY, aws_string_c_str(iter.element.key));
        ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_VALUE, aws_string_c_str(iter.element.value));
    }
    aws_kms_decrypt_request_destroy(request);

    /* Map of multiple elements. */
    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionContext\": { "
        "\"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\","
        "\"" ENCRYPTION_CONTEXT_KEY SUFIX "\": \"" ENCRYPTION_CONTEXT_VALUE SUFIX "\" } }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->ciphertext_blob.buffer,
        request->ciphertext_blob.len);
    for (struct aws_hash_iter iter = aws_hash_iter_begin(&request->encryption_context); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        if (strcmp(ENCRYPTION_CONTEXT_KEY, aws_string_c_str(iter.element.key)) == 0) {
            ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_VALUE, aws_string_c_str(iter.element.value));
            continue;
        }
        if (strcmp(ENCRYPTION_CONTEXT_KEY SUFIX, aws_string_c_str(iter.element.key)) == 0) {
            ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_VALUE SUFIX, aws_string_c_str(iter.element.value));
            continue;
        }
        /* Wrong size. */
        ASSERT_FAILS(true);
    }
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_tokens_from_json, s_test_kms_decrypt_request_tokens_from_json)
static int s_test_kms_decrypt_request_tokens_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* No Grant Tokens. */
    struct aws_string *json =
        aws_string_new_from_c_str(allocator, "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(false, aws_array_list_is_valid(&request->grant_tokens));
    aws_kms_decrypt_request_destroy(request);

    /* Empty Grant Tokens. */
    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"GrantTokens\": [ ] } ");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(0, aws_array_list_length(&request->grant_tokens));
    aws_kms_decrypt_request_destroy(request);

    /* List of one element. */
    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\" ] } ");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(1, aws_array_list_length(&request->grant_tokens));
    struct aws_string *elem = NULL;
    AWS_FATAL_ASSERT(aws_array_list_get_at(&request->grant_tokens, &elem, 0) == AWS_OP_SUCCESS);
    ASSERT_STR_EQUALS(TOKEN_FIRST, aws_string_c_str(elem));
    aws_kms_decrypt_request_destroy(request);

    /* List of multiple elements. */
    json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ] } ");
    ASSERT_NOT_NULL(json);

    request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(2, aws_array_list_length(&request->grant_tokens));
    AWS_FATAL_ASSERT(aws_array_list_get_at(&request->grant_tokens, &elem, 0) == AWS_OP_SUCCESS);
    ASSERT_STR_EQUALS(TOKEN_FIRST, aws_string_c_str(elem));
    AWS_FATAL_ASSERT(aws_array_list_get_at(&request->grant_tokens, &elem, 1) == AWS_OP_SUCCESS);
    ASSERT_STR_EQUALS(TOKEN_SECOND, aws_string_c_str(elem));
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_request_from_json, s_test_kms_decrypt_request_from_json)
static int s_test_kms_decrypt_request_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Add Key ID to the JSON. */
    struct aws_string *json = aws_string_new_from_c_str(
        allocator,
        "{ \"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\", "
        "\"EncryptionContext\": { "
        "\"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" }, "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ], "
        "\"KeyId\": \"" KEY_ID "\", "
        "\"Recipient\": { \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" } }");
    struct aws_kms_decrypt_request *request = aws_kms_decrypt_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->ciphertext_blob.buffer,
        request->ciphertext_blob.len);
    ASSERT_INT_EQUALS(request->encryption_algorithm, AWS_EA_SYMMETRIC_DEFAULT);
    for (struct aws_hash_iter iter = aws_hash_iter_begin(&request->encryption_context); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_KEY, aws_string_c_str(iter.element.key));
        ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_VALUE, aws_string_c_str(iter.element.value));
    }
    ASSERT_INT_EQUALS(2, aws_array_list_length(&request->grant_tokens));
    struct aws_string *elem = NULL;
    AWS_FATAL_ASSERT(aws_array_list_get_at(&request->grant_tokens, &elem, 0) == AWS_OP_SUCCESS);
    ASSERT_STR_EQUALS(TOKEN_FIRST, aws_string_c_str(elem));
    AWS_FATAL_ASSERT(aws_array_list_get_at(&request->grant_tokens, &elem, 1) == AWS_OP_SUCCESS);
    ASSERT_STR_EQUALS(TOKEN_SECOND, aws_string_c_str(elem));
    ASSERT_STR_EQUALS(KEY_ID, aws_string_c_str(request->key_id));
    ASSERT_NOT_NULL(request->recipient);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->recipient->public_key.buffer,
        request->recipient->public_key.len);

    /* Ensure we can serialize back to a JSON. */
    struct aws_string *json_second = aws_kms_decrypt_request_to_json(request);
    ASSERT_NOT_NULL(json_second);
    ASSERT_STR_EQUALS(aws_string_c_str(json), aws_string_c_str(json_second));

    aws_string_destroy(json);
    aws_string_destroy(json_second);
    aws_kms_decrypt_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_recipient_kea_to_json, s_test_recipient_kea_to_json)
static int s_test_recipient_kea_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_recipient *recipient = aws_recipient_new(allocator);
    ASSERT_NOT_NULL(recipient);

    recipient->key_encryption_algorithm = AWS_KEA_RSAES_PKCS1_V1_5;
    struct aws_string *json = aws_recipient_to_json(recipient);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected =
        aws_string_new_from_c_str(allocator, "{ \"KeyEncryptionAlgorithm\": \"" KEA_RSAES_PKCS1_V1_5 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_1;
    json = aws_recipient_to_json(recipient);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(allocator, "{ \"KeyEncryptionAlgorithm\": \"" KEA_RSAES_OAEP_SHA_1 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;
    json = aws_recipient_to_json(recipient);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(allocator, "{ \"KeyEncryptionAlgorithm\": \"" KEA_RSAES_OAEP_SHA_256 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256 + 1;
    json = aws_recipient_to_json(recipient);
    ASSERT_NULL(json);

    aws_recipient_destroy(recipient);

    return SUCCESS;
}

AWS_TEST_CASE(test_recipient_to_json, s_test_recipient_to_json)
static int s_test_recipient_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_recipient *recipient = aws_recipient_new(allocator);
    ASSERT_NOT_NULL(recipient);

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &recipient->public_key, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &recipient->attestation_document, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    recipient->key_encryption_algorithm = AWS_KEA_RSAES_PKCS1_V1_5;

    struct aws_string *json = aws_recipient_to_json(recipient);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"KeyEncryptionAlgorithm\": \"" KEA_RSAES_PKCS1_V1_5 "\", "
        "\"AttestationDocument\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_recipient_destroy(recipient);

    return SUCCESS;
}

AWS_TEST_CASE(test_recipient_kea_from_json, s_test_recipient_kea_from_json)
static int s_test_recipient_kea_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *json =
        aws_string_new_from_c_str(allocator, "{ \"KeyEncryptionAlgorithm\": \"" KEA_RSAES_PKCS1_V1_5 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_recipient *recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NOT_NULL(recipient);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(recipient->key_encryption_algorithm, AWS_KEA_RSAES_PKCS1_V1_5);
    aws_recipient_destroy(recipient);

    json = aws_string_new_from_c_str(allocator, "{ \"KeyEncryptionAlgorithm\": \"" KEA_RSAES_OAEP_SHA_1 "\" }");
    ASSERT_NOT_NULL(json);

    recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NOT_NULL(recipient);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(recipient->key_encryption_algorithm, AWS_KEA_RSAES_OAEP_SHA_1);
    aws_recipient_destroy(recipient);

    json = aws_string_new_from_c_str(allocator, "{ \"KeyEncryptionAlgorithm\": \"" KEA_RSAES_OAEP_SHA_256 "\" }");
    ASSERT_NOT_NULL(json);

    recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NOT_NULL(recipient);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(recipient->key_encryption_algorithm, AWS_KEA_RSAES_OAEP_SHA_256);
    aws_recipient_destroy(recipient);

    json = aws_string_new_from_c_str(allocator, "{ \"KeyEncryptionAlgorithm\": \"" CIPHERTEXT_BLOB_DATA "\" }");
    ASSERT_NOT_NULL(json);

    recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NULL(recipient);
    aws_string_destroy(json);

    return SUCCESS;
}

AWS_TEST_CASE(test_recipient_from_json, s_test_recipient_from_json)
static int s_test_recipient_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Invalid json. */
    struct aws_string *json = aws_string_new_from_c_str(
        allocator,
        "{ \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_recipient *recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NULL(recipient);
    aws_string_destroy(json);

    json = aws_string_new_from_c_str(
        allocator,
        "{ \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"KeyEncryptionAlgorithm\": \"" KEA_RSAES_PKCS1_V1_5 "\", "
        "\"AttestationDocument\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NOT_NULL(recipient);
    aws_string_destroy(json);

    ASSERT_INT_EQUALS(recipient->key_encryption_algorithm, AWS_KEA_RSAES_PKCS1_V1_5);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)recipient->public_key.buffer,
        recipient->public_key.len);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)recipient->attestation_document.buffer,
        recipient->attestation_document.len);

    aws_recipient_destroy(recipient);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_response_to_json, s_test_kms_decrypt_response_to_json)
static int s_test_kms_decrypt_response_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_decrypt_response *response = aws_kms_decrypt_response_new(allocator);
    ASSERT_NOT_NULL(response);

    response->key_id = aws_string_new_from_c_str(allocator, KEY_ID);
    ASSERT_NOT_NULL(response->key_id);

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &response->plaintext, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    response->encryption_algorithm = AWS_EA_SYMMETRIC_DEFAULT;

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &response->ciphertext_for_recipient, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    struct aws_string *json = aws_kms_decrypt_response_to_json(response);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"Plaintext\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\", "
        "\"CiphertextForRecipient\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_decrypt_response_destroy(response);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_decrypt_response_from_json, s_test_kms_decrypt_response_from_json)
static int s_test_kms_decrypt_response_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *json = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"Plaintext\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"EncryptionAlgorithm\": \"" ENCRYPTION_ALGORITHM "\", "
        "\"CiphertextForRecipient\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_decrypt_response *response = aws_kms_decrypt_response_from_json(allocator, json);
    ASSERT_NOT_NULL(response);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)response->plaintext.buffer,
        response->plaintext.len);
    ASSERT_INT_EQUALS(response->encryption_algorithm, AWS_EA_SYMMETRIC_DEFAULT);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)response->ciphertext_for_recipient.buffer,
        response->ciphertext_for_recipient.len);

    /* Ensure we can serialize back to a JSON. */
    struct aws_string *json_second = aws_kms_decrypt_response_to_json(response);
    ASSERT_NOT_NULL(json_second);
    ASSERT_STR_EQUALS(aws_string_c_str(json), aws_string_c_str(json_second));

    aws_string_destroy(json);
    aws_string_destroy(json_second);
    aws_kms_decrypt_response_destroy(response);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_data_key_request_to_json, s_test_kms_generate_data_key_request_to_json)
static int s_test_kms_generate_data_key_request_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_generate_data_key_request *request = aws_kms_generate_data_key_request_new(allocator);
    ASSERT_NOT_NULL(request);

    request->key_id = aws_string_new_from_c_str(allocator, KEY_ID);
    ASSERT_NOT_NULL(request->key_id);

    ASSERT_SUCCESS(aws_hash_table_init(
        &request->encryption_context,
        allocator,
        2,
        aws_hash_string,
        aws_hash_callback_string_eq,
        aws_hash_callback_string_destroy,
        aws_hash_callback_string_destroy));

    AWS_STATIC_STRING_FROM_LITERAL(context_key, ENCRYPTION_CONTEXT_KEY);
    AWS_STATIC_STRING_FROM_LITERAL(context_value, ENCRYPTION_CONTEXT_VALUE);
    ASSERT_SUCCESS(aws_hash_table_put(&request->encryption_context, context_key, (void *)context_value, NULL));

    request->number_of_bytes = 0;
    request->key_spec = AWS_KS_AES_256;

    ASSERT_SUCCESS(aws_array_list_init_dynamic(&request->grant_tokens, allocator, 2, sizeof(struct aws_string *)));
    struct aws_string *token_first = aws_string_new_from_c_str(allocator, TOKEN_FIRST);
    ASSERT_NOT_NULL(token_first);
    struct aws_string *token_second = aws_string_new_from_c_str(allocator, TOKEN_SECOND);
    ASSERT_NOT_NULL(token_second);
    ASSERT_SUCCESS(aws_array_list_push_back(&request->grant_tokens, &token_first));
    ASSERT_SUCCESS(aws_array_list_push_back(&request->grant_tokens, &token_second));

    struct aws_string *json = aws_string_new_from_c_str(allocator, "{ \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);
    request->recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NOT_NULL(request->recipient);
    aws_string_destroy(json);

    json = aws_kms_generate_data_key_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"KeySpec\": \"" KS_AES_256 "\", "
        "\"EncryptionContext\": { \"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" }, "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ], "
        "\"Recipient\": { \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" } }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);

    request->number_of_bytes = 1;
    request->key_spec = AWS_KS_UNINITIALIZED;

    json = aws_kms_generate_data_key_request_to_json(request);
    ASSERT_NOT_NULL(json);

    expected = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"NumberOfBytes\": 1, "
        "\"EncryptionContext\": { \"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" }, "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ], "
        "\"Recipient\": { \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" } }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_generate_data_key_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_data_key_request_from_json, s_test_kms_generate_data_key_request_from_json)
static int s_test_kms_generate_data_key_request_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *json = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"KeySpec\": \"" KS_AES_256 "\", "
        "\"EncryptionContext\": { \"" ENCRYPTION_CONTEXT_KEY "\": \"" ENCRYPTION_CONTEXT_VALUE "\" }, "
        "\"GrantTokens\": [ \"" TOKEN_FIRST "\", \"" TOKEN_SECOND "\" ], "
        "\"Recipient\": { \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" } }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_generate_data_key_request *request = aws_kms_generate_data_key_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    ASSERT_STR_EQUALS(KEY_ID, aws_string_c_str(request->key_id));
    ASSERT_INT_EQUALS(request->key_spec, AWS_KS_AES_256);
    for (struct aws_hash_iter iter = aws_hash_iter_begin(&request->encryption_context); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_KEY, aws_string_c_str(iter.element.key));
        ASSERT_STR_EQUALS(ENCRYPTION_CONTEXT_VALUE, aws_string_c_str(iter.element.value));
    }
    struct aws_string *elem = NULL;
    ASSERT_INT_EQUALS(2, aws_array_list_length(&request->grant_tokens));
    AWS_FATAL_ASSERT(aws_array_list_get_at(&request->grant_tokens, &elem, 0) == AWS_OP_SUCCESS);
    ASSERT_STR_EQUALS(TOKEN_FIRST, aws_string_c_str(elem));
    AWS_FATAL_ASSERT(aws_array_list_get_at(&request->grant_tokens, &elem, 1) == AWS_OP_SUCCESS);
    ASSERT_STR_EQUALS(TOKEN_SECOND, aws_string_c_str(elem));
    ASSERT_NOT_NULL(request->recipient);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->recipient->public_key.buffer,
        request->recipient->public_key.len);

    /* Ensure we can serialize back to a JSON. */
    struct aws_string *json_second = aws_kms_generate_data_key_request_to_json(request);
    ASSERT_NOT_NULL(json_second);
    ASSERT_STR_EQUALS(aws_string_c_str(json), aws_string_c_str(json_second));
    aws_string_destroy(json);
    aws_string_destroy(json_second);
    aws_kms_generate_data_key_request_destroy(request);

    json = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"NumberOfBytes\": 1 }");
    ASSERT_NOT_NULL(json);

    request = aws_kms_generate_data_key_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);
    ASSERT_STR_EQUALS(KEY_ID, aws_string_c_str(request->key_id));
    ASSERT_INT_EQUALS(request->number_of_bytes, 1);
    aws_string_destroy(json);
    aws_kms_generate_data_key_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_data_key_response_to_json, s_test_kms_generate_data_key_response_to_json)
static int s_test_kms_generate_data_key_response_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_generate_data_key_response *response = aws_kms_generate_data_key_response_new(allocator);
    ASSERT_NOT_NULL(response);

    response->key_id = aws_string_new_from_c_str(allocator, KEY_ID);
    ASSERT_NOT_NULL(response->key_id);

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &response->ciphertext_blob, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &response->plaintext, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &response->ciphertext_for_recipient, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    struct aws_string *json = aws_kms_generate_data_key_response_to_json(response);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"Plaintext\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"CiphertextForRecipient\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_generate_data_key_response_destroy(response);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_data_key_response_from_json, s_test_kms_generate_data_key_response_from_json)
static int s_test_kms_generate_data_key_response_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *json = aws_string_new_from_c_str(
        allocator,
        "{ \"KeyId\": \"" KEY_ID "\", "
        "\"CiphertextBlob\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"Plaintext\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"CiphertextForRecipient\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_generate_data_key_response *response = aws_kms_generate_data_key_response_from_json(allocator, json);
    ASSERT_NOT_NULL(response);

    ASSERT_STR_EQUALS(KEY_ID, aws_string_c_str(response->key_id));
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)response->plaintext.buffer,
        response->plaintext.len);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)response->plaintext.buffer,
        response->plaintext.len);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)response->ciphertext_for_recipient.buffer,
        response->ciphertext_for_recipient.len);

    /* Ensure we can serialize back to a JSON. */
    struct aws_string *json_second = aws_kms_generate_data_key_response_to_json(response);
    ASSERT_NOT_NULL(json_second);
    ASSERT_STR_EQUALS(aws_string_c_str(json), aws_string_c_str(json_second));

    aws_string_destroy(json);
    aws_string_destroy(json_second);
    aws_kms_generate_data_key_response_destroy(response);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_random_request_to_json, s_test_kms_generate_random_request_to_json)
static int s_test_kms_generate_random_request_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_generate_random_request *request = aws_kms_generate_random_request_new(allocator);
    ASSERT_NOT_NULL(request);

    request->number_of_bytes = 1;
    request->custom_key_store_id = aws_string_new_from_c_str(allocator, KEY_ID);
    ASSERT_NOT_NULL(request->custom_key_store_id);
    struct aws_string *json = aws_string_new_from_c_str(allocator, "{ \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);
    request->recipient = aws_recipient_from_json(allocator, json);
    ASSERT_NOT_NULL(request->recipient);
    aws_string_destroy(json);

    json = aws_kms_generate_random_request_to_json(request);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"NumberOfBytes\": 1, "
        "\"CustomKeyStoreId\": \"" KEY_ID "\", "
        "\"Recipient\": { \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" } }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_generate_random_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_random_request_from_json, s_test_kms_generate_random_request_from_json)
static int s_test_kms_generate_random_request_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *json = aws_string_new_from_c_str(
        allocator,
        "{ \"NumberOfBytes\": 1, "
        "\"CustomKeyStoreId\": \"" KEY_ID "\", "
        "\"Recipient\": { \"PublicKey\": \"" CIPHERTEXT_BLOB_BASE64 "\" } }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_generate_random_request *request = aws_kms_generate_random_request_from_json(allocator, json);
    ASSERT_NOT_NULL(request);

    ASSERT_INT_EQUALS(request->number_of_bytes, 1);
    ASSERT_STR_EQUALS(KEY_ID, aws_string_c_str(request->custom_key_store_id));
    ASSERT_NOT_NULL(request->recipient);
    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)request->recipient->public_key.buffer,
        request->recipient->public_key.len);

    /* Ensure we can serialize back to a JSON. */
    struct aws_string *json_second = aws_kms_generate_random_request_to_json(request);
    ASSERT_NOT_NULL(json_second);
    ASSERT_STR_EQUALS(aws_string_c_str(json), aws_string_c_str(json_second));

    aws_string_destroy(json);
    aws_string_destroy(json_second);
    aws_kms_generate_random_request_destroy(request);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_random_response_to_json, s_test_kms_generate_random_response_to_json)
static int s_test_kms_generate_random_response_to_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_kms_generate_random_response *response = aws_kms_generate_random_response_new(allocator);
    ASSERT_NOT_NULL(response);

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &response->plaintext, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(
        &response->ciphertext_for_recipient, allocator, aws_byte_cursor_from_c_str(CIPHERTEXT_BLOB_DATA)));

    struct aws_string *json = aws_kms_generate_random_response_to_json(response);
    ASSERT_NOT_NULL(json);

    struct aws_string *expected = aws_string_new_from_c_str(
        allocator,
        "{ \"Plaintext\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"CiphertextForRecipient\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(expected);
    ASSERT_STR_EQUALS(aws_string_c_str(expected), aws_string_c_str(json));
    aws_string_destroy(expected);
    aws_string_destroy(json);
    aws_kms_generate_random_response_destroy(response);

    return SUCCESS;
}

AWS_TEST_CASE(test_kms_generate_random_response_from_json, s_test_kms_generate_random_response_from_json)
static int s_test_kms_generate_random_response_from_json(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *json = aws_string_new_from_c_str(
        allocator,
        "{ \"Plaintext\": \"" CIPHERTEXT_BLOB_BASE64 "\", "
        "\"CiphertextForRecipient\": \"" CIPHERTEXT_BLOB_BASE64 "\" }");
    ASSERT_NOT_NULL(json);

    struct aws_kms_generate_random_response *response = aws_kms_generate_random_response_from_json(allocator, json);
    ASSERT_NOT_NULL(response);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)response->plaintext.buffer,
        response->plaintext.len);

    ASSERT_BIN_ARRAYS_EQUALS(
        CIPHERTEXT_BLOB_DATA,
        sizeof(CIPHERTEXT_BLOB_DATA) - 1,
        (char *)response->ciphertext_for_recipient.buffer,
        response->ciphertext_for_recipient.len);

    /* Ensure we can serialize back to a JSON. */
    struct aws_string *json_second = aws_kms_generate_random_response_to_json(response);
    ASSERT_NOT_NULL(json_second);
    ASSERT_STR_EQUALS(aws_string_c_str(json), aws_string_c_str(json_second));

    aws_string_destroy(json);
    aws_string_destroy(json_second);
    aws_kms_generate_random_response_destroy(response);

    return SUCCESS;
}
