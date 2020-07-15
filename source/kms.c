/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/encoding.h>
#include <aws/nitro_enclaves/kms.h>
#include <json-c/json.h>

/**
 * AWS KMS Request / Response JSON key values.
 */
#define KMS_CIPHERTEXT_BLOB "CiphertextBlob"
#define KMS_ENCRYPTION_ALGORITHM "EncryptionAlgorithm"
#define KMS_ENCRYPTION_CONTEXT "EncryptionContext"
#define KMS_GRANT_TOKENS "GrantTokens"
#define KMS_KEY_ID "KeyId"

/**
 * Helper macro for safe comparing a C string with a C string literal.
 * Returns true if the strings are equal, false otherwise.
 */
#define AWS_SAFE_COMPARE(C_STR, STR_LIT) aws_array_eq((C_STR), strlen((C_STR)), (STR_LIT), sizeof((STR_LIT)) - 1)

/**
 * Adds a c string (key, value) pair to the json object.
 *
 * @param[out]  obj    The json object that is modified.
 * @param[in]   key    The key at which the c string value is added.
 * @param[in]   value  The c string value added.
 *
 * @return             AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_string_to_json(struct json_object *obj, const char *const key, const char *const value) {
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(aws_c_string_is_valid(key));
    AWS_PRECONDITION(aws_c_string_is_valid(value));

    struct json_object *elem = json_object_new_string(value);
    if (elem == NULL) {
        /* TODO: Create custom AWS_NITRO_ENCLAVES errors for @ref aws_raise_error. */
        return AWS_OP_ERR;
    }

    if (json_object_object_add(obj, key, elem) < 0) {
        json_object_put(elem);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/**
 * Obtains a @ref aws_string from an json object.
 *
 * @param[in]  allocator  The allocator used for memory management.
 * @param[in]  obj        The json object containing the string of interest.
 *
 * @return                A new aws_string object on success, NULL otherwise.
 */
static struct aws_string *s_aws_string_from_json(struct aws_allocator *allocator, struct json_object *obj) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(obj);

    const char *str = json_object_get_string(obj);
    if (str == NULL) {
        return NULL;
    }

    struct aws_string *string = aws_string_new_from_c_str(allocator, str);
    if (string == NULL) {
        return NULL;
    }

    return string;
}

/**
 * Adds a @ref aws_byte_buf as base64 encoded blob to the json object at the provided key.
 *
 * @param[in]   allocator  The allocator used for memory management.
 * @param[out]  obj        The json object that will contain the base64 encoded blob.
 * @param[in]   key        The key at which the aws byte buffer base64 encoded blob is added.
 * @param[in]   byte_buf   The aws_byte_buf that is encoded to a base64 blob.
 *
 * @return                 AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_aws_byte_buf_to_base64_json(
    struct aws_allocator *allocator,
    struct json_object *obj,
    const char *const key,
    const struct aws_byte_buf *byte_buf) {

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(aws_c_string_is_valid(key));
    AWS_PRECONDITION(aws_byte_buf_is_valid(byte_buf));

    size_t needed_capacity = 0;
    if (aws_base64_compute_encoded_len(byte_buf->len, &needed_capacity) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    struct aws_byte_buf buf;
    if (aws_byte_buf_init(&buf, allocator, needed_capacity + 1) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(byte_buf);
    if (aws_base64_encode(&cursor, &buf) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    if (aws_byte_buf_append_null_terminator(&buf) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    if (s_string_to_json(obj, key, (const char *)buf.buffer) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    aws_byte_buf_clean_up_secure(&buf);

    return AWS_OP_SUCCESS;

clean_up:
    aws_byte_buf_clean_up_secure(&buf);

    return AWS_OP_ERR;
}

/**
 * Obtains a decoded aws_byte_buf from a base64 encoded blob represented by a json object.
 *
 * @param[in]   allocator  The allocator used for memory management.
 * @param[in]   obj        The json object that contains the base64 encoded blob.
 * @param[out]  byte_buf   The aws byte buffer that is decoded from the base64 blob.
 *
 * @return                 AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_aws_byte_buf_from_base64_json(
    struct aws_allocator *allocator,
    struct json_object *obj,
    struct aws_byte_buf *byte_buf) {

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(byte_buf);

    const char *str = json_object_get_string(obj);
    if (str == NULL) {
        return AWS_OP_ERR;
    }

    size_t needed_capacity = 0;
    struct aws_byte_cursor cursor = aws_byte_cursor_from_c_str(str);
    if (aws_base64_compute_decoded_len(&cursor, &needed_capacity) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init(byte_buf, allocator, needed_capacity) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    if (aws_base64_decode(&cursor, byte_buf) != AWS_OP_SUCCESS) {
        aws_byte_buf_clean_up_secure(byte_buf);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/**
 * Adds a aws_hash_table as a map of strings to the json object at the provided key.
 *
 * @param[out]  obj  The json object that will contain the map of strings.
 * @param[in]   key  The key at which the map of strings is added.
 * @param[in]   map  The aws_hash_table value added.
 *
 * @return           AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_aws_hash_table_to_json(struct json_object *obj, const char *const key, const struct aws_hash_table *map) {
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(aws_c_string_is_valid(key));
    AWS_PRECONDITION(aws_hash_table_is_valid(map));

    struct json_object *json_obj = json_object_new_object();
    if (json_obj == NULL) {
        return AWS_OP_ERR;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(map); !aws_hash_iter_done(&iter); aws_hash_iter_next(&iter)) {
        const struct aws_string *map_key = iter.element.key;
        const struct aws_string *map_value = iter.element.value;

        if (s_string_to_json(json_obj, aws_string_c_str(map_key), aws_string_c_str(map_value)) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (json_object_object_add(obj, key, json_obj) < 0) {
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    json_object_put(json_obj);

    return AWS_OP_ERR;
}

/**
 * Adds a aws_array_list as a list of strings to the json object at the provided key.
 *
 * @param[out]  obj    The json object that will contain the map of strings.
 * @param[in]   key    The key at which the list of strings is added.
 * @param[in]   array  The aws_array_list value added.
 *
 * @return             AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_aws_array_list_to_json(
    struct json_object *obj,
    const char *const key,
    const struct aws_array_list *array) {

    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(aws_c_string_is_valid(key));
    AWS_PRECONDITION(aws_array_list_is_valid(array));

    struct json_object *arr = json_object_new_array();
    if (arr == NULL) {
        return AWS_OP_ERR;
    }

    for (size_t i = 0; i < aws_array_list_length(array); i++) {
        struct aws_string **elem = NULL;
        if (aws_array_list_get_at_ptr(array, (void **)&elem, i) != AWS_OP_SUCCESS) {
            goto clean_up;
        }

        struct json_object *elem_arr = json_object_new_string(aws_string_c_str(*elem));
        if (elem == NULL) {
            goto clean_up;
        }

        if (json_object_array_add(arr, elem_arr) < 0) {
            json_object_put(elem_arr);
            goto clean_up;
        }
    }

    if (json_object_object_add(obj, key, arr) < 0) {
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    json_object_put(arr);

    return AWS_OP_ERR;
}

/**
 * Obtains a @ref json_object from a aws_string representing a valid json.
 *
 * @param[in]  json  The json object represented by a aws_string.
 *
 * @return           A new json_object on success, NULL otherwise.
 */
struct json_object *s_json_object_from_string(const struct aws_string *json) {
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_tokener *tok = json_tokener_new_ex(JSON_TOKENER_STRICT | JSON_TOKENER_DEFAULT_DEPTH);
    if (tok == NULL) {
        return NULL;
    }

    struct json_object *obj = json_tokener_parse_ex(tok, aws_string_c_str(json), json->len);
    if (obj == NULL) {
        json_tokener_free(tok);
        return NULL;
    }

    json_tokener_free(tok);

    return obj;
}

struct aws_string *aws_kms_decrypt_request_to_json(const struct aws_kms_decrypt_request *req) {
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));
    AWS_PRECONDITION(aws_byte_buf_is_valid(&req->ciphertext_blob));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    /* Required parameter. */
    if (req->ciphertext_blob.buffer == NULL) {
        goto clean_up;
    }

    if (s_aws_byte_buf_to_base64_json(req->allocator, obj, KMS_CIPHERTEXT_BLOB, &req->ciphertext_blob) !=
        AWS_OP_SUCCESS) {
        goto clean_up;
    }

    /* Optional parameters. */
    if (req->encryption_algorithm != NULL) {
        if (s_string_to_json(obj, KMS_ENCRYPTION_ALGORITHM, aws_string_c_str(req->encryption_algorithm)) !=
            AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (aws_hash_table_is_valid(&req->encryption_context) &&
        aws_hash_table_get_entry_count(&req->encryption_context) != 0) {
        if (s_aws_hash_table_to_json(obj, KMS_ENCRYPTION_CONTEXT, &req->encryption_context) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (aws_array_list_is_valid(&req->grant_tokens) && aws_array_list_length(&req->grant_tokens) != 0) {
        if (s_aws_array_list_to_json(obj, KMS_GRANT_TOKENS, &req->grant_tokens) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (req->key_id != NULL) {
        if (s_string_to_json(obj, KMS_KEY_ID, aws_string_c_str(req->key_id)) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    struct aws_string *json = s_aws_string_from_json(req->allocator, obj);
    if (json == NULL) {
        goto clean_up;
    }

    json_object_put(obj);

    return json;

clean_up:
    json_object_put(obj);

    return NULL;
}

struct aws_kms_decrypt_request *aws_kms_decrypt_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_decrypt_request *req = aws_kms_decrypt_request_new(allocator);
    if (req == NULL) {
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (value_type == json_type_string) {
            if (AWS_SAFE_COMPARE(key, KMS_CIPHERTEXT_BLOB)) {
                if (s_aws_byte_buf_from_base64_json(allocator, value, &req->ciphertext_blob) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            if (AWS_SAFE_COMPARE(key, KMS_KEY_ID)) {
                req->key_id = s_aws_string_from_json(allocator, value);
                if (req->key_id == NULL) {
                    goto clean_up;
                }
                continue;
            }

            if (AWS_SAFE_COMPARE(key, KMS_ENCRYPTION_ALGORITHM)) {
                req->encryption_algorithm = s_aws_string_from_json(allocator, value);
                if (req->encryption_algorithm == NULL) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for string type. */
            goto clean_up;
        }

        /* Unexpected value type. */
        goto clean_up;
    }

    /* Validate required parameters. */
    if (req->ciphertext_blob.buffer == NULL || !aws_byte_buf_is_valid(&req->ciphertext_blob)) {
        goto clean_up;
    }

    json_object_put(obj);

    return req;

clean_up:
    json_object_put(obj);
    aws_kms_decrypt_request_destroy(req);

    return NULL;
}

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
