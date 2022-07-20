/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/encoding.h>
#include <aws/io/stream.h>
#include <aws/nitro_enclaves/internal/cms.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <json-c/json.h>

/**
 * AWS KMS Request / Response JSON key values.
 */
#define KMS_CIPHERTEXT_BLOB "CiphertextBlob"
#define KMS_ENCRYPTION_ALGORITHM "EncryptionAlgorithm"
#define KMS_ENCRYPTION_CONTEXT "EncryptionContext"
#define KMS_GRANT_TOKENS "GrantTokens"
#define KMS_KEY_ID "KeyId"
#define KMS_RECIPIENT "Recipient"
#define KMS_PUBLIC_KEY "PublicKey"
#define KMS_KEY_ENCRYPTION_ALGORITHM "KeyEncryptionAlgorithm"
#define KMS_ATTESTATION_DOCUMENT "AttestationDocument"
#define KMS_PLAINTEXT "Plaintext"
#define KMS_CIPHERTEXT_FOR_RECIPIENT "CiphertextForRecipient"
#define KMS_NUMBER_OF_BYTES "NumberOfBytes"
#define KMS_KEY_SPEC "KeySpec"
#define KMS_CUSTOM_KEY_STORE_ID "CustomKeyStoreId"

/**
 * Helper macro for safe comparing a C string with a C string literal.
 * Returns true if the strings are equal, false otherwise.
 */
#define AWS_SAFE_COMPARE(C_STR, STR_LIT) aws_array_eq((C_STR), strlen((C_STR)), (STR_LIT), sizeof((STR_LIT)) - 1)

/**
 * Aws string values for the AWS Encryption Algorithm used by KMS.
 */
AWS_STATIC_STRING_FROM_LITERAL(s_ea_symmetric_default, "SYMMETRIC_DEFAULT");
AWS_STATIC_STRING_FROM_LITERAL(s_ea_rsaes_oaep_sha_1, "RSAES_OAEP_SHA_1");
AWS_STATIC_STRING_FROM_LITERAL(s_ea_rsaes_oaep_sha_256, "RSAES_OAEP_SHA_256");

/**
 * Aws string values for the AWS Key Encryption Algorithm used by KMS.
 */
AWS_STATIC_STRING_FROM_LITERAL(s_aws_kea_rsaes_oaep_sha_256, "RSAES_OAEP_SHA_256");

/**
 * Aws string value for the AWS Key Spec used by KMS.
 */
AWS_STATIC_STRING_FROM_LITERAL(s_aws_ks_aes_256, "AES_256");
AWS_STATIC_STRING_FROM_LITERAL(s_aws_ks_aes_128, "AES_128");

/**
 * Initializes a @ref aws_encryption_algorithm from string.
 *
 * @param[in]   str                   The string used to initialize the encryption algorithm.
 * @param[out]  encryption_algorithm  The initialized encryption algorithm.
 *
 * @return                            True if the string is valid, false otherwise.
 */
static bool s_aws_encryption_algorithm_from_aws_string(
    const struct aws_string *str,
    enum aws_encryption_algorithm *encryption_algorithm) {

    AWS_PRECONDITION(aws_string_c_str(str));
    AWS_PRECONDITION(encryption_algorithm);

    if (aws_string_compare(str, s_ea_symmetric_default) == 0) {
        *encryption_algorithm = AWS_EA_SYMMETRIC_DEFAULT;
        return true;
    }

    if (aws_string_compare(str, s_ea_rsaes_oaep_sha_1) == 0) {
        *encryption_algorithm = AWS_EA_RSAES_OAEP_SHA_1;
        return true;
    }

    if (aws_string_compare(str, s_ea_rsaes_oaep_sha_256) == 0) {
        *encryption_algorithm = AWS_EA_RSAES_OAEP_SHA_256;
        return true;
    }

    return false;
}

/**
 * Obtains the string representation of a @ref aws_encryption_algorithm.
 *
 * @param[int]  encryption_algorithm  The encryption algorithm that is converted to string.
 *
 * @return                            A string representing the encryption algorithm.
 */
static const struct aws_string *s_aws_encryption_algorithm_to_aws_string(
    enum aws_encryption_algorithm encryption_algorithm) {

    switch (encryption_algorithm) {
        case AWS_EA_SYMMETRIC_DEFAULT:
            return s_ea_symmetric_default;
        case AWS_EA_RSAES_OAEP_SHA_1:
            return s_ea_rsaes_oaep_sha_1;
        case AWS_EA_RSAES_OAEP_SHA_256:
            return s_ea_rsaes_oaep_sha_256;

        case AWS_EA_UNINITIALIZED:
        default:
            return NULL;
    }
}

/**
 * Initializes a @ref aws_key_encryption_algorithm from string.
 *
 * @param[in]   str  The string used to initialize the key encryption algorithm.
 * @param[out]  kea  The initialized key encryption algorithm.
 *
 * @return           True if the string is valid, false otherwise.
 */
static bool s_aws_key_encryption_algorithm_from_aws_string(
    const struct aws_string *str,
    enum aws_key_encryption_algorithm *kea) {

    AWS_PRECONDITION(aws_string_c_str(str));
    AWS_PRECONDITION(kea);

    if (aws_string_compare(str, s_aws_kea_rsaes_oaep_sha_256) == 0) {
        *kea = AWS_KEA_RSAES_OAEP_SHA_256;
        return true;
    }

    return false;
}

/**
 * Obtains the string representation of a @ref aws_request_payer.
 *
 * @param[int]  kea  The request payer that is converted to string.
 *
 * @return           A string representing the encryption algorithm.
 */
static const struct aws_string *s_aws_key_encryption_algorithm_to_aws_string(enum aws_key_encryption_algorithm kea) {
    switch (kea) {
        case AWS_KEA_RSAES_OAEP_SHA_256:
            return s_aws_kea_rsaes_oaep_sha_256;

        case AWS_KEA_UNINITIALIZED:
        default:
            return NULL;
    }
}

/**
 * Initializes a @ref aws_key_spec from string.
 *
 * @param[in]   str  The string used to initialize the key spec.
 * @param[out]  ks   The initialized key spec.
 *
 * @return           True if the string is valid, false otherwise.
 */
static bool s_aws_key_spec_from_aws_string(const struct aws_string *str, enum aws_key_spec *ks) {
    AWS_PRECONDITION(aws_string_c_str(str));
    AWS_PRECONDITION(ks);

    if (aws_string_compare(str, s_aws_ks_aes_256) == 0) {
        *ks = AWS_KS_AES_256;
        return true;
    }

    if (aws_string_compare(str, s_aws_ks_aes_128) == 0) {
        *ks = AWS_KS_AES_128;
        return true;
    }

    return false;
}

/**
 * Obtains the string representation of a @ref aws_key_spec.
 *
 * @param[int]  ks  The key spec that is converted to string.
 *
 * @return          A string representing the key spec.
 */
static const struct aws_string *s_aws_key_spec_to_aws_string(enum aws_key_spec ks) {
    switch (ks) {
        case AWS_KS_AES_256:
            return s_aws_ks_aes_256;
        case AWS_KS_AES_128:
            return s_aws_ks_aes_128;

        case AWS_KS_UNINITIALIZED:
        default:
            return NULL;
    }
}

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
 * Adds a int32_t value (key, value) pair to the json object.
 *
 * @param[out]  obj    The json object that is modified.
 * @param[in]   key    The key at which the int32_t value is added.
 * @param[in]   value  The int32_t value added.
 *
 * @return             AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_int_to_json(struct json_object *obj, const char *const key, const int32_t value) {
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(aws_c_string_is_valid(key));

    struct json_object *elem = json_object_new_int(value);
    if (elem == NULL) {
        return AWS_OP_ERR;
    }

    if (json_object_object_add(obj, key, elem) < 0) {
        json_object_put(elem);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/**
 * Obtains a uint32_t from an json object.
 *
 * @param[in]   obj      The json object containing the number of interest.
 * @param[out]  out_val  The number obtained from the json object.
 *
 * @return               AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_int_from_json(struct json_object *obj, uint32_t *out_val) {
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(out_val);

    int32_t value = json_object_get_int(obj);
    if (value < 0) {
        return AWS_OP_ERR;
    }

    *out_val = (uint32_t)value;
    return AWS_OP_SUCCESS;
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
 * Obtains a @ref aws_hash_table from a map of strings represented by a json object.
 *
 * @param[in]   allocator  The allocator used for memory management.
 * @param[in]   obj        The json object that contains a list of strings.
 * @param[out]  map        The aws_hash_table that is obtained from the json object.
 *
 * @return                 AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_aws_hash_table_from_json(
    struct aws_allocator *allocator,
    struct json_object *obj,
    struct aws_hash_table *map) {

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(map);

    if (aws_hash_table_init(
            map,
            allocator,
            json_object_object_length(obj),
            aws_hash_string,
            aws_hash_callback_string_eq,
            aws_hash_callback_string_destroy,
            aws_hash_callback_string_destroy) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);

        if (json_object_get_type(value) != json_type_string) {
            goto clean_up;
        }

        struct aws_string *map_key = aws_string_new_from_c_str(allocator, key);
        if (map_key == NULL) {
            goto clean_up;
        }

        struct aws_string *map_value = s_aws_string_from_json(allocator, value);
        if (map_value == NULL) {
            aws_string_destroy(map_key);
            goto clean_up;
        }

        if (aws_hash_table_put(map, map_key, map_value, NULL) != AWS_OP_SUCCESS) {
            aws_string_destroy(map_key);
            aws_string_destroy(map_value);
            goto clean_up;
        }
    }

    return AWS_OP_SUCCESS;

clean_up:
    aws_hash_table_clean_up(map);

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
 * Obtains a @ref aws_array_list from a list of strings represented by a json object.
 *
 * @param[in]   allocator  The allocator used for memory management.
 * @param[in]   obj        The json object that contains a list of strings.
 * @param[out]  array      The aws_array_list that is obtained from the json object.
 *
 * @return                 AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
static int s_aws_array_list_from_json(
    struct aws_allocator *allocator,
    struct json_object *obj,
    struct aws_array_list *array) {

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(array);

    struct array_list *arr = json_object_get_array(obj);
    if (arr == NULL) {
        return AWS_OP_ERR;
    }

    size_t length = array_list_length(arr);
    if (aws_array_list_init_dynamic(array, allocator, length, sizeof(struct aws_string *)) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    for (size_t i = 0; i < length; i++) {
        struct json_object *elem = array_list_get_idx(arr, i);
        if (json_object_get_type(elem) != json_type_string) {
            goto clean_up;
        }

        struct aws_string *str = s_aws_string_from_json(allocator, elem);
        if (str == NULL) {
            goto clean_up;
        }

        if (aws_array_list_push_back(array, &str) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    return AWS_OP_SUCCESS;

clean_up:
    for (size_t i = 0; i < aws_array_list_length(array); i++) {
        struct aws_string *elem = NULL;
        AWS_FATAL_ASSERT(aws_array_list_get_at(array, &elem, i) == AWS_OP_SUCCESS);

        aws_string_destroy(elem);
    }

    aws_array_list_clean_up(array);

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

/**
 * Adds a @ref aws_string representing a json object
 * as (key, value) pair to the json object.
 *
 * @param[out]  obj    The json object that is modified.
 * @param[in]   key    The key at which the aws_string json object is added.
 * @param[in]   value  The aws_string representing a json object.
 *
 * @return             AWS_OP_SUCCESS on success, AWS_OP_ERR otherwise.
 */
int s_string_to_json_object(struct json_object *obj, const char *const key, const struct aws_string *value) {
    AWS_PRECONDITION(obj);
    AWS_PRECONDITION(aws_c_string_is_valid(key));
    AWS_PRECONDITION(aws_string_is_valid(value));

    struct json_object *json = s_json_object_from_string(value);
    if (json == NULL) {
        return AWS_OP_ERR;
    }

    if (json_object_object_add(obj, key, json) < 0) {
        json_object_put(json);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
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
    if (req->encryption_algorithm != AWS_EA_UNINITIALIZED) {
        const struct aws_string *encryption_algorithm =
            s_aws_encryption_algorithm_to_aws_string(req->encryption_algorithm);
        if (encryption_algorithm == NULL) {
            goto clean_up;
        }

        if (s_string_to_json(obj, KMS_ENCRYPTION_ALGORITHM, aws_string_c_str(encryption_algorithm)) != AWS_OP_SUCCESS) {
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

    if (req->recipient != NULL) {
        struct aws_string *str = aws_recipient_to_json(req->recipient);
        if (str == NULL) {
            goto clean_up;
        }

        if (s_string_to_json_object(obj, KMS_RECIPIENT, str) != AWS_OP_SUCCESS) {
            aws_string_destroy(str);
            goto clean_up;
        }

        aws_string_destroy(str);
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

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_decrypt_request *req = aws_kms_decrypt_request_new(allocator);
    if (req == NULL) {
        json_object_put(obj);
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
                struct aws_string *str = s_aws_string_from_json(allocator, value);
                if (str == NULL) {
                    goto clean_up;
                }

                if (!s_aws_encryption_algorithm_from_aws_string(str, &req->encryption_algorithm)) {
                    aws_string_destroy(str);
                    goto clean_up;
                }

                aws_string_destroy(str);
                continue;
            }

            /* Unexpected key for string type. */
            goto clean_up;
        }

        if (value_type == json_type_array) {
            if (AWS_SAFE_COMPARE(key, KMS_GRANT_TOKENS)) {
                if (s_aws_array_list_from_json(allocator, value, &req->grant_tokens) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for array type. */
            goto clean_up;
        }

        if (value_type == json_type_object) {
            if (AWS_SAFE_COMPARE(key, KMS_ENCRYPTION_CONTEXT)) {
                if (s_aws_hash_table_from_json(allocator, value, &req->encryption_context) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            if (AWS_SAFE_COMPARE(key, KMS_RECIPIENT)) {
                struct aws_string *str = s_aws_string_from_json(allocator, value);
                if (str == NULL) {
                    goto clean_up;
                }

                req->recipient = aws_recipient_from_json(allocator, str);
                if (req->recipient == NULL) {
                    aws_string_destroy(str);
                    goto clean_up;
                }

                aws_string_destroy(str);
                continue;
            }
            /* Unexpected key for object type. */
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

struct aws_string *aws_kms_encrypt_request_to_json(const struct aws_kms_encrypt_request *req) {
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));
    AWS_PRECONDITION(aws_byte_buf_is_valid(&req->plaintext));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    /* Required parameter. */
    if (req->plaintext.buffer == NULL) {
        goto clean_up;
    }

    if (s_aws_byte_buf_to_base64_json(req->allocator, obj, KMS_PLAINTEXT, &req->plaintext) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    /* Optional parameters. */
    if (req->encryption_algorithm != AWS_EA_UNINITIALIZED) {
        const struct aws_string *encryption_algorithm =
            s_aws_encryption_algorithm_to_aws_string(req->encryption_algorithm);
        if (encryption_algorithm == NULL) {
            goto clean_up;
        }

        if (s_string_to_json(obj, KMS_ENCRYPTION_ALGORITHM, aws_string_c_str(encryption_algorithm)) != AWS_OP_SUCCESS) {
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

struct aws_kms_encrypt_request *aws_kms_encrypt_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_encrypt_request *req = aws_kms_encrypt_request_new(allocator);
    if (req == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (value_type == json_type_string) {
            if (AWS_SAFE_COMPARE(key, KMS_PLAINTEXT)) {
                if (s_aws_byte_buf_from_base64_json(allocator, value, &req->plaintext) != AWS_OP_SUCCESS) {
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
                struct aws_string *str = s_aws_string_from_json(allocator, value);
                if (str == NULL) {
                    goto clean_up;
                }

                if (!s_aws_encryption_algorithm_from_aws_string(str, &req->encryption_algorithm)) {
                    aws_string_destroy(str);
                    goto clean_up;
                }

                aws_string_destroy(str);
                continue;
            }

            /* Unexpected key for string type. */
            goto clean_up;
        }

        if (value_type == json_type_array) {
            if (AWS_SAFE_COMPARE(key, KMS_GRANT_TOKENS)) {
                if (s_aws_array_list_from_json(allocator, value, &req->grant_tokens) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for array type. */
            goto clean_up;
        }

        if (value_type == json_type_object) {
            if (AWS_SAFE_COMPARE(key, KMS_ENCRYPTION_CONTEXT)) {
                if (s_aws_hash_table_from_json(allocator, value, &req->encryption_context) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for object type. */
            goto clean_up;
        }

        /* Unexpected value type. */
        goto clean_up;
    }

    /* Validate required parameters. */
    if (req->plaintext.buffer == NULL || !aws_byte_buf_is_valid(&req->plaintext)) {
        goto clean_up;
    }

    json_object_put(obj);

    return req;

clean_up:
    json_object_put(obj);
    aws_kms_encrypt_request_destroy(req);

    return NULL;
}

struct aws_string *aws_recipient_to_json(const struct aws_recipient *recipient) {
    AWS_PRECONDITION(recipient);
    AWS_PRECONDITION(aws_allocator_is_valid(recipient->allocator));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    if (recipient->key_encryption_algorithm != AWS_KEA_UNINITIALIZED) {
        const struct aws_string *kea =
            s_aws_key_encryption_algorithm_to_aws_string(recipient->key_encryption_algorithm);
        if (kea == NULL) {
            goto clean_up;
        }

        if (s_string_to_json(obj, KMS_KEY_ENCRYPTION_ALGORITHM, aws_string_c_str(kea)) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (recipient->attestation_document.buffer != NULL) {
        if (s_aws_byte_buf_to_base64_json(
                recipient->allocator, obj, KMS_ATTESTATION_DOCUMENT, &recipient->attestation_document) !=
            AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    struct aws_string *json = s_aws_string_from_json(recipient->allocator, obj);
    if (json == NULL) {
        goto clean_up;
    }

    json_object_put(obj);

    return json;

clean_up:
    json_object_put(obj);

    return NULL;
}

struct aws_recipient *aws_recipient_from_json(struct aws_allocator *allocator, const struct aws_string *json) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_recipient *recipient = aws_recipient_new(allocator);
    if (recipient == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (value_type != json_type_string) {
            goto clean_up;
        }

        if (AWS_SAFE_COMPARE(key, KMS_KEY_ENCRYPTION_ALGORITHM)) {
            struct aws_string *str = s_aws_string_from_json(allocator, value);
            if (str == NULL) {
                goto clean_up;
            }

            if (!s_aws_key_encryption_algorithm_from_aws_string(str, &recipient->key_encryption_algorithm)) {
                aws_string_destroy(str);
                goto clean_up;
            }

            aws_string_destroy(str);
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_ATTESTATION_DOCUMENT)) {
            if (s_aws_byte_buf_from_base64_json(allocator, value, &recipient->attestation_document) != AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }

        goto clean_up;
    }

    json_object_put(obj);

    return recipient;

clean_up:
    json_object_put(obj);
    aws_recipient_destroy(recipient);

    return NULL;
}

struct aws_string *aws_kms_decrypt_response_to_json(const struct aws_kms_decrypt_response *res) {
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));
    AWS_PRECONDITION(aws_string_is_valid(res->key_id));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    /* Required parameter. */
    if (s_string_to_json(obj, KMS_KEY_ID, aws_string_c_str(res->key_id)) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    /* Optional parameters. */
    if (res->plaintext.buffer != NULL) {
        if (s_aws_byte_buf_to_base64_json(res->allocator, obj, KMS_PLAINTEXT, &res->plaintext) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (res->encryption_algorithm != AWS_EA_UNINITIALIZED) {
        const struct aws_string *encryption_algorithm =
            s_aws_encryption_algorithm_to_aws_string(res->encryption_algorithm);
        if (encryption_algorithm == NULL) {
            goto clean_up;
        }

        if (s_string_to_json(obj, KMS_ENCRYPTION_ALGORITHM, aws_string_c_str(encryption_algorithm)) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (res->ciphertext_for_recipient.buffer != NULL) {
        if (s_aws_byte_buf_to_base64_json(
                res->allocator, obj, KMS_CIPHERTEXT_FOR_RECIPIENT, &res->ciphertext_for_recipient) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    struct aws_string *json = s_aws_string_from_json(res->allocator, obj);
    if (json == NULL) {
        goto clean_up;
    }

    json_object_put(obj);
    return json;

clean_up:
    json_object_put(obj);
    return NULL;
}

struct aws_kms_decrypt_response *aws_kms_decrypt_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_decrypt_response *response = aws_kms_decrypt_response_new(allocator);
    if (response == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (AWS_SAFE_COMPARE(key, KMS_KEY_ID)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            response->key_id = s_aws_string_from_json(allocator, value);
            if (response->key_id == NULL) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_PLAINTEXT)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->plaintext) != AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_ENCRYPTION_ALGORITHM)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            struct aws_string *str = s_aws_string_from_json(allocator, value);
            if (str == NULL) {
                goto clean_up;
            }

            if (!s_aws_encryption_algorithm_from_aws_string(str, &response->encryption_algorithm)) {
                aws_string_destroy(str);
                goto clean_up;
            }

            aws_string_destroy(str);
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_CIPHERTEXT_FOR_RECIPIENT)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->ciphertext_for_recipient) !=
                AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }
    }

    /* Validate required parameters. */
    if (!aws_string_is_valid(response->key_id)) {
        goto clean_up;
    }

    json_object_put(obj);

    return response;

clean_up:
    json_object_put(obj);
    aws_kms_decrypt_response_destroy(response);

    return NULL;
}

struct aws_string *aws_kms_encrypt_response_to_json(const struct aws_kms_encrypt_response *res) {
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));
    AWS_PRECONDITION(aws_string_is_valid(res->key_id));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    /* Required parameter. */
    if (s_string_to_json(obj, KMS_KEY_ID, aws_string_c_str(res->key_id)) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    /* Optional parameters. */
    if (res->ciphertext_blob.buffer != NULL) {
        if (s_aws_byte_buf_to_base64_json(res->allocator, obj, KMS_CIPHERTEXT_BLOB, &res->ciphertext_blob) !=
            AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (res->encryption_algorithm != AWS_EA_UNINITIALIZED) {
        const struct aws_string *encryption_algorithm =
            s_aws_encryption_algorithm_to_aws_string(res->encryption_algorithm);
        if (encryption_algorithm == NULL) {
            goto clean_up;
        }

        if (s_string_to_json(obj, KMS_ENCRYPTION_ALGORITHM, aws_string_c_str(encryption_algorithm)) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    struct aws_string *json = s_aws_string_from_json(res->allocator, obj);
    if (json == NULL) {
        goto clean_up;
    }

    json_object_put(obj);
    return json;

clean_up:
    json_object_put(obj);
    return NULL;
}

struct aws_kms_encrypt_response *aws_kms_encrypt_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_encrypt_response *response = aws_kms_encrypt_response_new(allocator);
    if (response == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (AWS_SAFE_COMPARE(key, KMS_KEY_ID)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            response->key_id = s_aws_string_from_json(allocator, value);
            if (response->key_id == NULL) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_CIPHERTEXT_BLOB)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->ciphertext_blob) != AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_ENCRYPTION_ALGORITHM)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            struct aws_string *str = s_aws_string_from_json(allocator, value);
            if (str == NULL) {
                goto clean_up;
            }

            if (!s_aws_encryption_algorithm_from_aws_string(str, &response->encryption_algorithm)) {
                aws_string_destroy(str);
                goto clean_up;
            }

            aws_string_destroy(str);
            continue;
        }
    }

    /* Validate required parameters. */
    if (!aws_string_is_valid(response->key_id)) {
        goto clean_up;
    }

    json_object_put(obj);

    return response;

clean_up:
    json_object_put(obj);
    aws_kms_encrypt_response_destroy(response);

    return NULL;
}

struct aws_string *aws_kms_generate_data_key_request_to_json(const struct aws_kms_generate_data_key_request *req) {
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));
    AWS_PRECONDITION(aws_string_is_valid(req->key_id));
    /* KeySpec or the NumberOfBytes must be specified, but not both. */
    AWS_PRECONDITION(req->number_of_bytes == 0 || req->key_spec == AWS_KS_UNINITIALIZED);
    AWS_PRECONDITION(req->number_of_bytes > 0 || req->key_spec != AWS_KS_UNINITIALIZED);

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    /* Required parameters. */
    if (s_string_to_json(obj, KMS_KEY_ID, aws_string_c_str(req->key_id)) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    if (req->number_of_bytes > 0) {
        if (s_int_to_json(obj, KMS_NUMBER_OF_BYTES, req->number_of_bytes) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    } else if (req->key_spec != AWS_KS_UNINITIALIZED) {
        const struct aws_string *key_spec = s_aws_key_spec_to_aws_string(req->key_spec);
        if (key_spec == NULL) {
            goto clean_up;
        }

        if (s_string_to_json(obj, KMS_KEY_SPEC, aws_string_c_str(key_spec)) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    /* Optional parameters. */
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

    if (req->recipient != NULL) {
        struct aws_string *str = aws_recipient_to_json(req->recipient);
        if (str == NULL) {
            goto clean_up;
        }

        if (s_string_to_json_object(obj, KMS_RECIPIENT, str) != AWS_OP_SUCCESS) {
            aws_string_destroy(str);
            goto clean_up;
        }

        aws_string_destroy(str);
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

struct aws_kms_generate_data_key_request *aws_kms_generate_data_key_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_generate_data_key_request *req = aws_kms_generate_data_key_request_new(allocator);
    if (req == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (value_type == json_type_string) {
            if (AWS_SAFE_COMPARE(key, KMS_KEY_ID)) {
                req->key_id = s_aws_string_from_json(allocator, value);
                if (req->key_id == NULL) {
                    goto clean_up;
                }
                continue;
            }

            if (AWS_SAFE_COMPARE(key, KMS_KEY_SPEC)) {
                struct aws_string *str = s_aws_string_from_json(allocator, value);
                if (str == NULL) {
                    goto clean_up;
                }

                if (!s_aws_key_spec_from_aws_string(str, &req->key_spec)) {
                    aws_string_destroy(str);
                    goto clean_up;
                }

                aws_string_destroy(str);
                continue;
            }

            /* Unexpected key for string type. */
            goto clean_up;
        }

        if (value_type == json_type_array) {
            if (AWS_SAFE_COMPARE(key, KMS_GRANT_TOKENS)) {
                if (s_aws_array_list_from_json(allocator, value, &req->grant_tokens) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for array type. */
            goto clean_up;
        }

        if (value_type == json_type_object) {
            if (AWS_SAFE_COMPARE(key, KMS_ENCRYPTION_CONTEXT)) {
                if (s_aws_hash_table_from_json(allocator, value, &req->encryption_context) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            if (AWS_SAFE_COMPARE(key, KMS_RECIPIENT)) {
                struct aws_string *str = s_aws_string_from_json(allocator, value);
                if (str == NULL) {
                    goto clean_up;
                }

                req->recipient = aws_recipient_from_json(allocator, str);
                if (req->recipient == NULL) {
                    aws_string_destroy(str);
                    goto clean_up;
                }

                aws_string_destroy(str);
                continue;
            }

            /* Unexpected key for object type. */
            goto clean_up;
        }

        if (value_type == json_type_int) {
            if (AWS_SAFE_COMPARE(key, KMS_NUMBER_OF_BYTES)) {
                if (s_int_from_json(value, &req->number_of_bytes) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for object type. */
            goto clean_up;
        }

        /* Unexpected value type. */
        goto clean_up;
    }

    /* Validate required parameters. */
    if (!aws_string_is_valid(req->key_id)) {
        goto clean_up;
    }

    /* KeySpec or the NumberOfBytes must be specified, but not both. */
    if (req->number_of_bytes > 0 && req->key_spec != AWS_KS_UNINITIALIZED) {
        goto clean_up;
    }

    if (req->number_of_bytes == 0 && req->key_spec == AWS_KS_UNINITIALIZED) {
        goto clean_up;
    }

    json_object_put(obj);

    return req;

clean_up:
    json_object_put(obj);
    aws_kms_generate_data_key_request_destroy(req);

    return NULL;
}

struct aws_string *aws_kms_generate_data_key_response_to_json(const struct aws_kms_generate_data_key_response *res) {
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));
    AWS_PRECONDITION(aws_string_is_valid(res->key_id));
    AWS_PRECONDITION(aws_byte_buf_is_valid(&res->ciphertext_blob));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    /* Required parameters. */
    if (s_string_to_json(obj, KMS_KEY_ID, aws_string_c_str(res->key_id)) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    if (s_aws_byte_buf_to_base64_json(res->allocator, obj, KMS_CIPHERTEXT_BLOB, &res->ciphertext_blob) !=
        AWS_OP_SUCCESS) {
        goto clean_up;
    }

    /* Optional parameters. */
    if (s_aws_byte_buf_to_base64_json(res->allocator, obj, KMS_PLAINTEXT, &res->plaintext) != AWS_OP_SUCCESS) {
        goto clean_up;
    }

    if (res->ciphertext_for_recipient.buffer != NULL) {
        if (s_aws_byte_buf_to_base64_json(
                res->allocator, obj, KMS_CIPHERTEXT_FOR_RECIPIENT, &res->ciphertext_for_recipient) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    struct aws_string *json = s_aws_string_from_json(res->allocator, obj);
    if (json == NULL) {
        goto clean_up;
    }

    json_object_put(obj);
    return json;

clean_up:
    json_object_put(obj);

    return NULL;
}

struct aws_kms_generate_data_key_response *aws_kms_generate_data_key_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_generate_data_key_response *response = aws_kms_generate_data_key_response_new(allocator);
    if (response == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (AWS_SAFE_COMPARE(key, KMS_KEY_ID)) {
            response->key_id = s_aws_string_from_json(allocator, value);
            if (response->key_id == NULL) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_CIPHERTEXT_BLOB)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->ciphertext_blob) != AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_PLAINTEXT)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->plaintext) != AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_CIPHERTEXT_FOR_RECIPIENT)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->ciphertext_for_recipient) !=
                AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }
    }

    /* Validate required parameters. */
    if (!aws_string_is_valid(response->key_id)) {
        goto clean_up;
    }

    if (response->ciphertext_blob.buffer == NULL || !aws_byte_buf_is_valid(&response->ciphertext_blob)) {
        goto clean_up;
    }

    json_object_put(obj);

    return response;

clean_up:
    json_object_put(obj);
    aws_kms_generate_data_key_response_destroy(response);

    return NULL;
}

struct aws_string *aws_kms_generate_random_request_to_json(const struct aws_kms_generate_random_request *req) {
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    if (req->number_of_bytes > 0) {
        if (s_int_to_json(obj, KMS_NUMBER_OF_BYTES, req->number_of_bytes) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (aws_string_is_valid(req->custom_key_store_id)) {
        if (s_string_to_json(obj, KMS_CUSTOM_KEY_STORE_ID, aws_string_c_str(req->custom_key_store_id)) !=
            AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (req->recipient != NULL) {
        struct aws_string *str = aws_recipient_to_json(req->recipient);
        if (str == NULL) {
            goto clean_up;
        }

        if (s_string_to_json_object(obj, KMS_RECIPIENT, str) != AWS_OP_SUCCESS) {
            aws_string_destroy(str);
            goto clean_up;
        }

        aws_string_destroy(str);
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

struct aws_kms_generate_random_request *aws_kms_generate_random_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_generate_random_request *request = aws_kms_generate_random_request_new(allocator);
    if (request == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (value_type == json_type_string) {
            if (AWS_SAFE_COMPARE(key, KMS_CUSTOM_KEY_STORE_ID)) {
                request->custom_key_store_id = s_aws_string_from_json(allocator, value);
                if (request->custom_key_store_id == NULL) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for object type. */
            goto clean_up;
        }

        if (value_type == json_type_object) {
            if (AWS_SAFE_COMPARE(key, KMS_RECIPIENT)) {
                struct aws_string *str = s_aws_string_from_json(allocator, value);
                if (str == NULL) {
                    goto clean_up;
                }

                request->recipient = aws_recipient_from_json(allocator, str);
                if (request->recipient == NULL) {
                    aws_string_destroy(str);
                    goto clean_up;
                }

                aws_string_destroy(str);
                continue;
            }

            /* Unexpected key for object type. */
            goto clean_up;
        }

        if (value_type == json_type_int) {
            if (AWS_SAFE_COMPARE(key, KMS_NUMBER_OF_BYTES)) {
                if (s_int_from_json(value, &request->number_of_bytes) != AWS_OP_SUCCESS) {
                    goto clean_up;
                }
                continue;
            }

            /* Unexpected key for object type. */
            goto clean_up;
        }

        /* Unexpected value type. */
        goto clean_up;
    }

    json_object_put(obj);

    return request;

clean_up:
    json_object_put(obj);
    aws_kms_generate_random_request_destroy(request);

    return NULL;
}

struct aws_string *aws_kms_generate_random_response_to_json(const struct aws_kms_generate_random_response *res) {
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));

    struct json_object *obj = json_object_new_object();
    if (obj == NULL) {
        return NULL;
    }

    if (res->plaintext.buffer != NULL) {
        if (s_aws_byte_buf_to_base64_json(res->allocator, obj, KMS_PLAINTEXT, &res->plaintext) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    if (res->ciphertext_for_recipient.buffer != NULL) {
        if (s_aws_byte_buf_to_base64_json(
                res->allocator, obj, KMS_CIPHERTEXT_FOR_RECIPIENT, &res->ciphertext_for_recipient) != AWS_OP_SUCCESS) {
            goto clean_up;
        }
    }

    struct aws_string *json = s_aws_string_from_json(res->allocator, obj);
    if (json == NULL) {
        goto clean_up;
    }

    json_object_put(obj);
    return json;

clean_up:
    json_object_put(obj);

    return NULL;
}

struct aws_kms_generate_random_response *aws_kms_generate_random_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json) {

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_string_is_valid(json));

    struct json_object *obj = s_json_object_from_string(json);
    if (obj == NULL) {
        return NULL;
    }

    struct aws_kms_generate_random_response *response = aws_kms_generate_random_response_new(allocator);
    if (response == NULL) {
        json_object_put(obj);
        return NULL;
    }

    struct json_object_iterator it_end = json_object_iter_end(obj);
    for (struct json_object_iterator it = json_object_iter_begin(obj); !json_object_iter_equal(&it, &it_end);
         json_object_iter_next(&it)) {
        const char *key = json_object_iter_peek_name(&it);
        struct json_object *value = json_object_iter_peek_value(&it);
        int value_type = json_object_get_type(value);

        if (AWS_SAFE_COMPARE(key, KMS_PLAINTEXT)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->plaintext) != AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }

        if (AWS_SAFE_COMPARE(key, KMS_CIPHERTEXT_FOR_RECIPIENT)) {
            if (value_type != json_type_string) {
                goto clean_up;
            }
            if (s_aws_byte_buf_from_base64_json(allocator, value, &response->ciphertext_for_recipient) !=
                AWS_OP_SUCCESS) {
                goto clean_up;
            }
            continue;
        }
    }

    json_object_put(obj);

    return response;

clean_up:
    json_object_put(obj);
    aws_kms_generate_random_response_destroy(response);

    return NULL;
}

struct aws_recipient *aws_recipient_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_recipient *recipient = aws_mem_calloc(allocator, 1, sizeof(struct aws_recipient));
    if (recipient == NULL) {
        return NULL;
    }

    recipient->key_encryption_algorithm = AWS_KEA_UNINITIALIZED;

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&recipient->allocator) = allocator;

    return recipient;
}

void aws_recipient_destroy(struct aws_recipient *recipient) {
    if (recipient == NULL) {
        return;
    }
    AWS_PRECONDITION(recipient);
    AWS_PRECONDITION(aws_allocator_is_valid(recipient->allocator));

    if (aws_byte_buf_is_valid(&recipient->attestation_document)) {
        aws_byte_buf_clean_up_secure(&recipient->attestation_document);
    }

    aws_mem_release(recipient->allocator, recipient);
}

struct aws_kms_decrypt_request *aws_kms_decrypt_request_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_decrypt_request *request = aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_decrypt_request));
    if (request == NULL) {
        return NULL;
    }

    request->encryption_algorithm = AWS_EA_UNINITIALIZED;

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&request->allocator) = allocator;

    return request;
}

void aws_kms_decrypt_request_destroy(struct aws_kms_decrypt_request *req) {
    if (req == NULL) {
        return;
    }
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));

    if (aws_byte_buf_is_valid(&req->ciphertext_blob)) {
        aws_byte_buf_clean_up_secure(&req->ciphertext_blob);
    }

    if (aws_string_is_valid(req->key_id)) {
        aws_string_destroy(req->key_id);
    }

    if (req->recipient != NULL) {
        aws_recipient_destroy(req->recipient);
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

struct aws_kms_decrypt_response *aws_kms_decrypt_response_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_decrypt_response *response = aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_decrypt_response));
    if (response == NULL) {
        return NULL;
    }

    response->encryption_algorithm = AWS_EA_UNINITIALIZED;

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&response->allocator) = allocator;

    return response;
}

void aws_kms_decrypt_response_destroy(struct aws_kms_decrypt_response *res) {
    if (res == NULL) {
        return;
    }
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));

    if (aws_string_is_valid(res->key_id)) {
        aws_string_destroy(res->key_id);
    }

    if (aws_byte_buf_is_valid(&res->plaintext)) {
        aws_byte_buf_clean_up_secure(&res->plaintext);
    }

    if (aws_byte_buf_is_valid(&res->ciphertext_for_recipient)) {
        aws_byte_buf_clean_up_secure(&res->ciphertext_for_recipient);
    }

    aws_mem_release(res->allocator, res);
}

struct aws_kms_encrypt_request *aws_kms_encrypt_request_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_encrypt_request *request = aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_encrypt_request));
    if (request == NULL) {
        return NULL;
    }

    request->encryption_algorithm = AWS_EA_UNINITIALIZED;

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&request->allocator) = allocator;

    return request;
}

void aws_kms_encrypt_request_destroy(struct aws_kms_encrypt_request *req) {
    if (req == NULL) {
        return;
    }
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));

    if (aws_byte_buf_is_valid(&req->plaintext)) {
        aws_byte_buf_clean_up_secure(&req->plaintext);
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

struct aws_kms_encrypt_response *aws_kms_encrypt_response_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_encrypt_response *response = aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_encrypt_response));
    if (response == NULL) {
        return NULL;
    }

    response->encryption_algorithm = AWS_EA_UNINITIALIZED;

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&response->allocator) = allocator;

    return response;
}

void aws_kms_encrypt_response_destroy(struct aws_kms_encrypt_response *res) {
    if (res == NULL) {
        return;
    }
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));

    if (aws_string_is_valid(res->key_id)) {
        aws_string_destroy(res->key_id);
    }

    if (aws_byte_buf_is_valid(&res->ciphertext_blob)) {
        aws_byte_buf_clean_up_secure(&res->ciphertext_blob);
    }

    aws_mem_release(res->allocator, res);
}

struct aws_kms_generate_data_key_request *aws_kms_generate_data_key_request_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_generate_data_key_request *request =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_generate_data_key_request));
    if (request == NULL) {
        return NULL;
    }

    request->key_spec = AWS_KS_UNINITIALIZED;

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&request->allocator) = allocator;

    return request;
}

void aws_kms_generate_data_key_request_destroy(struct aws_kms_generate_data_key_request *req) {
    if (req == NULL) {
        return;
    }
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));

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

    if (req->recipient != NULL) {
        aws_recipient_destroy(req->recipient);
    }

    aws_mem_release(req->allocator, req);
}

struct aws_kms_generate_data_key_response *aws_kms_generate_data_key_response_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_generate_data_key_response *response =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_generate_data_key_response));
    if (response == NULL) {
        return NULL;
    }

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&response->allocator) = allocator;

    return response;
}

void aws_kms_generate_data_key_response_destroy(struct aws_kms_generate_data_key_response *res) {
    if (res == NULL) {
        return;
    }
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));

    if (aws_string_is_valid(res->key_id)) {
        aws_string_destroy(res->key_id);
    }

    if (aws_byte_buf_is_valid(&res->ciphertext_blob)) {
        aws_byte_buf_clean_up_secure(&res->ciphertext_blob);
    }

    if (aws_byte_buf_is_valid(&res->plaintext)) {
        aws_byte_buf_clean_up_secure(&res->plaintext);
    }

    if (aws_byte_buf_is_valid(&res->ciphertext_for_recipient)) {
        aws_byte_buf_clean_up_secure(&res->ciphertext_for_recipient);
    }

    aws_mem_release(res->allocator, res);
}

struct aws_kms_generate_random_request *aws_kms_generate_random_request_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_generate_random_request *request =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_generate_random_request));
    if (request == NULL) {
        return NULL;
    }

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&request->allocator) = allocator;

    return request;
}

void aws_kms_generate_random_request_destroy(struct aws_kms_generate_random_request *req) {
    if (req == NULL) {
        return;
    }
    AWS_PRECONDITION(req);
    AWS_PRECONDITION(aws_allocator_is_valid(req->allocator));

    if (aws_string_is_valid(req->custom_key_store_id)) {
        aws_string_destroy(req->custom_key_store_id);
    }

    if (req->recipient != NULL) {
        aws_recipient_destroy(req->recipient);
    }

    aws_mem_release(req->allocator, req);
}

struct aws_kms_generate_random_response *aws_kms_generate_random_response_new(struct aws_allocator *allocator) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_kms_generate_random_response *response =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_kms_generate_random_response));
    if (response == NULL) {
        return NULL;
    }

    /* Ensure allocator constness for customer usage. Utilize the @ref aws_string pattern. */
    *(struct aws_allocator **)(&response->allocator) = allocator;

    return response;
}

void aws_kms_generate_random_response_destroy(struct aws_kms_generate_random_response *res) {
    if (res == NULL) {
        return;
    }
    AWS_PRECONDITION(res);
    AWS_PRECONDITION(aws_allocator_is_valid(res->allocator));

    if (aws_byte_buf_is_valid(&res->plaintext)) {
        aws_byte_buf_clean_up_secure(&res->plaintext);
    }

    if (aws_byte_buf_is_valid(&res->ciphertext_for_recipient)) {
        aws_byte_buf_clean_up_secure(&res->ciphertext_for_recipient);
    }

    aws_mem_release(res->allocator, res);
}

AWS_STATIC_STRING_FROM_LITERAL(s_kms_string, "kms");

struct aws_nitro_enclaves_kms_client_configuration *aws_nitro_enclaves_kms_client_config_default(
    struct aws_string *region,
    struct aws_socket_endpoint *endpoint,
    enum aws_socket_domain domain,
    struct aws_string *access_key_id,
    struct aws_string *secret_access_key,
    struct aws_string *session_token) {

    AWS_PRECONDITION(aws_string_is_valid(region));
    AWS_PRECONDITION(aws_string_is_valid(access_key_id));
    AWS_PRECONDITION(aws_string_is_valid(secret_access_key));
    if (session_token != NULL) {
        AWS_PRECONDITION(aws_string_is_valid(session_token));
    }

    struct aws_allocator *allocator = aws_nitro_enclaves_get_allocator();
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_nitro_enclaves_kms_client_configuration *config =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_nitro_enclaves_kms_client_configuration));
    if (config == NULL) {
        return NULL;
    }

    config->allocator = allocator;
    config->region = region;
    config->endpoint = endpoint;
    config->domain = domain;

    struct aws_credentials *creds = aws_credentials_new(
        allocator,
        aws_byte_cursor_from_string(access_key_id),
        aws_byte_cursor_from_string(secret_access_key),
        aws_byte_cursor_from_string(session_token),
        48 * 3600); /* Expiration in seconds */
    if (creds == NULL) {
        aws_mem_release(allocator, config);
        return NULL;
    }

    config->credentials = creds;
    config->credentials_provider = NULL;

    return config;
}

void aws_nitro_enclaves_kms_client_config_destroy(struct aws_nitro_enclaves_kms_client_configuration *config) {
    if (config == NULL) {
        return;
    }

    AWS_PRECONDITION(aws_allocator_is_valid(config->allocator));

    if (config->credentials != NULL) {
        aws_credentials_release(config->credentials);
    }

    aws_mem_release(config->allocator, config);
}

struct aws_nitro_enclaves_kms_client *aws_nitro_enclaves_kms_client_new(
    struct aws_nitro_enclaves_kms_client_configuration *configuration) {
    struct aws_allocator *allocator =
        configuration->allocator != NULL ? configuration->allocator : aws_nitro_enclaves_get_allocator();
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));

    struct aws_nitro_enclaves_kms_client *client =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_nitro_enclaves_kms_client));
    if (client == NULL) {
        return NULL;
    }

    client->allocator = allocator;

    struct aws_nitro_enclaves_rest_client_configuration rest_configuration = {
        .allocator = allocator,
        .service = s_kms_string,
        .region = configuration->region,
        .credentials = configuration->credentials,
        .credentials_provider = configuration->credentials_provider,
        .host_name = configuration->host_name,
    };

    if (configuration->endpoint != NULL) {
        rest_configuration.endpoint = configuration->endpoint;
        rest_configuration.domain = configuration->domain;
    }

    client->rest_client = aws_nitro_enclaves_rest_client_new(&rest_configuration);
    if (client->rest_client == NULL) {
        aws_mem_release(allocator, client);
        return NULL;
    }

    client->keypair = aws_attestation_rsa_keypair_new(allocator, AWS_RSA_2048);
    if (client->keypair == NULL) {
        aws_nitro_enclaves_rest_client_destroy(client->rest_client);
        aws_mem_release(allocator, client);
        return NULL;
    }

    return client;
}

void aws_nitro_enclaves_kms_client_destroy(struct aws_nitro_enclaves_kms_client *client) {
    if (client == NULL) {
        return;
    }

    aws_attestation_rsa_keypair_destroy(client->keypair);
    aws_nitro_enclaves_rest_client_destroy(client->rest_client);
    aws_mem_release(client->allocator, client);
}

static int s_aws_nitro_enclaves_kms_client_call_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    struct aws_byte_cursor target,
    struct aws_string *request,
    struct aws_string **response) {
    *response = NULL;

    struct aws_nitro_enclaves_rest_response *rest_response = aws_nitro_enclaves_rest_client_request_blocking(
        client->rest_client,
        aws_http_method_post,
        aws_byte_cursor_from_c_str("/"),
        target,
        aws_byte_cursor_from_string(request));
    if (rest_response == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_input_stream *request_stream = aws_http_message_get_body_stream(rest_response->response);
    struct aws_byte_buf response_data;
    int64_t length;
    aws_input_stream_get_length(request_stream, &length);

    aws_byte_buf_init(&response_data, client->allocator, length);
    aws_input_stream_read(request_stream, &response_data);
    *response = aws_string_new_from_array(client->allocator, response_data.buffer, response_data.len);
    aws_byte_buf_clean_up(&response_data);

    int status = AWS_OP_SUCCESS;
    aws_http_message_get_response_status(rest_response->response, &status);
    aws_nitro_enclaves_rest_response_destroy(rest_response);

    return status;
}

static int s_decrypt_ciphertext_for_recipient(
    struct aws_allocator *allocator,
    struct aws_byte_buf *ciphertext_for_recipient,
    struct aws_rsa_keypair *keypair,
    struct aws_byte_buf *plaintext) {
    AWS_PRECONDITION(aws_allocator_is_valid(allocator));
    AWS_PRECONDITION(aws_byte_buf_is_valid(ciphertext_for_recipient));
    AWS_PRECONDITION(keypair != NULL);

    struct aws_byte_buf encrypted_symm_key, decrypted_symm_key, iv, ciphertext_out;
    int rc = aws_cms_parse_enveloped_data(ciphertext_for_recipient, &encrypted_symm_key, &iv, &ciphertext_out);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Cannot parse CMS enveloped data.\n");
        return AWS_OP_ERR;
    }

    rc = aws_attestation_rsa_decrypt(allocator, keypair, &encrypted_symm_key, &decrypted_symm_key);
    if (rc != AWS_OP_SUCCESS) {
        aws_byte_buf_clean_up(&encrypted_symm_key);
        aws_byte_buf_clean_up(&iv);
        aws_byte_buf_clean_up(&ciphertext_out);
        return rc;
    }

    rc = aws_cms_cipher_decrypt(&ciphertext_out, &decrypted_symm_key, &iv, plaintext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Cannot decrypt CMS encrypted content\n");
        return rc;
    }

    aws_byte_buf_clean_up(&encrypted_symm_key);
    aws_byte_buf_clean_up(&decrypted_symm_key);
    aws_byte_buf_clean_up(&iv);
    aws_byte_buf_clean_up(&ciphertext_out);

    return rc;
}

static struct aws_byte_cursor kms_target_decrypt = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TrentService.Decrypt");
static struct aws_byte_cursor kms_target_encrypt = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TrentService.Encrypt");
static struct aws_byte_cursor kms_target_generate_data_key =
    AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TrentService.GenerateDataKey");
static struct aws_byte_cursor kms_target_generate_random =
    AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("TrentService.GenerateRandom");

int aws_kms_decrypt_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    const struct aws_string *encryption_algorithm,
    const struct aws_byte_buf *ciphertext,
    struct aws_byte_buf *plaintext /* TODO: err_reason */) {
    AWS_PRECONDITION(client != NULL);
    AWS_PRECONDITION(ciphertext != NULL);
    AWS_PRECONDITION(plaintext != NULL);

    struct aws_string *response = NULL;
    struct aws_string *request = NULL;
    struct aws_kms_decrypt_response *response_structure = NULL;
    struct aws_kms_decrypt_request *request_structure = NULL;
    int rc = 0;

    request_structure = aws_kms_decrypt_request_new(client->allocator);
    if (request_structure == NULL) {
        return AWS_OP_ERR;
    }

    aws_byte_buf_init_copy(&request_structure->ciphertext_blob, client->allocator, ciphertext);

    if (key_id != NULL) {
        request_structure->key_id = aws_string_clone_or_reuse(client->allocator, key_id);
        if (aws_string_compare(encryption_algorithm, s_ea_symmetric_default) == 0) {
            request_structure->encryption_algorithm = AWS_EA_SYMMETRIC_DEFAULT;
        } else if (aws_string_compare(encryption_algorithm, s_ea_rsaes_oaep_sha_1) == 0) {
            request_structure->encryption_algorithm = AWS_EA_RSAES_OAEP_SHA_1;
        } else if (aws_string_compare(encryption_algorithm, s_ea_rsaes_oaep_sha_256) == 0) {
            request_structure->encryption_algorithm = AWS_EA_RSAES_OAEP_SHA_256;
        } else {
            fprintf(stderr, "Invalid encryption algorithm\n");
            goto err_clean;
        }
    }

    request_structure->recipient = aws_recipient_new(client->allocator);
    if (request_structure->recipient == NULL) {
        goto err_clean;
    }
    rc = aws_attestation_request(
        client->allocator, client->keypair, &request_structure->recipient->attestation_document);
    if (rc != AWS_OP_SUCCESS) {
        goto err_clean;
    }
    request_structure->recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;

    request = aws_kms_decrypt_request_to_json(request_structure);
    if (request == NULL) {
        goto err_clean;
    }

    rc = s_aws_nitro_enclaves_kms_client_call_blocking(client, kms_target_decrypt, request, &response);
    if (rc != 200) {
        fprintf(stderr, "Got non-200 answer from KMS: %d\n", rc);
        goto err_clean;
    }

    response_structure = aws_kms_decrypt_response_from_json(client->allocator, response);
    if (response_structure == NULL) {
        fprintf(stderr, "Could not read response from KMS: %d\n", rc);
        goto err_clean;
    }

    rc = s_decrypt_ciphertext_for_recipient(
        client->allocator, &response_structure->ciphertext_for_recipient, client->keypair, plaintext);

    aws_kms_decrypt_request_destroy(request_structure);
    aws_kms_decrypt_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);

    return rc;
err_clean:
    aws_kms_decrypt_request_destroy(request_structure);
    aws_kms_decrypt_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);
    return AWS_OP_ERR;
}

int aws_kms_encrypt_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    const struct aws_byte_buf *plaintext,
    struct aws_byte_buf *ciphertext_blob
    /* TODO: err_reason */) {
    AWS_PRECONDITION(client != NULL);
    AWS_PRECONDITION(key_id != NULL);
    AWS_PRECONDITION(ciphertext_blob != NULL);
    AWS_PRECONDITION(plaintext != NULL);

    struct aws_string *response = NULL;
    struct aws_string *request = NULL;
    struct aws_kms_encrypt_response *response_structure = NULL;
    struct aws_kms_encrypt_request *request_structure = NULL;
    int rc = 0;

    request_structure = aws_kms_encrypt_request_new(client->allocator);
    if (request_structure == NULL) {
        return AWS_OP_ERR;
    }

    aws_byte_buf_init_copy(&request_structure->plaintext, client->allocator, plaintext);
    request_structure->key_id = aws_string_clone_or_reuse(client->allocator, key_id);

    request = aws_kms_encrypt_request_to_json(request_structure);
    if (request == NULL) {
        goto err_clean;
    }

    rc = s_aws_nitro_enclaves_kms_client_call_blocking(client, kms_target_encrypt, request, &response);
    if (rc != 200) {
        fprintf(stderr, "Got non-200 answer from KMS: %d\n", rc);
        goto err_clean;
    }

    response_structure = aws_kms_encrypt_response_from_json(client->allocator, response);
    if (response_structure == NULL) {
        fprintf(stderr, "Could not read response from KMS: %d\n", rc);
        goto err_clean;
    }

    aws_byte_buf_init_copy(ciphertext_blob, client->allocator, &response_structure->ciphertext_blob);

    aws_kms_encrypt_request_destroy(request_structure);
    aws_kms_encrypt_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);

    return AWS_OP_SUCCESS;
err_clean:
    aws_kms_encrypt_request_destroy(request_structure);
    aws_kms_encrypt_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);
    return AWS_OP_ERR;
}

int aws_kms_generate_data_key_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    enum aws_key_spec key_spec,
    struct aws_byte_buf *plaintext,
    struct aws_byte_buf *ciphertext_blob
    /* TODO: err_reason */) {
    AWS_PRECONDITION(client != NULL);
    AWS_PRECONDITION(key_id != NULL);
    AWS_PRECONDITION(plaintext != NULL);
    AWS_PRECONDITION(ciphertext_blob != NULL);

    struct aws_string *response = NULL;
    struct aws_string *request = NULL;
    struct aws_kms_generate_data_key_response *response_structure = NULL;
    struct aws_kms_generate_data_key_request *request_structure = NULL;
    int rc = 0;

    request_structure = aws_kms_generate_data_key_request_new(client->allocator);
    if (request_structure == NULL) {
        return AWS_OP_ERR;
    }

    request_structure->key_id = aws_string_clone_or_reuse(client->allocator, key_id);
    request_structure->key_spec = key_spec;

    request_structure->recipient = aws_recipient_new(client->allocator);
    if (request_structure->recipient == NULL) {
        goto err_clean;
    }
    rc = aws_attestation_request(
        client->allocator, client->keypair, &request_structure->recipient->attestation_document);
    if (rc != AWS_OP_SUCCESS) {
        goto err_clean;
    }
    request_structure->recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;

    request = aws_kms_generate_data_key_request_to_json(request_structure);
    if (request == NULL) {
        goto err_clean;
    }

    rc = s_aws_nitro_enclaves_kms_client_call_blocking(client, kms_target_generate_data_key, request, &response);
    if (rc != 200) {
        fprintf(stderr, "Got non-200 answer from KMS: %d\n", rc);
        goto err_clean;
    }

    response_structure = aws_kms_generate_data_key_response_from_json(client->allocator, response);
    if (response_structure == NULL) {
        fprintf(stderr, "Could not read response from KMS: %d\n", rc);
        goto err_clean;
    }

    rc = s_decrypt_ciphertext_for_recipient(
        client->allocator, &response_structure->ciphertext_for_recipient, client->keypair, plaintext);

    aws_byte_buf_init_copy(ciphertext_blob, client->allocator, &response_structure->ciphertext_blob);
    aws_kms_generate_data_key_request_destroy(request_structure);
    aws_kms_generate_data_key_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);

    return rc;
err_clean:
    aws_kms_generate_data_key_request_destroy(request_structure);
    aws_kms_generate_data_key_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);
    return AWS_OP_ERR;
}

int aws_kms_generate_random_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    uint32_t number_of_bytes,
    struct aws_byte_buf *plaintext /* TODO: err_reason */) {
    AWS_PRECONDITION(client != NULL);
    AWS_PRECONDITION(number_of_bytes > 0);
    AWS_PRECONDITION(plaintext != NULL);

    struct aws_string *response = NULL;
    struct aws_string *request = NULL;
    struct aws_kms_generate_random_response *response_structure = NULL;
    struct aws_kms_generate_random_request *request_structure = NULL;
    int rc = 0;

    request_structure = aws_kms_generate_random_request_new(client->allocator);
    if (request_structure == NULL) {
        return AWS_OP_ERR;
    }

    request_structure->number_of_bytes = number_of_bytes;

    request_structure->recipient = aws_recipient_new(client->allocator);
    if (request_structure->recipient == NULL) {
        goto err_clean;
    }
    rc = aws_attestation_request(
        client->allocator, client->keypair, &request_structure->recipient->attestation_document);
    if (rc != AWS_OP_SUCCESS) {
        goto err_clean;
    }
    request_structure->recipient->key_encryption_algorithm = AWS_KEA_RSAES_OAEP_SHA_256;

    request = aws_kms_generate_random_request_to_json(request_structure);
    if (request == NULL) {
        goto err_clean;
    }

    rc = s_aws_nitro_enclaves_kms_client_call_blocking(client, kms_target_generate_random, request, &response);
    if (rc != 200) {
        fprintf(stderr, "Got non-200 answer from KMS: %d\n", rc);
        goto err_clean;
    }

    response_structure = aws_kms_generate_random_response_from_json(client->allocator, response);
    if (response_structure == NULL) {
        fprintf(stderr, "Could not read response from KMS: %d\n", rc);
        goto err_clean;
    }

    rc = s_decrypt_ciphertext_for_recipient(
        client->allocator, &response_structure->ciphertext_for_recipient, client->keypair, plaintext);

    aws_kms_generate_random_request_destroy(request_structure);
    aws_kms_generate_random_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);

    return rc;
err_clean:
    aws_kms_generate_random_request_destroy(request_structure);
    aws_kms_generate_random_response_destroy(response_structure);
    aws_string_destroy(request);
    aws_string_destroy(response);
    return AWS_OP_ERR;
}
