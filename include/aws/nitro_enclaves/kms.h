#ifndef AWS_NITRO_ENCLAVES_KMS_H
#define AWS_NITRO_ENCLAVES_KMS_H
/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/exports.h>

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/linked_list.h>
#include <aws/common/string.h>

AWS_EXTERN_C_BEGIN

/**
 * Specifies the encryption algorithm that will be used to decrypt the ciphertext.
 */
enum aws_encryption_algorithm {
    /* No encryption algorithm is specified. */
    AWS_EA_UNINITIALIZED = -1,

    /* SYMMETRIC_DEFAULT algorithm. */
    AWS_EA_SYMMETRIC_DEFAULT,
    /* RSAES_OAEP_SHA_1 algorithm. */
    AWS_EA_RSAES_OAEP_SHA_1,
    /* RSAES_OAEP_SHA_256 algorithm. */
    AWS_EA_RSAES_OAEP_SHA_256,
};

enum aws_key_encryption_algorithm {
    AWS_KEA_UNINITIALIZED = -1,

    AWS_KEA_RSAES_PKCS1_V1_5,
    AWS_KEA_RSAES_OAEP_SHA_1,
    AWS_KEA_RSAES_OAEP_SHA_256,
};

enum aws_key_spec {
    AWS_KS_UNINITIALIZED = -1,

    AWS_KS_AES_256,
    AWS_KS_AES_128,
};

struct aws_recipient {
    struct aws_byte_buf public_key;

    enum aws_key_encryption_algorithm key_encryption_algorithm;

    struct aws_byte_buf attestation_document;

    struct aws_allocator *const allocator;
};

struct aws_kms_decrypt_request {
    /**
     * Ciphertext to be decrypted. The blob includes metadata.
     *
     * Required: Yes.
     */
    struct aws_byte_buf ciphertext_blob;

    /**
     * Specifies the encryption algorithm that will be used to decrypt the ciphertext.
     * Specify the same algorithm that was used to encrypt the data.
     * If you specify a different algorithm, the Decrypt operation fails.
     *
     * Required: No.
     */
    enum aws_encryption_algorithm encryption_algorithm;

    /**
     * Specifies the encryption context to use when decrypting the data. An encryption
     * context is valid only for cryptographic operations with a symmetric CMK.
     * The standard asymmetric encryption algorithms that AWS KMS uses do not
     * support an encryption context.
     *
     * An encryption context is a collection of non-secret key-value pairs that
     * represents additional authenticated data. When you use an encryption context
     * to encrypt data, you must specify the same (an exact case-sensitive match)
     * encryption context to decrypt the data. An encryption context is optional
     * when encrypting with a symmetric CMK, but it is highly recommended.
     *
     * Required: No.
     */
    struct aws_hash_table encryption_context;

    /**
     * A list of grant tokens.
     *
     * For more information, see
     * <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token">Grant Tokens</a>
     * in the AWS Key Management Service Developer Guide.
     *
     * Required: No.
     */
    struct aws_array_list grant_tokens;

    /**
     * Specifies the customer master key (CMK) that AWS KMS will use to decrypt
     * the ciphertext. Enter a key ID of the CMK that was used to encrypt the ciphertext.
     *
     * If you specify a KeyId value, the Decrypt operation succeeds only if the specified
     * CMK was used to encrypt the ciphertext.
     *
     * This parameter is required only when the ciphertext was encrypted under an asymmetric CMK.
     * Otherwise, AWS KMS uses the metadata that it adds to the ciphertext blob to determine
     * which CMK was used to encrypt the ciphertext. However, you can use this parameter to
     * ensure that a particular CMK (of any kind) is used to decrypt the ciphertext.
     *
     * Required: No.
     */
    struct aws_string *key_id;

    /**
     * Recipient field.
     *
     * Required: No.
     */
    struct aws_recipient *recipient;

    /**
     * Allocator used for memory management of associated resources.
     *
     * Note that this is not part of the request.
     */
    struct aws_allocator *const allocator;
};

struct aws_kms_decrypt_response {
    /**
     * ARN of the key used to perform the decryption. This value is returned if no errors are
     * encountered during the operation.
     *
     * Required: Yes.
     */
    struct aws_string *key_id;

    /**
     * Decrypted plaintext data. This value may not be returned if the customer master key is
     * not available or if you didn't have permission to use it.
     *
     * Required: No.
     */
    struct aws_byte_buf plaintext;

    /**
     * The encryption algorithm that was used to decrypt the ciphertext.
     *
     * Required: No.
     */
    enum aws_encryption_algorithm encryption_algorithm;

    /**
     * Ciphertext for recipient field.
     *
     * Required: No.
     */
    struct aws_byte_buf ciphertext_for_recipient;

    /**
     * Allocator used for memory management of associated resources.
     *
     * Note that this is not part of the response.
     */
    struct aws_allocator *const allocator;
};

struct aws_kms_generate_data_key_request {
    /**
     * Identifies the symmetric CMK that encrypts the data key.
     *
     * Required: Yes.
     */
    struct aws_string *key_id;

    /**
     * Specifies the encryption context that will be used when encrypting the data key.
     *
     * An encryption context is a collection of non-secret key-value pairs that
     * represents additional authenticated data. When you use an encryption context
     * to encrypt data, you must specify the same (an exact case-sensitive match)
     * encryption context to decrypt the data. An encryption context is optional
     * when encrypting with a symmetric CMK, but it is highly recommended.
     *
     * Required: No.
     */
    struct aws_hash_table encryption_context;

    /**
     * Specifies the length of the data key in bytes. For example, use the value 64 to
     * generate a 512-bit data key (64 bytes is 512 bits). For 128-bit (16-byte) and
     * 256-bit (32-byte) data keys, use the KeySpec parameter.
     *
     * You must specify either the KeySpec or the NumberOfBytes parameter (but not both)
     * in every GenerateDataKey request.
     *
     * Required: No.
     */
    uint32_t number_of_bytes;

    /**
     * Specifies the length of the data key. Use AES_128 to generate a 128-bit symmetric key,
     * or AES_256 to generate a 256-bit symmetric key.
     *
     * You must specify either the KeySpec or the NumberOfBytes parameter (but not both)
     * in every GenerateDataKey request.
     *
     * Required: No.
     */
    enum aws_key_spec key_spec;

    /**
     * A list of grant tokens.
     *
     * For more information, see
     * <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token">Grant Tokens</a>
     * in the AWS Key Management Service Developer Guide.
     *
     * Required: No.
     */
    struct aws_array_list grant_tokens;

    /**
     * Recipient field.
     *
     * Required: No.
     */
    struct aws_recipient *recipient;

    /**
     * Allocator used for memory management of associated resources.
     *
     * Note that this is not part of the response.
     */
    struct aws_allocator *const allocator;
};

struct aws_kms_generate_data_key_response {
    /**
     * The identifier of the CMK under which the data encryption key was generated and encrypted.
     *
     * Required: Yes.
     */
    struct aws_string *key_id;

    /**
     * The encrypted data encryption key.
     *
     * Required: Yes.
     */
    struct aws_byte_buf ciphertext_blob;

    /**
     * The data encryption key. Use this data key for local encryption and decryption, then
     * remove it from memory as soon as possible.
     *
     * Required: No.
     */
    struct aws_byte_buf plaintext;

    /**
     * Ciphertext for recipient field.
     *
     * Required: No.
     */
    struct aws_byte_buf ciphertext_for_recipient;

    /**
     * Allocator used for memory management of associated resources.
     *
     * Note that this is not part of the response.
     */
    struct aws_allocator *const allocator;
};

struct aws_kms_generate_random_request {
    /**
     * The length of the byte string.
     *
     * Required: No.
     */
    uint32_t number_of_bytes;

    /**
     * Generates the random byte string in the AWS CloudHSM cluster that is associated
     * with the specified custom key store. To find the ID of a custom key store,
     * use the DescribeCustomKeyStores operation.
     *
     * Required: No.
     */
    struct aws_string *custom_key_store_id;

    /**
     * Recipient field.
     *
     * Required: No.
     */
    struct aws_recipient *recipient;

    /**
     * Allocator used for memory management of associated resources.
     *
     * Note that this is not part of the response.
     */
    struct aws_allocator *const allocator;
};

struct aws_kms_generate_random_response {
    /**
     * The random byte string.
     *
     * Required: No.
     */
    struct aws_byte_buf plaintext;

    /**
     * Ciphertext for recipient field.
     *
     * Required: No.
     */
    struct aws_byte_buf ciphertext_for_recipient;

    /**
     * Allocator used for memory management of associated resources.
     *
     * Note that this is not part of the response.
     */
    struct aws_allocator *const allocator;
};

/**
 * Creates an aws_recipient structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_recipient structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_recipient *aws_recipient_new(struct aws_allocator *allocator);

/**
 * Serializes a Recipient @ref aws_recipient to json.
 *
 * @param[in]   req        The Recipient that is to be serialized.
 *
 * @return                 The serialized Recipient.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_recipient_to_json(const struct aws_recipient *recipient);

/**
 * Deserialized a Recipient @ref aws_recipient from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation.
 * @param[in]   json       The serialized json Recipient.
 *
 * @return                 A new aws_recipient structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_recipient *aws_recipient_from_json(struct aws_allocator *allocator, const struct aws_string *json);

/**
 * Deallocate all internal data for an aws_recipient.
 *
 * @param[in]  recipient  The AWS recipient.
 */
AWS_NITRO_ENCLAVES_API
void aws_recipient_destroy(struct aws_recipient *recipient);

/**
 * Creates an aws_kms_decrypt_request structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_kms_decrypt_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_decrypt_request *aws_kms_decrypt_request_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Decrypt Request @ref aws_kms_decrypt_request to json.
 *
 * @note The request must contain the required @ref aws_kms_decrypt_request::ciphertext_blob parameter.
 *
 * @param[in]   req        The KMS Decrypt Request that is to be serialized.
 *
 * @return                 The serialized KMS Decrypt Request.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_decrypt_request_to_json(const struct aws_kms_decrypt_request *req);

/**
 * Deserialized a KMS Decrypt Request @ref aws_kms_decrypt_request from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation.
 * @param[in]   json       The serialized json KMS Decrypt Request.
 *
 * @return                 A new aws_kms_decrypt_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_decrypt_request *aws_kms_decrypt_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Decrypt Request.
 *
 * @param[in]  req  The KMS Decrypt Request.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_decrypt_request_destroy(struct aws_kms_decrypt_request *req);

/**
 * Creates an aws_kms_decrypt_response structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_kms_decrypt_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_decrypt_response *aws_kms_decrypt_response_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Decrypt Response @ref aws_kms_decrypt_response to json.
 *
 * @param[in]   res        The KMS Decrypt Response that is to be serialized.
 *
 * @return                 The serialized KMS Decrypt Response.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_decrypt_response_to_json(const struct aws_kms_decrypt_response *res);

/**
 * Deserialized a KMS Decrypt Response @ref aws_kms_decrypt_response from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation.
 * @param[in]   json       The serialized json KMS Decrypt Response.
 *
 * @return                 A new aws_kms_decrypt_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_decrypt_response *aws_kms_decrypt_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Decrypt Response.
 *
 * @param[in]  res  The KMS Decrypt Response.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_decrypt_response_destroy(struct aws_kms_decrypt_response *res);

/**
 * Creates an aws_kms_generate_data_key_request structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_kms_generate_data_key_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_data_key_request *aws_kms_generate_data_key_request_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Generate Data Key Request @ref aws_kms_generate_data_key_request to json.
 *
 * @note The request must contain the required @ref aws_kms_generate_data_key_request::key_id parameter.
 *
 * @param[in]   req        The KMS Generate Data Key Request that is to be serialized.
 *
 * @return                 The serialized KMS Generate Data Key Request.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_generate_data_key_request_to_json(const struct aws_kms_generate_data_key_request *req);

/**
 * Deserialized a KMS Generate Data Key Request @ref aws_kms_generate_data_key_request from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation.
 * @param[in]   json       The serialized json KMS Generate Data Key Request.
 *
 * @return                 A new aws_kms_generate_data_key_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_data_key_request *aws_kms_generate_data_key_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Generate Data Key Request.
 *
 * @param[in]  req  The KMS Generate Data Key Request.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_generate_data_key_request_destroy(struct aws_kms_generate_data_key_request *req);

/**
 * Creates an aws_kms_generate_data_key_response structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_kms_generate_data_key_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_data_key_response *aws_kms_generate_data_key_response_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Generate Data Key Response @ref aws_kms_generate_data_key_response to json.
 *
 * @param[in]   res        The KMS Generate Data Key Response that is to be serialized.
 *
 * @return                 The serialized KMS Generate Data Key Response.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_generate_data_key_response_to_json(const struct aws_kms_generate_data_key_response *res);

/**
 * Deserialized a KMS Generate Data Key Response @ref aws_kms_generate_data_key_response from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation.
 * @param[in]   json       The serialized json KMS Generate Data Key Response.
 *
 * @return                 A new aws_kms_generate_data_key_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_data_key_response *aws_kms_generate_data_key_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Generate Data Key Response.
 *
 * @param[in]  res  The KMS Generate Data Key Request.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_generate_data_key_response_destroy(struct aws_kms_generate_data_key_response *res);

/**
 * Creates an aws_kms_generate_random_request structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_kms_generate_random_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_random_request *aws_kms_generate_random_request_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Generate Random Request @ref aws_kms_generate_random_request to json.
 *
 * @param[in]   req       The KMS Generate Random Request that is to be serialized.
 *
 * @return                The serialized KMS Generate Random Request.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_generate_random_request_to_json(const struct aws_kms_generate_random_request *req);

/**
 * Deserialized a KMS Generate Random Request @ref aws_kms_generate_random_request from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation.
 * @param[in]   json       The serialized json KMS Generate Random Request.
 *
 * @return                 A new aws_kms_generate_random_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_random_request *aws_kms_generate_random_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Generate Random Request.
 *
 * @param[in]  req  The KMS Generate Random Request.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_generate_random_request_destroy(struct aws_kms_generate_random_request *req);

/**
 * Creates an aws_kms_generate_random_response structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_kms_generate_random_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_random_response *aws_kms_generate_random_response_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Generate Random Response @ref aws_kms_generate_random_response to json.
 *
 * @param[in]   res       The KMS Generate Random Response that is to be serialized.
 *
 * @return                The serialized KMS Generate Random Response.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_generate_random_response_to_json(const struct aws_kms_generate_random_response *res);

/**
 * Deserialized a KMS Generate Random Response @ref aws_kms_generate_random_response from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation.
 * @param[in]   json       The serialized json KMS Generate Random Response.
 *
 * @return                 A new aws_kms_generate_random_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_generate_random_response *aws_kms_generate_random_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Generate Random Response.
 *
 * @param[in]  res  The KMS Generate Random Response.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_generate_random_response_destroy(struct aws_kms_generate_random_response *res);

AWS_EXTERN_C_END

#endif /* AWS_NITRO_ENCLAVES_KMS_H */
