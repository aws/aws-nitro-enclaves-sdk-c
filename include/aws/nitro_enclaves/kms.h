#ifndef AWS_NITRO_ENCLAVES_KMS_H
#define AWS_NITRO_ENCLAVES_KMS_H
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * @file
 * AWS Nitro Enclaves can call into AWS KMS with an Attestation Document that allows AWS KMS to
 * validate the state of an enclave at boot and restrict privileges based on the policy set on
 * the KMS CMK. More information can be found in the
 * [AWS Nitro Enclaves documentation](https://docs.aws.amazon.com/enclaves/latest/user/kms.html)
 *
 * aws_kms_decrypt_blocking(), aws_kms_generate_random_blocking() and aws_kms_generate_data_key_blocking()
 * implement the AWS KMS APIs using the enclave-specific Recipient parameters.
 */

#include <aws/nitro_enclaves/attestation.h>
#include <aws/nitro_enclaves/exports.h>
#include <aws/nitro_enclaves/rest.h>

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/linked_list.h>
#include <aws/common/string.h>
#include <aws/io/socket.h>

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

    AWS_KEA_RSAES_OAEP_SHA_256,
};

enum aws_key_spec {
    AWS_KS_UNINITIALIZED = -1,

    AWS_KS_AES_256,
    AWS_KS_AES_128,
};

struct aws_recipient {
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

struct aws_kms_encrypt_request {
    /**
     * Plaintext to be encrypted.
     *
     * Required: Yes.
     */
    struct aws_byte_buf plaintext;

    /**
     * Specifies the encryption algorithm that AWS KMS will use to encrypt the plaintext message.
     * The algorithm must be compatible with the CMK that you specify.
     *
     * Required: No.
     */
    enum aws_encryption_algorithm encryption_algorithm;

    /**
     * Specifies the encryption context that will be used to encrypt the data.
     * An encryption context is valid only for cryptographic operations with a symmetric CMK.
     * The standard asymmetric encryption algorithms that AWS KMS uses do not support
     * an encryption context.
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
     * A unique identifier for the customer master key (CMK).
     *
     * To specify a CMK, use its key ID, Amazon Resource Name (ARN),
     * alias name, or alias ARN. When using an alias name,
     * prefix it with "alias/". To specify a CMK in a different AWS account,
     * you must use the key ARN or alias ARN.
     *
     * Required: Yes.
     */
    struct aws_string *key_id;

    /**
     * Allocator used for memory management of associated resources.
     *
     * Note that this is not part of the request.
     */
    struct aws_allocator *const allocator;
};

struct aws_kms_encrypt_response {
    /**
     * The Amazon Resource Name (key ARN) of the CMK
     * that was used to encrypt the plaintext.
     *
     * Required: Yes.
     */
    struct aws_string *key_id;

    /**
     * The encrypted plaintext.
     *
     * Length Constraints: Minimum length of 1. Maximum length of 6144.
     *
     * Required: No.
     */
    struct aws_byte_buf ciphertext_blob;

    /**
     * The encryption algorithm that was used to encrypt the plaintext.
     *
     * Required: Yes.
     */
    enum aws_encryption_algorithm encryption_algorithm;

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

struct aws_nitro_enclaves_kms_client_configuration {
    /* Optional. Will default to library allocator if NULL. */
    struct aws_allocator *allocator;

    /** The name of the AWS region this client uses */
    const struct aws_string *region;

    /* Optional endpoint to use instead of the DNS endpoint. */
    const struct aws_socket_endpoint *endpoint;
    /* Optional. Specifies the domain of the given endpoint, if the endpoint is set. */
    enum aws_socket_domain domain;

    /*
     * Signing key control:
     *
     *   (1) If "credentials" is valid, use it
     *   (2) Else if "credentials_provider" is valid, query credentials from the provider and use the result
     *   (3) Else fail
     *
     */
    struct aws_credentials *credentials;
    struct aws_credentials_provider *credentials_provider;
};

struct aws_nitro_enclaves_kms_client {
    struct aws_allocator *allocator;

    struct aws_nitro_enclaves_rest_client *rest_client;

    struct aws_rsa_keypair *keypair;
};

/**
 * Creates an aws_recipient structure.
 *
 * @param[in]  allocator  The allocator used for initialization. NULL for default.
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
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
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
 * @param[in]  allocator  The allocator used for initialization. NULL for default.
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
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
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
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
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
 * Creates an aws_kms_encrypt_request structure.
 *
 * @param[in]  allocator  The allocator used for initialization. NULL for default.
 *
 * @return                A new aws_kms_encrypt_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_encrypt_request *aws_kms_encrypt_request_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Encrypt Request @ref aws_kms_encrypt_request to json.
 *
 * @note The request must contain the required @ref aws_kms_encrypt_request::plaintext parameter.
 *
 * @param[in]   req        The KMS Encrypt Request that is to be serialized.
 *
 * @return                 The serialized KMS Encrypt Request.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_encrypt_request_to_json(const struct aws_kms_encrypt_request *req);

/**
 * Deserialized a KMS Encrypt Request @ref aws_kms_encrypt_request from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
 * @param[in]   json       The serialized json KMS Encrypt Request.
 *
 * @return                 A new aws_kms_encrypt_request structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_encrypt_request *aws_kms_encrypt_request_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Encrypt Request.
 *
 * @param[in]  req  The KMS Encrypt Request.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_encrypt_request_destroy(struct aws_kms_encrypt_request *req);

/**
 * Creates an aws_kms_encrypt_response structure.
 *
 * @param[in]  allocator  The allocator used for initialization.
 *
 * @return                A new aws_kms_encrypt_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_encrypt_response *aws_kms_encrypt_response_new(struct aws_allocator *allocator);

/**
 * Serializes a KMS Encrypt Response @ref aws_kms_encrypt_response to json.
 *
 * @param[in]   res        The KMS Encrypt Response that is to be serialized.
 *
 * @return                 The serialized KMS Encrypt Response.
 */
AWS_NITRO_ENCLAVES_API
struct aws_string *aws_kms_encrypt_response_to_json(const struct aws_kms_encrypt_response *res);

/**
 * Deserialized a KMS Encrypt Response @ref aws_kms_encrypt_response from json.
 *
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
 * @param[in]   json       The serialized json KMS Encrypt Response.
 *
 * @return                 A new aws_kms_encrypt_response structure.
 */
AWS_NITRO_ENCLAVES_API
struct aws_kms_encrypt_response *aws_kms_encrypt_response_from_json(
    struct aws_allocator *allocator,
    const struct aws_string *json);

/**
 * Deallocate all internal data for a KMS Encrypt Response.
 *
 * @param[in]  res  The KMS Encrypt Response.
 */
AWS_NITRO_ENCLAVES_API
void aws_kms_encrypt_response_destroy(struct aws_kms_encrypt_response *res);

/**
 * Creates an aws_kms_generate_data_key_request structure.
 *
 * @param[in]  allocator  The allocator used for initialization. NULL for default.
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
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
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
 * @param[in]  allocator  The allocator used for initialization. NULL for default.
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
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
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
 * @param[in]  allocator  The allocator used for initialization. NULL for default.
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
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
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
 * @param[in]  allocator  The allocator used for initialization. NULL for default.
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
 * @param[in]   allocator  The allocator used for managing resource creation. NULL for default.
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

/**
 * Create a default KMS client configuration.
 * Uses the library default allocator.
 * uses explicit credentials instead of a credential provider.
 * The client shall retain ownership on the input parameters after this function returns.
 *
 * @param[in]   region              The AWS region.
 * @param[in]   endpoint            The remote endpoint.
 * @param[in]   domain              The remote domain. If the endpoint is set.
 * @param[in]   access_key_id       The AWS_ACCESS_KEY_ID.
 * @param[in]   secret_access_key   The AWS_SECRET_ACCESS_KEY.
 * @param[in]   session_token       The AWS_SESSION_TOKEN.
 *
 * @return  A valid KMS client configuration.
 */
AWS_NITRO_ENCLAVES_API
struct aws_nitro_enclaves_kms_client_configuration *aws_nitro_enclaves_kms_client_config_default(
    struct aws_string *region,
    struct aws_socket_endpoint *endpoint,
    enum aws_socket_domain domain,
    struct aws_string *access_key_id,
    struct aws_string *secret_access_key,
    struct aws_string *session_token);

/**
 * Destroys a previously created KMS client configuration
 *
 * @param[in]   config  The KMS client configuration.
 */
AWS_NITRO_ENCLAVES_API
void aws_nitro_enclaves_kms_client_config_destroy(struct aws_nitro_enclaves_kms_client_configuration *config);

/**
 * Create a new KMS client based on the given configuration.
 *
 * @param[in]    configuration    The configuration parameters of the client.
 *
 * @return                        A new aws_nitro_enclaves_kms_client
 */
AWS_NITRO_ENCLAVES_API
struct aws_nitro_enclaves_kms_client *aws_nitro_enclaves_kms_client_new(
    struct aws_nitro_enclaves_kms_client_configuration *configuration);

/**
 * Deallocate a KMS client.
 *
 * @param[in]    client    The KMS client to deallocate.
 */
AWS_NITRO_ENCLAVES_API
void aws_nitro_enclaves_kms_client_destroy(struct aws_nitro_enclaves_kms_client *client);

/**
 * Call [AWS KMS Decrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html).
 * This function blocks and waits for the reply.
 * This function generates an Attestation Document and calls AWS KMS with enclave-specific parameters.
 * Calling it from a non-enclave environment will fail.
 *
 * @param[in]   client      The AWS KMS client to use for calling the API.
 * @param[in]   ciphertext  The ciphertext to decrypt.
 * @param[out]  plaintext   The plaintext output of the call. Should be an empty, but non-null aws_byte_buf.
 * @return                  Returns AWS_OP_SUCCESS if the call succeeds and plaintext is populated.
 */
AWS_NITRO_ENCLAVES_API
int aws_kms_decrypt_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_byte_buf *ciphertext,
    struct aws_byte_buf *plaintext /* TODO: err_reason */);

/**
 * Call [AWS KMS Encrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html).
 * This function blocks and waits for the reply.
 *
 * @param[in]   client      The AWS KMS client to use for calling the API.
 * @param[in]   key_id      The ARN or alias of AWS KMS CMK used to encrypt the plaintext.
 * @param[in]   plaintext   The plaintext to encrypt.
 * @param[out]  ciphertext_blob  The ciphertext blob output of the call. Should be an empty, but non-null aws_byte_buf.
 * @return                  Returns AWS_OP_SUCCESS if the call succeeds and ciphertext_blob is populated.
 */
AWS_NITRO_ENCLAVES_API
int aws_kms_encrypt_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    const struct aws_byte_buf *plaintext,
    struct aws_byte_buf *ciphertext_blob
    /* TODO: err_reason */);

/**
 * Call [AWS KMS GenerateDataKey API](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html).
 * This function blocks and waits for the reply.
 * This function generates an Attestation Document and calls AWS KMS with enclave-specific parameters.
 * Calling it from a non-enclave environment will fail.
 *
 * @param[in]   client       The AWS KMS client to use for calling the API.
 * @param[in]   key_id       The ARN or alias of AWS KMS CMK used to encrypt the data key.
 * @param[in]   key_spec     The spec of key to generate: an AES128 or an AES256 key.
 * @param[out]  plaintext    The plaintext output of the call. Should be an empty, but non-null aws_byte_buf.
 * @param[out]  ciphertext_blob The ciphertext blob output of the call. Should be an empty, but non-null aws_byte_buf.
 * @return                   Returns AWS_OP_SUCCESS if the call succeeds and plaintext and ciphertext_blob are populated.
 */
AWS_NITRO_ENCLAVES_API
int aws_kms_generate_data_key_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    enum aws_key_spec key_spec,
    struct aws_byte_buf *plaintext,
    struct aws_byte_buf *ciphertext_blob
    /* TODO: err_reason */);

/**
 * Call [AWS KMS GenerateRandom API](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateRandom.html).
 * This function blocks and waits for the reply.
 * This function generates an Attestation Document and calls AWS KMS with enclave-specific parameters.
 * Calling it from a non-enclave environment will fail.
 *
 * @param[in]   client          The AWS KMS client to use for calling the API.
 * @param[in]   number_of_bytes The number of random bytes to generate.
 * @param[out]  plaintext       The plaintext output of the call. Should be an empty, but non-null aws_byte_buf.
 * @return                      Returns AWS_OP_SUCCESS if the call succeeds and plaintext is populated.
 */
AWS_NITRO_ENCLAVES_API
int aws_kms_generate_random_blocking(
    struct aws_nitro_enclaves_kms_client *client,
    uint32_t number_of_bytes,
    struct aws_byte_buf *plaintext /* TODO: err_reason */);

AWS_EXTERN_C_END

#endif /* AWS_NITRO_ENCLAVES_KMS_H */
