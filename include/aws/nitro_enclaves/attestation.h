#ifndef AWS_NITRO_ENCLAVES_ATTESTATION_H
#define AWS_NITRO_ENCLAVES_ATTESTATION_H
/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/exports.h>
#include <aws/nitro_enclaves/kms.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>

AWS_EXTERN_C_BEGIN

enum aws_rsa_key_size {
    AWS_RSA_2048 = 2048,
    AWS_RSA_3072 = 3072,
    AWS_RSA_4096 = 4096,
};

/**
 * The RSA keypair.
 */
struct aws_rsa_keypair {
    /** The allocator. */
    struct aws_allocator *allocator;

    /** The opaque keyspair object. */
    void *key_impl;
};

/**
 * Generates an RSA key pair used for attestation.
 *
 * @param[in]   allocator   The allocator to use.
 * @param[in]   key_size    The RSA keypair size.
 *
 * @return                  The generated keypair.
 */
AWS_NITRO_ENCLAVES_API
struct aws_rsa_keypair *aws_attestation_rsa_keypair_new(
    struct aws_allocator *allocator,
    enum aws_rsa_key_size key_size);

/**
 * Cleanups internal structures for a previously generated RSA keypair.
 *
 * @param[in]   aws_rsa_keypair     The RSA keypair previously allocated via @aws_attestation_keypair_new.
 */
AWS_NITRO_ENCLAVES_API
void aws_attestation_rsa_keypair_destroy(struct aws_rsa_keypair *keypair);

/**
 * Generates attestation data.
 *
 * @param[in]   allocator        The allocator to use.
 * @param[in]   public_key       The public key used for attestation.
 * @param[out]  attestation_doc  The public key used for attestation.
 *
 * @return                       Returns the error code. If SUCCESS, then attestation_doc is populated.
 */
AWS_NITRO_ENCLAVES_API
int aws_attestation_request(
    struct aws_allocator *allocator,
    struct aws_rsa_keypair *keypair,
    struct aws_byte_buf *attestion_doc);

/**
 * Decrypts the provided ciphertext data using the specified private key.
 * Uses the cipher text allocator.
 *
 * @param[in]   allocator   The allocator used to initialize plaintext.
 * @param[in]   keypair     The keypair used to decrypt.
 * @param[in]   ciphertext  The ciphertext to decrypt.
 * @param[out]  plaintext   The decrypted ciphertext.
 *
 * @return                  The result of the operation. On SUCCESS, the result will be placed in plaintext.
 */
AWS_NITRO_ENCLAVES_API
int aws_attestation_rsa_decrypt(
    struct aws_allocator *allocator,
    struct aws_rsa_keypair *keypair,
    struct aws_byte_buf *ciphertext,
    struct aws_byte_buf *plaintext);

AWS_EXTERN_C_END

#endif /* AWS_NITRO_ENCLAVES_ATTESTATION_H */
