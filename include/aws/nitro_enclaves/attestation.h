#ifndef AWS_NITRO_ENCLAVES_ATTESTATION_H
#define AWS_NITRO_ENCLAVES_ATTESTATION_H
/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/exports.h>
#include <aws/nitro_enclaves/kms.h>

AWS_EXTERN_C_BEGIN

enum aws_rsa_key_size {
    AWS_RSA_2048,
    AWS_RSA_3084,
    AWS_RSA_4096,
};

struct aws_rsa_keypair {
    struct aws_byte_buf *public_key;
    struct aws_byte_buf *private_key;
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
struct aws_rsa_keypair * aws_attestation_rsa_keypair_new(struct aws_allocator *allocator, enum aws_rsa_key_size key_size);

/**
 * Cleanups internal structures for a previously generated RSA keypair.
 *
 * @param[in]   allocator           The allocator to use.
 * @param[in]   aws_rsa_keypair     The RSA keypair previously allocated via @aws_attestation_keypair_new.
 */
AWS_NITRO_ENCLAVES_API
void aws_attestation_rsa_keypair_destroy(struct aws_allocator *allocator, struct aws_rsa_keypair *keypair);

/**
 * Generates attestation data.
 *
 * @param[in]   allocator   The allocator to use.
 * @param[in]   public_key  The public key used for attestation.
 *
 * @return                  The attestation document as a newly allocated byte buffer.
 */
AWS_NITRO_ENCLAVES_API
struct aws_byte_buf * aws_attestation_request(struct aws_allocator *allocator, struct aws_byte_buf *public_key);

/**
 * Decrypts the provided ciphertext data using the specified private key.
 *
 * @param[in]   allocator   The allocator to use.
 * @param[in]   ciphertext  The ciphertext to decrypt.
 * @param[in]   private_key The private key to decrypt with.
 * 
 * @return                  The decrypted data as newly allocated byte buffer.
 */
AWS_NITRO_ENCLAVES_API
struct aws_byte_buf *aws_attestation_rsa_decrypt(struct aws_allocator *allocator, struct aws_byte_buf *ciphertext, struct aws_byte_buf *private_key);

AWS_EXTERN_C_END

#endif /* AWS_NITRO_ENCLAVES_ATTESTATION_H */
