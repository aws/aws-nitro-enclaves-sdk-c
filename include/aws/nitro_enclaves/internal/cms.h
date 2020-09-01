#ifndef AWS_NITRO_ENCLAVES_INTERNAL_CMS_H
#define AWS_NITRO_ENCLAVES_INTERNAL_CMS_H
/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/exports.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>

AWS_EXTERN_C_BEGIN

/**
 * A highly specialized function that parses a BER-encoded CMS Enveloped Data
 * content stream and outputs specific entries required for decrypting content
 * in the KMS client side.
 *
 * NOTE: Always assumes RecipentInfo to have RSA-OAEP with SHA256 for envelope
 * encryption and AES-256-CBC for content encryption.
 *
 * @param[in]   in_ber      The serialized CMS content.
 * @param[out]  cipherkey   The symmetric key received in the RecipientInfo structure.
 *                          Caller has to decrypt this with the asymmetric public key.
 * @param[out]  iv          The IV received in the EncryptedContent structure.
 * @param[out]  ciphertext  The actual ciphertext present in the Encrypted Content.
 *                          Caller has to decrypt this with the symmetric @cipherkey and @iv.
 *
 * @return                  Returns the error code. If SUCCESS, the above parameters are valid.
 */
AWS_NITRO_ENCLAVES_API
int aws_cms_parse_enveloped_data(
    struct aws_byte_buf *in_ber,
    struct aws_byte_buf *cipherkey,
    struct aws_byte_buf *iv,
    struct aws_byte_buf *ciphertext);

/**
 * Symmetric one-shot decryption function.
 *
 * NOTE: Implicitly assumes AES-256-CBC cipher.
 *
 * @param[in]   The ciphertext to decrypt.
 * @param[in]   The symmetric key.
 * @param[in]   The IV used initially for encryption.
 * @param[out]  The plaintext.
 *
 * @return      Returns the error code. If SUCCESS, the output plaintext is valid.
 */
AWS_NITRO_ENCLAVES_API
int aws_cms_cipher_decrypt(
    struct aws_byte_buf *ciphertext,
    struct aws_byte_buf *key,
    struct aws_byte_buf *iv,
    struct aws_byte_buf *plaintext);

AWS_EXTERN_C_END

#endif /* AWS_NITRO_ENCLAVES_INTERNAL_CMS_H */
