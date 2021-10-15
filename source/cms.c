/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/nitro_enclaves/internal/cms.h>

#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/nid.h>
#include <openssl/obj.h>

/* Expected CMS content versions. These versions denote
 * the current CMS structure so it is mandatory that we
 * stick with these two versions
 */
#define ENVELOPED_DATA_VERSION (2)
#define ENVELOPED_DATA_RECIPIENT_VERSION (2)

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
int aws_cms_parse_enveloped_data(
    struct aws_byte_buf *in_ber,
    struct aws_byte_buf *cipherkey,
    struct aws_byte_buf *iv,
    struct aws_byte_buf *ciphertext) {

    AWS_PRECONDITION(aws_byte_buf_is_valid(in_ber));

    /* This function consumes BER encoded tags and gets relevant inner values
     * in accordance with the CMS General Syntax. Since we currently do not
     * have a usecase where KMS responses with multiple recipient keys, this
     * whole code assumes the RecipientInfo is a SET of MAX_SIZE = 1.
     *
     * CMS General Syntax
     * https://tools.ietf.org/html/rfc5652#section-3
     */
    CBS cms;
    CBS_init(&cms, in_ber->buffer, in_ber->len);

    /* Validate that this is PKCS#7 Enveloped Data type and version we support.
     * CMS PKCS#7 Enveloped Data
     * See https://tools.ietf.org/html/rfc5652#section-6.1
     */
    unsigned tag;
    size_t tag_size;

    CBS content_type;
    if (!CBS_get_any_ber_asn1_element(&cms, NULL, &tag, &tag_size, NULL) || /* ASN1_SEQ */
        (tag != CBS_ASN1_SEQUENCE) || !CBS_get_asn1(&cms, &content_type, CBS_ASN1_OBJECT)) {
        goto err;
    }

    if (NID_pkcs7_enveloped != OBJ_cbs2nid(&content_type)) {
        goto err;
    }

    /* Validate the version */
    CBS version;
    if (!CBS_get_any_ber_asn1_element(&cms, NULL, &tag, &tag_size, NULL) || /* ASN1_ENUM */
        !CBS_get_any_ber_asn1_element(&cms, NULL, &tag, &tag_size, NULL) || (tag != CBS_ASN1_SEQUENCE) || /* ASN1_SEQ */
        !CBS_get_asn1(&cms, &version, CBS_ASN1_INTEGER)) {
        goto err;
    }
    uint8_t env_ver = 0;
    if (!CBS_get_u8(&version, &env_ver) || env_ver != ENVELOPED_DATA_VERSION) {
        goto err;
    }

    /* CMS PKCS#7 Enveloped Data
     * See https://tools.ietf.org/html/rfc5652#section-6.1
     */
    CBS enveloped_data;
    if (!CBS_get_any_ber_asn1_element(&cms, &enveloped_data, &tag, &tag_size, NULL) || tag != CBS_ASN1_SET) {
        goto err;
    }

    /* Originator Info. Optional, but if present, consume it.
     * We currently have no interest in its contents.
     */
    int has_originator;
    CBS originator_info;
    if (!CBS_get_optional_asn1(&enveloped_data, &originator_info, &has_originator, CBS_ASN1_SEQUENCE)) {
        goto err;
    }
    (void)has_originator;

    /* Recipient Info. Type: KeyTransRecipientInfo
     * See https://tools.ietf.org/html/rfc5652#section-6.2.1
     */
    CBS recipient_infos, recipient_info_data;
    uint64_t recipient_ver;
    if (!CBS_get_asn1(&enveloped_data, &recipient_infos, CBS_ASN1_SET) ||
        !CBS_get_asn1(&recipient_infos, &recipient_info_data, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1_uint64(&recipient_info_data, &recipient_ver)) {
        goto err;
    }
    if (recipient_ver != ENVELOPED_DATA_RECIPIENT_VERSION) {
        /* Only subjectKeyIdentifier is supported */
        goto err;
    }

    CBS recipient_encrypted_key;
    if (!CBS_get_any_asn1_element(&recipient_info_data, NULL, NULL, NULL) || /* RID */
        !CBS_get_asn1(&recipient_info_data, NULL, CBS_ASN1_SEQUENCE) || /* Asymmetric ALGO. RSA-OAEP in this case. */
        !CBS_get_asn1(&recipient_info_data, &recipient_encrypted_key, CBS_ASN1_OCTETSTRING)) {
        goto err;
    }
    const uint8_t *symmetric_key = CBS_data(&recipient_encrypted_key);
    size_t symmetric_key_len = CBS_len(&recipient_encrypted_key);

    /* Construct the encrypted symmetric key output buffer. */
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(symmetric_key, symmetric_key_len);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(cipherkey, aws_nitro_enclaves_get_allocator(), cursor)) {
        goto err;
    }

    /* EncryptedContentInfo
     * See https://tools.ietf.org/html/rfc5652#section-6.1
     */
    CBS encrypted_content_type;
    if (!CBS_get_any_ber_asn1_element(&cms, NULL, &tag, &tag_size, NULL) || (tag != CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&cms, &encrypted_content_type, CBS_ASN1_OBJECT)) {
        goto err;
    }

    /* Validate that this is PKCS#7 Data type */
    if (NID_pkcs7_data != OBJ_cbs2nid(&encrypted_content_type)) {
        goto err;
    }

    /* Fetch the IV.
     * See https://tools.ietf.org/html/rfc5652#section-6.3
     */
    CBS content_encryption_algo, algo, iv_string;
    if (!CBS_get_any_ber_asn1_element(&cms, &content_encryption_algo, &tag, &tag_size, NULL) ||
        tag != CBS_ASN1_SEQUENCE || !CBS_skip(&content_encryption_algo, tag_size) ||
        !CBS_get_asn1(&content_encryption_algo, &algo, CBS_ASN1_OBJECT) ||
        !CBS_get_asn1(&content_encryption_algo, &iv_string, CBS_ASN1_OCTETSTRING)) {
        goto err;
    }

    /* Validate that we have AES256-CBC in the Content */
    if (NID_aes_256_cbc != OBJ_cbs2nid(&algo)) {
        goto err;
    }

    const uint8_t *iv_data = CBS_data(&iv_string);
    size_t iv_data_len = CBS_len(&iv_string);

    cursor = aws_byte_cursor_from_array(iv_data, iv_data_len);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(iv, aws_nitro_enclaves_get_allocator(), cursor)) {
        goto err;
    }

    /* Fetch the encrypted content. This can be optional, but in our usecase it is
     * received as a scattered OCTETSTRING. Concatenate all of them.
     */
    if (!CBS_get_any_ber_asn1_element(&cms, NULL, &tag, &tag_size, NULL)) { /* ASN1_ENUM */
        goto err;
    }

    CBB encrypted_content;
    /* Grow as much as needed. Do not limit KMS encrypted content size from here. */
    if (!CBB_init(&encrypted_content, 0)) {
        goto err;
    }

    /* Consume all the entries in the scattered list */
    CBS wrapped_encrypted_content;
    while (CBS_get_any_ber_asn1_element(&cms, &wrapped_encrypted_content, &tag, &tag_size, NULL) == 1 &&
           tag == CBS_ASN1_OCTETSTRING) {
        CBS encrypted_content_part;
        if (!CBS_get_asn1(&wrapped_encrypted_content, &encrypted_content_part, CBS_ASN1_OCTETSTRING) ||
            !CBB_add_bytes(&encrypted_content, CBS_data(&encrypted_content_part), CBS_len(&encrypted_content_part))) {

            CBB_cleanup(&encrypted_content);
            goto err;
        }
    }

    /* Guaranteed to have at least one OCTETSTRING, so we should always have a valid CBB here */
    const uint8_t *cipher_content = CBB_data(&encrypted_content);
    size_t cipher_content_len = CBB_len(&encrypted_content);

    cursor = aws_byte_cursor_from_array(cipher_content, cipher_content_len);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(ciphertext, aws_nitro_enclaves_get_allocator(), cursor)) {
        CBB_cleanup(&encrypted_content);
        goto err;
    }

    CBB_cleanup(&encrypted_content);

    return AWS_OP_SUCCESS;

err:
    if (aws_byte_buf_is_valid(cipherkey)) {
        aws_byte_buf_clean_up_secure(cipherkey);
    }
    if (aws_byte_buf_is_valid(iv)) {
        aws_byte_buf_clean_up_secure(iv);
    }
    if (aws_byte_buf_is_valid(ciphertext)) {
        aws_byte_buf_clean_up_secure(ciphertext);
    }

    return AWS_OP_ERR;
}

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
int aws_cms_cipher_decrypt(
    struct aws_byte_buf *ciphertext,
    struct aws_byte_buf *key,
    struct aws_byte_buf *iv,
    struct aws_byte_buf *plaintext) {

    AWS_PRECONDITION(aws_byte_buf_is_valid(ciphertext));
    AWS_PRECONDITION(aws_byte_buf_is_valid(key));
    AWS_PRECONDITION(aws_byte_buf_is_valid(iv));

    if (key->len != EVP_CIPHER_key_length(EVP_aes_256_cbc())) {
        return AWS_OP_ERR;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return AWS_OP_ERR;
    }

    /* Setup the decryption context */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key->buffer, iv->buffer)) {
        EVP_CIPHER_CTX_free(ctx);
        return AWS_OP_ERR;
    }

    /* Output: ciphertext_len + the block length minus one */
    int ulen, flen;
    uint8_t out_text[ciphertext->len + EVP_CIPHER_CTX_block_size(ctx)];
    if (!EVP_DecryptUpdate(ctx, out_text, &ulen, ciphertext->buffer, ciphertext->len) ||
        !EVP_DecryptFinal_ex(ctx, &out_text[ulen], &flen)) {
        EVP_CIPHER_CTX_free(ctx);
        return AWS_OP_ERR;
    }

    /* Construct the plaintext output buffer. */
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(out_text, ulen + flen);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(plaintext, aws_nitro_enclaves_get_allocator(), cursor)) {
        EVP_CIPHER_CTX_free(ctx);
        return AWS_OP_ERR;
    }

    EVP_CIPHER_CTX_free(ctx);

    return AWS_OP_SUCCESS;
}
