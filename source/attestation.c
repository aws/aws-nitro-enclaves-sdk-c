/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/attestation.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

/* Low level crypto backend interfaces */
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <nsm.h>

/* Maximum size of the attestation document */
#define NSM_MAX_ATTESTATION_DOC_SIZE (16 * 1024)

/**
 * Generates an RSA key pair used for attestation.
 *
 * @param[in]   allocator   The allocator to use.
 * @param[in]   key_size    The RSA keypair size to generate.
 *
 * @return                  The generated keypair.
 */
struct aws_rsa_keypair *aws_attestation_rsa_keypair_new(struct aws_allocator *allocator, enum aws_rsa_key_size key_size) {
    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    RSA *key = RSA_new();
    if (key == NULL) {
        return NULL;
    }

    BIGNUM *e = BN_new();
    if (e == NULL) {
        RSA_free(key);
        return NULL;
    }
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(key, key_size, e, NULL) != 1) {
        BN_free(e);
        RSA_free(key);
        return NULL;
    }

    BN_free(e);

    /* Create a keypair container and store the key streams in it */
    struct aws_byte_cursor cursor;
    struct aws_rsa_keypair *keypair = aws_mem_calloc(allocator, 1, sizeof(struct aws_rsa_keypair));
    if (keypair == NULL) {
        RSA_free(key);
        return NULL;
    }
    keypair->allocator = allocator;

    /* Private Key */
    size_t out_key_len = 0;
    uint8_t *out_key_ptr = NULL;
    if (RSA_private_key_to_bytes(&out_key_ptr, &out_key_len, key) != 1) {
        RSA_free(key);
        return NULL;
    }
    cursor = aws_byte_cursor_from_array(out_key_ptr, out_key_len);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(&keypair->private_key, allocator, cursor)) {
        OPENSSL_free(out_key_ptr);
        RSA_free(key);
        return NULL;
    }
    OPENSSL_free(out_key_ptr);

    /* Public Key */
    if (RSA_public_key_to_bytes(&out_key_ptr, &out_key_len, key) != 1) {
        RSA_free(key);
        return NULL;
    }
    cursor = aws_byte_cursor_from_array(out_key_ptr, out_key_len);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(&keypair->public_key, allocator, cursor)) {
        OPENSSL_free(out_key_ptr);
        RSA_free(key);
        return NULL;
    }

    OPENSSL_free(out_key_ptr);

    RSA_free(key);

    return keypair;
}

/**
 * Cleanups internal structures for a previously generated RSA keypair.
 *
 * @param[in]   allocator           The allocator to use.
 * @param[in]   aws_rsa_keypair     The RSA keypair previously allocated via @aws_attestation_rsa_keypair_new.
 */
void aws_attestation_rsa_keypair_destroy(struct aws_rsa_keypair *keypair) {

    AWS_PRECONDITION(aws_byte_buf_is_valid(&keypair->public_key));
    aws_byte_buf_clean_up_secure(&keypair->public_key);
    AWS_PRECONDITION(aws_byte_buf_is_valid(&keypair->private_key));
    aws_byte_buf_clean_up_secure(&keypair->private_key);
    aws_mem_release(keypair->allocator, keypair);
}

/**
 * Generates attestation data.
 *
 * @param[in]   allocator        The allocator to use.
 * @param[in]   public_key       The public key used for attestation.
 * @param[out]  attestation_doc  The public key used for attestation.
 *
 * @return                       Returns the error code. If SUCCESS, then attestation_doc is populated.
 */
int aws_attestation_request(struct aws_allocator *allocator, struct aws_rsa_keypair *keypair, struct aws_byte_buf *attestation_document) {
    AWS_PRECONDITION(aws_byte_buf_is_valid(&keypair->public_key));

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    int nsm_fd = nsm_lib_init();
    if (nsm_fd < 0) {
        return AWS_OP_ERR;
    }

    /* Get the attestation document. */
    uint8_t att_doc[NSM_MAX_ATTESTATION_DOC_SIZE];
    uint32_t att_doc_len = NSM_MAX_ATTESTATION_DOC_SIZE;
    int rc =
        nsm_get_attestation_doc(nsm_fd, NULL, 0, NULL, 0, keypair->public_key.buffer, keypair->public_key.len, att_doc, &att_doc_len);
    if (rc) {
        nsm_lib_exit(nsm_fd);
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(att_doc, att_doc_len);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(attestation_document, allocator, cursor)) {
        nsm_lib_exit(nsm_fd);
        return AWS_OP_ERR;
    }

    nsm_lib_exit(nsm_fd);

    return AWS_OP_SUCCESS;
}

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
int aws_attestation_rsa_decrypt(
    struct aws_allocator *allocator,
    struct aws_rsa_keypair *keypair,
    struct aws_byte_buf *ciphertext,
    struct aws_byte_buf *plaintext
    ) {
    AWS_PRECONDITION(aws_byte_buf_is_valid(&keypair->private_key));
    AWS_PRECONDITION(aws_byte_buf_is_valid(ciphertext));

    if (allocator == NULL) {
        allocator = aws_nitro_enclaves_get_allocator();
    }

    /* Construct local RSA private key from the bytestream */
    RSA *key = RSA_private_key_from_bytes(keypair->private_key.buffer, keypair->private_key.len);
    if (key == NULL) {
        return AWS_OP_ERR;
    }

    /* Construct an EVP PKEY container */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(key);
        return AWS_OP_ERR;
    }

    /* Take ownership over the RSA private key. */
    if (EVP_PKEY_set1_RSA(pkey, key) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(key);
        return AWS_OP_ERR;
    }

    /* Create the decryption context */
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_PKEY_free(pkey);
        return AWS_OP_ERR;
    }

    /* Initialize the decryption context. */
    if (EVP_PKEY_decrypt_init(pkey_ctx) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, EVP_sha256()) != 1) {

        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pkey);
        return AWS_OP_ERR;
    }

    /* Decrypt. RSA maximum encrypted data size is key modulus in bytes */
    size_t plain_data_len = EVP_PKEY_size(pkey);
    uint8_t plain_data[plain_data_len];

    if (EVP_PKEY_decrypt(pkey_ctx, plain_data, &plain_data_len, ciphertext->buffer, ciphertext->len) != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pkey);
        return AWS_OP_ERR;
    }

    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pkey);

    /* Construct the plain data byte buf */
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(plain_data, plain_data_len);
    if (AWS_OP_SUCCESS != aws_byte_buf_init_copy_from_cursor(plaintext, allocator, cursor)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
