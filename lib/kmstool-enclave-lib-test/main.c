#include "kmstool_enclave_lib.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    /* Mark unused parameters to avoid warnings */
    (void)argc;
    (void)argv;

    /* Global static application context */
    struct kmstool_init_params params_init = {
        .region = "ap-southeast-1",
        .proxy_port = 8000,
        .aws_access_key_id = "",
        .aws_secret_access_key = "",
        .aws_session_token = "",
        .key_id = "",
        .encryption_algorithm = "SYMMETRIC_DEFAULT",
        .with_logs = 1,
    };

    kmstool_enclave_init(&params_init);

    for (int i = 0; i < 100; i++) {
        // Create a unique plaintext string for each iteration.
        uint8_t plaintext[256];
        uint8_t plaintext_check[256];

        sprintf((char *)plaintext, "test1234567890_%d", i);
        sprintf((char *)plaintext_check, "test1234567890_%d", i);

        struct kmstool_encrypt_params params_encrypt = {
            .plaintext = plaintext, .plaintext_len = strlen((char *)plaintext)};

        uint8_t *output_enc = NULL;
        size_t output_enc_len = 0;
        // Encrypt the plaintext.
        if (kmstool_enclave_encrypt(&params_encrypt, &output_enc, &output_enc_len) != 0 || output_enc == NULL) {
            fprintf(stderr, "Encryption failed at iteration %d\n", i);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "Encryption success with data length %ld\n", output_enc_len);

        struct kmstool_decrypt_params params_decrypt = {.ciphertext = output_enc, .ciphertext_len = output_enc_len};

        uint8_t *output_dec = NULL;
        size_t output_dec_len = 0;

        // Decrypt the ciphertext.
        if (kmstool_enclave_decrypt(&params_decrypt, &output_dec, &output_dec_len) != 0 || output_dec == NULL) {
            fprintf(stderr, "Decryption failed at iteration %d\n", i);
            free(output_enc);
            exit(EXIT_FAILURE);
        }

        // Validate that the decrypted output matches the original plaintext.
        if (strncmp((char *)plaintext_check, (char *)output_dec, output_dec_len) != 0) {
            fprintf(
                stderr, "Mismatch at iteration %d: expected %s, got %s\n", i, (char *)plaintext, (char *)output_dec);
            free(output_enc);
            free(output_dec);
            exit(EXIT_FAILURE);
        }

        if (strlen((char *)plaintext_check) != output_dec_len) {
            fprintf(stderr, "Mismatch len expected %zu got %zu\n", strlen((char *)plaintext), output_dec_len);
            free(output_enc);
            free(output_dec);
            exit(EXIT_FAILURE);
        }

        free(output_enc);
        free(output_dec);
        fprintf(stderr, "success with i: %d\n", i);
        sleep(2);
    }
    return 0;
}
