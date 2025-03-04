#include "kmstool_enclave_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char decoding_table[256];

void build_decoding_table(void) {
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)encoding_table[i]] = i;
    }
}

char *base64_encode(char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL)
        return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }
    encoded_data[output_length] = '\0';
    return encoded_data;
}

char *base64_decode(char *data, size_t input_length, size_t *output_length) {
    if (decoding_table[0] == 0)
        build_decoding_table();

    if (input_length % 4 != 0)
        return NULL;
    *output_length = input_length / 4 * 3;

    char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL)
        return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_b = decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_c = decoding_table[(unsigned char)data[i++]];
        uint32_t sextet_d = decoding_table[(unsigned char)data[i++]];

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_length)
            decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length)
            decoded_data[j++] = triple & 0xFF;
    }
    return decoded_data;
}

int main(int argc, char **argv) {
    fprintf(stderr, "params %d %p \n", argc, (void *)argv);

    /* Global static application context */
    struct kmstool_init_params params_init = {
        .region = "ap-southeast-1",
        .proxy_port = 8000,
        .aws_access_key_id = "ASIA5WLTTLBC3TQCBH4Y",
        .aws_secret_access_key = "7DMiDin6VbhvHDoM7ZiQkCHAl4ASvwzZJczgwYs9",
        .aws_session_token =
            "IQoJb3JpZ2luX2VjEJX//////////"
            "wEaDmFwLXNvdXRoZWFzdC0xIkYwRAIgCdGPSJ+zoYRbhv3bWmjYn4GyrMpwLjLRJt7ZU1H+"
            "fW8CIDiLMZ3GKdba3ZMppn87hDClD4S3TbhAG4ABCLc8OiTnKtQFCM7//////////"
            "wEQABoMOTQxMzc3MTQ4OTk3IgwfPAp+"
            "0LADvILcAL4qqAU6ztHLkHrZjDBk9nC3L7sKmHlCWqBwBt7bA4TpJeYWNYbh5tAM4D9se7KHM1SynCLImA8zzXB5e2qxL3iORra4VlXsDj"
            "mKG3RXAWTAiyWUuSjrD3PuLZ2xNdhN51zXKaFfYKgqFe//jWpcUa9cu3h6343XomAaKRdWixmgV5kA69eNFYk0/"
            "OxwO+5uMPunWQBrObevTlwnQYfTM7xkuquU7oTAD5Rop+9wBuSxzjJY7+Ihk46CqnQNlSsOcd5wXG87Lb5sO8RUtx+agvV8tB4kF+"
            "kK6cY2k9mC9vO6oL1wmUMNiGeMaOaUrcXsKCtnwNRm5KSoMEBZ/VBywa9cXn8/"
            "CPdmCnvwJHiJzqna8hUwkxxr8uUVsTDMP8kcAuy9YZvLOVU1gB1+PqcBESJSMo84YTj8SaqnnkScsGj5IWun4ZYAqp0Yh+"
            "EhEkz6KPrlrQXIoaA5FXYuXKU3dp1KXV/"
            "o2yvzMElvZFNwhO9TQVjxHRbQc4p5APEvzsI59peBZ9IT7PF+aY46OXMaz8KCJEpA8yEKudpZw8RFCVTzPE0E5GpVAt8pQAGn+"
            "57W9oOLgDNHHwp3r0RegtSP5FIbYHlor+OJS0IjjYYnbIZVEE0EQdq7qy3G6/Fw59ZQcvqQX8B/"
            "NENqTV76TIF5Y7ebGs0CzWNKKu1zQCDIDN5rqZ4ehR5FkIlqZcifqmNztzakdWfGooXeohtnmqTRM83Sqqt+EgEenD7xS5Ilq12L3x1+"
            "GIx3NzeqweF/cCoT5yWbaIbqhQ1T6y8fgxPWROrKSStGYOP/kpkcjczLblfv8TgTBcbLzpq3M8/kue6DH/A+znb/"
            "aWW11uxs730pd4+W1BPFlccZDHED1aw8eoR/OeZ4BCNz+D/"
            "FGrMgpYFHhYKLeW6OgSF7W6FyYTCR8pS+BjqyAc9pzLrJjuhRRuaLSBBNJBLT7Y+uLqGIe3qg4v6UJG+OX/"
            "2dEm7C1+o8GX9LVm4PH6h0qaAPglnqWmgC+"
            "W0EtYGBWVavZwBksSZYJvVrxxPxtZgYLKxbKoM5Gsucawn0f7AWQX4zifvRCjqYwrpOuk1v8ZoBTT6lu7pYnJ+"
            "yrNmSZxp1bwDrtS4eojWFiAsdq6CEnRIu4A3BLxPTAvpRnOyRRFU7bB2iv0dfflRJYRLBFZs=",
        .key_id = "60b8ce3a-7466-42b7-96a7-a3868f0fd1bf",
        .encryption_algorithm = "SYMMETRIC_DEFAULT",
        .with_logs = 0,
    };

    kmstool_enclave_init(&params_init);

    for (int i = 0; i < 100; i++) {
        // Create a unique plaintext string for each iteration.
        char plaintext[32];
        snprintf(plaintext, sizeof(plaintext), "test1234567890_%d", i);
        char *plaintext_b64 = base64_encode(plaintext, strlen(plaintext));
        struct kmstool_encrypt_params params_encrypt = {
            .plaintext_b64 = plaintext_b64,
        };
        char *output_enc = NULL;

        // Encrypt the plaintext.
        if (kmstool_enclave_encrypt(&params_encrypt, &output_enc) != 0 || output_enc == NULL) {
            fprintf(stderr, "Encryption failed at iteration %d\n", i);
            exit(EXIT_FAILURE);
        }

        struct kmstool_decrypt_params params_decrypt = {
            .ciphertext_b64 = output_enc,
        };

        char *output_dec_b64 = NULL;

        // Decrypt the ciphertext.
        if (kmstool_enclave_decrypt(&params_decrypt, &output_dec_b64) != 0 || output_dec_b64 == NULL) {
            fprintf(stderr, "Decryption failed at iteration %d\n", i);
            free(output_enc);
            exit(EXIT_FAILURE);
        }
        size_t output_length;
        char *output_dec = base64_decode(output_dec_b64, strlen(output_dec_b64), &output_length);
        // Validate that the decrypted output matches the original plaintext.
        fprintf(stderr, "dec output %s \n", output_dec);
        if (strcmp(plaintext, output_dec) != 0) {
            fprintf(stderr, "Mismatch at iteration %d: expected %s, got %s\n", i, plaintext, output_dec);
            free(output_enc);
            free(output_dec);
            exit(EXIT_FAILURE);
        }

        free(output_enc);
        free(output_dec);

        sleep(2);
    }
    return 0;
}
