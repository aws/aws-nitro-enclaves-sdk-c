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
        .aws_access_key_id = "ASIA5WLTTLBCX46GJQF2",
        .aws_secret_access_key = "nbNTIox3QX9qdrUIqzf1b1JVAUfJOQ+O3egHqpAo",
        .aws_session_token =
            "IQoJb3JpZ2luX2VjELD//////////"
            "wEaDmFwLXNvdXRoZWFzdC0xIkYwRAIgRhqIAMtNeYrVBlIHu3fVZYJbfuiIT+yjSMac9K2S7BkCIEbWMkIheTfZzHRqT1LHkQKZ/"
            "rxBDJuJBZ6gjym1zkMkKtMFCOn//////////wEQABoMOTQxMzc3MTQ4OTk3IgxU/"
            "ipnpDHmzv2vsBcqpwVC9zpLbqTjjYc0MDrVr8g5AvhD9l1QroOacRt2zf5A50IXop1WuTDB26eK/1XV7/"
            "i98D+cLPAwFDQ4S0moBWU+uQWK5CwiEH70nBmI3RS3EzyeDPpwP3n6D+"
            "z5MkxYDLHWuttxo2JYvLAMW4uGk261IcSCua6VS8AklTC5fiFzS1GMjceUxjEMC20Egr6ulOGviLp+"
            "ysYyHp5kpJ0wWgPYRu2UvaN8nnOI2GcKRx39BkWZce4NKv50REMnmbcCMwSF7U9yiDEK7fr285PQKaSkBSngOQ4AJOQrCQTMAnrr814Omr"
            "K03xqaGlSiTdSx803jyzBUNhAEL/KXbJOJk4SCnMzRGGb93L9VbTCBVGgTG3eJPAH6xsCs6sK18LNp9IbuPT+baAv0oCMD6NkKcZY/"
            "RPbxQebZMwQ17MUsyz3TrY4xytgF3g/vZUp4jdVMYXpt0BpiS/fgH02xN+/1ZAFA0+AOTG7rf/+PfeEC+OWxvRujTWo7mmAz/"
            "TQTOfh29R799wx3EAGC8ObGZvdMQF2uyKyjZ5JsJHW/qr/PYP+C0+qlaHBgcaNfjfWJ8Ob9ibVtyAf/"
            "8L8i8LfOe48VjKQnGZGFcl13IGWYebkMPreLTGdDsBISdjnX63CPYtcn+KcSsyEXpc7IY4F1zlHT7Q2zEIr+xfoNAuEXLR8xvuLU7/"
            "sCt4Mog0vJZXanxwSeSbf44Y8og1hukyIUKeba3oWGB7c1slrF2gQkA6kRpq2eciRUqw069Y1QcyrKNyIH5/"
            "8l7GXNtX4Z6QtxV6+xLeJDi+uSnPKyoddpKunG3HwZSH2f8UMiHHF+EAtPMug99s5USgU3BMJOrV203o/"
            "T3GgZ+j6KKa+AvNaNMxwQXnio9+uHJrUZ0onFNAK2J3LkIasV20aoLD6tMIHhmr4GOrIBRQZlMzhKr7yvUo/"
            "HSLvjlE8FYLzZzJZRwizoOafe4KHK0dxofxZzCyHHNqhPY+MNLvafF2zhJ4gBcjas4w36S5o8awa3Cn/"
            "UStL5uPcpce3YfrqUuYxjvUrAI5qron6pXmOndkWWD8OijpsDEGu8B+Yr6K0QpUnuXQ0KoKN0XQM95YLZX7523eam/"
            "9+V8pysXJbZf0HZsffLI91T3AOM5XFMkQp+ynSF8ao92FkLVuX+4A==",
        .key_id = "60b8ce3a-7466-42b7-96a7-a3868f0fd1bf",
        .encryption_algorithm = "SYMMETRIC_DEFAULT",
        .with_logs = 1,
    };

    kmstool_enclave_init(&params_init);

    for (int i = 0; i < 100; i++) {
        // Create a unique plaintext string for each iteration.
        uint8_t plaintext[32];
        snprintf((char *)plaintext, sizeof(plaintext), "test1234567890_%d", i);
        struct kmstool_encrypt_params params_encrypt = {
            .plaintext = plaintext, .plaintext_len = strlen((char *)plaintext)};

        uint8_t *output_enc = NULL;
        size_t output_enc_len = 0;
        // Encrypt the plaintext.
        if (kmstool_enclave_encrypt(&params_encrypt, &output_enc, &output_enc_len) != 0 || output_enc == NULL) {
            fprintf(stderr, "Encryption failed at iteration %d\n", i);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "Encryption success with data length %d\n", output_enc_len);

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
        if (memcmp(plaintext, output_dec, output_dec_len) != 0) {
            fprintf(
                stderr,
                "Mismatch at iteration %d: expected %s, got %.*s\n",
                i,
                plaintext,
                (int)output_dec_len,
                output_dec);
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
