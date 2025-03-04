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
        .aws_region = "ap-southeast-1",
        .proxy_port = 8000,
        .aws_access_key_id = "ASIA5WLTTLBC62IJU74P",
        .aws_secret_access_key = "aWInohuwGG4ol4L338+fUjOTm4GR+QptMDyj+RBI",
        .aws_session_token =
            "IQoJb3JpZ2luX2VjELT//////////wEaDmFwLXNvdXRoZWFzdC0xIkcwRQIhAOSO3luvrywt/"
            "L3I0OQjwVN1Jlcha+LUIFnWXebGNivyAiBTQpMYiSrxxaJF2CL7ips5VrXYGG/1s15p4xvTVRJzNyrTBQjt//////////"
            "8BEAAaDDk0MTM3NzE0ODk5NyIMF4lgQxfuVple8PmfKqcFXnvtE+hw/Fi2WA1VuWMNGYHyTBFS+rI9kH/"
            "TdJxfuBbZ8sEihmP6jCmMFKbx7yKEbX30t6V1oDWquGGjE8PzZAn04BjZwLnsa+"
            "D83scQOBYeOnoUIldocu5HOByyPDgOjPP1gF6RGyprx0qmzBi9dlurfCOo+fNGgZcGBfSj5/"
            "gAcIVEhKyLOPyFUqo7IxvgTo8pOipH9xm9hXVul4QtvkNiePAXzhA63k8fkH8cxDbLNQ4eocYNyjTK7NVbzS7brzL5wWqwgMDDe/"
            "xQ6iyMx9LJLMBMAgsS3cH5frEcX/"
            "oj8fMNUJkgj5IiOn9CCTAjlnJIDLJkdQQgOYhEVSwZVzz9T6TpElo4dzvfuSzsprGya1FF3uQGrdSMW/wtBiJVFhw/"
            "ijdu65OIfWcIipr9fMVHbeBGwySk+P3DdDa3GqCZ2zAzT6EfkZLPTkEGqwf37Rk5vEw2tPCNT7MfXID8jqZI5+"
            "xMFFB8PKhnuOmCpprr7JV9rZiANl86GtBd/zuiiDtDPNlAk9DFEDprx4jJtIWgxB3TXkPWwqD1Z/aUaMppgUkFXt5sjueAQM7Nf1/"
            "J+UdD0PeNkFPBPgXjugbVMMgUnk+K6r0qQFSY/p1whdTb7di7acpbHCwJDyClB3lkmZTvnr39E5nkE25XUBA/WN9L1YsNeQhHJ5tN/"
            "R12HFDClvaCaYUpSW9Ng6jH3XWECQ5zi4Y8uAFLT0jmr1C98N9j7lrWD4tJRwWXRM6smOJghz/"
            "KImXeRmYwFVP2iGysBjLoKauj4KAXTuV+"
            "VNoauzIJTuh2HJ7R1gTveDgtoMUypDOm37RcWQ88AtkQozdJabHb9hBRSfIsNNrbRCk6tF5Ojwnhnx7QT1smt4Kf+Ir/"
            "zzbFvq5vHWuvrgo9HVCmStze/"
            "IEaAzCh1Zu+BjqxAbfKH9ECs+"
            "AvIeggK6EYCfPoLKLXTwGOQ1pvdmrqctMxsn3Qr2WY8SHmNEKd6StMJxexE6YnjXPATObkSOOEf9ZTZPbv3QgViuJiiBTj/"
            "aWgcC84nLDscC3d0a67ajfK/pHU8qgCeH2YDDsTqBXLCNUuYpoyspteUCM9y4RksgVD/nyOqmPycUaUeDUw8t9bbI/"
            "iFX2YlJ8oD3Yr96BXP70vJu3GW87se5y94kkauWMOCA==",
        .kms_key_id = "60b8ce3a-7466-42b7-96a7-a3868f0fd1bf",
        .kms_algorithm = "SYMMETRIC_DEFAULT",
        .enable_logging = 1,
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
