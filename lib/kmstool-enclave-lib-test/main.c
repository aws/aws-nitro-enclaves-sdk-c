#include "kmstool_enclave_lib.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    /* Global static application context */
    struct kmstool_init_params params_init = {
        .region = "ap-southeast-1",
        .proxy_port = 8000,
        .aws_access_key_id = "ASIA5WLTTLBCXTRTDNY7",
        .aws_secret_access_key = "7Ehagx/BFsxsdF6JY7KqI9RNc3R7SAJoScheG5tr",
        .aws_session_token =
            "IQoJb3JpZ2luX2VjEK7//////////wEaDmFwLXNvdXRoZWFzdC0xIkgwRgIhAMeWwiXnGOMZxnVzGY5kDdUf29P97jQ5xmh1P+l/"
            "9nxFAiEA9y5bNaWl+1ZYSBmpCfgDHy0pWxA3djln3U02A33M108q0wUI5///////////"
            "ARAAGgw5NDEzNzcxNDg5OTciDDtn1KkrJghiOUBjfCqnBVXpsN6GjtSvkj/"
            "dkfelufTIolBXJGz1b3+LvQ7WcbP42L3D5td86pSDEfRa1o7mokNunIKVEcIeZwuiwtEfU3D2Jw9WnzV/"
            "oUwKdE+LO1Wh+w3UcDm8AU3vlXCld9dw9BUROqc7lDsLznZtV+KW8+5lx6EisW4BW9AfGbeOHHcqxqQs38JKCaf9JikSc4jugS7+"
            "3rukzddDHEewsa1oDeOql/"
            "KWlt0MNvF36iK1HRZsYVTo6MXfDn4YPz2gwEBgcnaFouU4F8ILuFXmiGhaUM79dBnPXTPSGt1muNwVho47Syu0spq53lqU+"
            "MF0tioVCJTLmTo5l6p3TbUWz9X6dTHIRG+OdFO+NK1fbwabt5j9fUZHsLXxRS7PvbFQEKyDpXH+"
            "o36JfoGZ5ivT4tS1lzvKqu1WYvjJhWu0+Dnc1obcJAHzuclWIqUa9XRYrsnDeCTD/"
            "oqn94NePdemEtQhC6fpKQ710uPV2kq3+1980UZ1xBUEHa7LhmPXFIhznt+"
            "ffmSG1FrHDD7m6xLxlH8hs4rjjMm3Fc9H6tE52yMBxFKqFWcFOOCWrEqLQXSd15QyVJugBuJQb2nUaWFDfhBgiXE03tZriBmq2ukuCRiT6"
            "25Fcut47gA97e8BLdLPoNPTDL/MUmI3oMNpY8c+Q4bwaW4H6AJsYRkTJDLtEseYpsH3O6dd81Gn/"
            "iTRuEcWspw+9gS1Tr6H8gwNKY6hsN9kYR0evs9wYIA87b/"
            "uRpHG+1VeJEW9e4IIfgIxUqtLTfWmysQPOIEOatW4Ajc0WGipgAjEYRaxPZ64FVwmTjMok1kFLQYonxUi0xjYp5RtF/6Wy7xRsC8bL/"
            "PX4I0yqdKoxdHr747QQpruhKJZx1vNAggk7qn6k8EoTc7uFNSgkdnXsYqakrgDsT8wzaeavgY6sAEbU5FB3T+FKlvr/"
            "zVSdsmZvO4A4pxBglW8kQ06RWJRJBDVnTLBJADcjFyEYZGdz283BwTt4/vEzUjbHQxk35AkvwNXuiw58/"
            "Bzig8FQHOihC75KePumSWHmn1kFCWweRumYvFHmuJ5/"
            "QO7JOmhaNo0mVZZk7As52YRG8cLyHfyfF0P3VaBbXaIzyb+9wmsvcTu1j0ta5cDqYNETU8+iQ3QWXL4x2CWRjS2OJ6Seh6umw==",
        .key_id = "60b8ce3a-7466-42b7-96a7-a3868f0fd1bf",
        .encryption_algorithm = "SYMMETRIC_DEFAULT",
        .with_logs = 0,
    };

    kmstool_enclave_init(&params_init);

    for (int i = 0; i < 100; i++) {
        // Create a unique plaintext string for each iteration.
        char plaintext[32];
        snprintf(plaintext, sizeof(plaintext), "test1234567890_%d", i);
        struct kmstool_encrypt_params params_encrypt = {
            .plaintext_b64 = plaintext,
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

        char *output_dec = NULL;

        // Decrypt the ciphertext.
        if (kmstool_enclave_decrypt(&params_decrypt, &output_dec) != 0 || output_dec == NULL) {
            fprintf(stderr, "Decryption failed at iteration %d\n", i);
            free(output_enc);
            exit(EXIT_FAILURE);
        }
        // Validate that the decrypted output matches the original plaintext.
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
