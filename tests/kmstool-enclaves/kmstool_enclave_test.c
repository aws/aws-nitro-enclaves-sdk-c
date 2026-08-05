/**
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/*
 * Regression test for the SetClient use-after-free.
 *
 * handle_connection() and s_read_region() are static in the kmstool-enclave
 * binary and are not part of the library, so this test includes the binary's
 * translation unit directly, renaming its main() out of the way. The KMS entry
 * points it calls are redirected to stubs with -Wl,--wrap, so no vsock proxy,
 * NSM device or KMS endpoint is required.
 *
 * The stub deliberately keeps the destroyed client's memory and poisons it in
 * place rather than freeing it. That makes the reuse observable in an ordinary
 * build: the vendored aws-c-common cannot enable AddressSanitizer here, so a
 * test that relied on ASan would silently pass.
 */

#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/testing/aws_test_harness.h>

#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

/* Pull in the code under test; its main() is not used. */
#define main s_kmstool_enclave_main_unused
#include "bin/kmstool-enclave/main.c"
#undef main

#define CLIENT_POISON 0xDE

static void *s_destroyed_client;
static bool s_used_after_free;

struct aws_nitro_enclaves_kms_client *__wrap_aws_nitro_enclaves_kms_client_new(
    struct aws_nitro_enclaves_kms_client_configuration *configuration);
void __wrap_aws_nitro_enclaves_kms_client_destroy(struct aws_nitro_enclaves_kms_client *client);
int __wrap_aws_kms_decrypt_blocking_with_context(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    const struct aws_string *encryption_algorithm,
    const struct aws_byte_buf *ciphertext,
    const struct aws_string *encryption_context,
    struct aws_byte_buf *plaintext);

struct aws_nitro_enclaves_kms_client *__wrap_aws_nitro_enclaves_kms_client_new(
    struct aws_nitro_enclaves_kms_client_configuration *configuration) {
    struct aws_nitro_enclaves_kms_client *client = malloc(sizeof(*client));
    if (client == NULL) {
        return NULL;
    }
    client->allocator = configuration != NULL && configuration->allocator != NULL ? configuration->allocator
                                                                                  : aws_nitro_enclaves_get_allocator();
    client->rest_client = NULL;
    client->keypair = NULL;
    return client;
}

void __wrap_aws_nitro_enclaves_kms_client_destroy(struct aws_nitro_enclaves_kms_client *client) {
    if (client == NULL) {
        return;
    }
    /* Poison but keep the allocation, so a later read is detectable rather than
     * depending on what the allocator does with a freed block. */
    memset(client, CLIENT_POISON, sizeof(*client));
    s_destroyed_client = client;
}

int __wrap_aws_kms_decrypt_blocking_with_context(
    struct aws_nitro_enclaves_kms_client *client,
    const struct aws_string *key_id,
    const struct aws_string *encryption_algorithm,
    const struct aws_byte_buf *ciphertext,
    const struct aws_string *encryption_context,
    struct aws_byte_buf *plaintext) {
    (void)key_id;
    (void)encryption_algorithm;
    (void)ciphertext;
    (void)encryption_context;

    if (client != NULL && (void *)client == s_destroyed_client && *(const unsigned char *)client == CLIENT_POISON) {
        s_used_after_free = true;
    }

    AWS_ZERO_STRUCT(*plaintext);
    return AWS_OP_ERR;
}

/* SetClient, then a SetClient whose AwsRegion is a number so s_read_region
 * fails, then a Decrypt. Before the fix the failed SetClient had already
 * destroyed the client without clearing the pointer, so the Decrypt reused it. */
static const char *const s_messages[] = {
    "{\"Operation\":\"SetClient\",\"AwsAccessKeyId\":\"AKID\","
    "\"AwsSecretAccessKey\":\"SECRET\",\"AwsSessionToken\":\"TOKEN\"}",
    "{\"Operation\":\"SetClient\",\"AwsAccessKeyId\":\"AKID\","
    "\"AwsSecretAccessKey\":\"SECRET\",\"AwsSessionToken\":\"TOKEN\",\"AwsRegion\":5}",
    "{\"Operation\":\"Decrypt\",\"Ciphertext\":\"Zm9v\"}",
};

static int s_peer_fd;

static void *s_peer_thread(void *arg) {
    (void)arg;

    for (size_t i = 0; i < AWS_ARRAY_SIZE(s_messages); ++i) {
        /* Messages are NUL-delimited on the wire. */
        if (write(s_peer_fd, s_messages[i], strlen(s_messages[i]) + 1) < 0) {
            break;
        }
        usleep(150000);
    }

    /* Close our side entirely: the enclave loop then sees end of file on its
     * next read and returns, rather than waiting out its receive timeout.
     * Replies still queued are discarded with the socket, which is fine here -
     * the test asserts on the client pointer, not on the replies. */
    usleep(300000);
    close(s_peer_fd);
    return NULL;
}

AWS_TEST_CASE(
    test_kmstool_enclave_setclient_failure_does_not_reuse_client,
    s_test_kmstool_enclave_setclient_failure_does_not_reuse_client)
static int s_test_kmstool_enclave_setclient_failure_does_not_reuse_client(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_nitro_enclaves_library_init(allocator);

    s_destroyed_client = NULL;
    s_used_after_free = false;

    int fds[2];
    ASSERT_INT_EQUALS(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    s_peer_fd = fds[1];

    struct app_ctx app_ctx;
    AWS_ZERO_STRUCT(app_ctx);
    app_ctx.allocator = allocator;
    app_ctx.proxy_port = PROXY_PORT;

    pthread_t peer;
    ASSERT_INT_EQUALS(0, pthread_create(&peer, NULL, s_peer_thread, NULL));

    handle_connection(&app_ctx, fds[0]);

    ASSERT_INT_EQUALS(0, pthread_join(peer, NULL));
    close(fds[0]);

    /* The failed SetClient must leave no client behind for Decrypt to reuse. */
    ASSERT_FALSE(s_used_after_free);

    free(s_destroyed_client);
    aws_nitro_enclaves_library_clean_up();

    return SUCCESS;
}
