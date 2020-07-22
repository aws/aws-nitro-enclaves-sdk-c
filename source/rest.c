/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/rest.h>

#include <aws/common/assert.h>
#include <aws/http/connection.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/tls_channel_handler.h>

#define ALPN_STRING "h2;http/1.1"
#define CONNECT_TIMEOUT_MS 3000UL

static void s_on_client_connection_setup(struct aws_http_connection *connection, int error_code, void *user_data) {
    struct aws_nitro_enclaves_rest_client *rest_client = user_data;
    /* TODO: Proper logging. */
    fprintf(stderr, "Connected\n");

    if (error_code) {
        fprintf(stderr, "Connection failed with error %s\n", aws_error_debug_str(error_code));
        return;
    }

    aws_mutex_lock(&rest_client->mutex);
    rest_client->connection = connection;
    aws_mutex_unlock(&rest_client->mutex);
    aws_condition_variable_notify_all(&rest_client->c_var);
}

static void s_on_client_connection_shutdown(struct aws_http_connection *connection, int error_code, void *user_data) {
    (void)connection;
    (void)user_data;
    fprintf(stderr, "Disconnected\n");

    if (error_code) {
        fprintf(stderr, "Connection failed with error %s\n", aws_error_debug_str(error_code));
        return;
    }
}

struct aws_nitro_enclaves_rest_client *aws_nitro_enclaves_rest_client_new(
    struct aws_nitro_enclaves_rest_client_configuration *configuration) {
    AWS_PRECONDITION(aws_allocator_is_valid(configuration->allocator));
    AWS_PRECONDITION(aws_byte_cursor_is_valid(&configuration->host_name));

    struct aws_nitro_enclaves_rest_client *rest_client =
        aws_mem_calloc(configuration->allocator, 1, sizeof(struct aws_nitro_enclaves_rest_client));
    if (rest_client == NULL) {
        /* TODO: aws_raise */
        return NULL;
    }
    rest_client->allocator = configuration->allocator;

    if (aws_mutex_init(&rest_client->mutex) != AWS_OP_SUCCESS ||
        aws_condition_variable_init(&rest_client->c_var) != AWS_OP_SUCCESS) {
        goto err_clean;
    }

    struct aws_tls_ctx_options tls_ctx_options;
    AWS_ZERO_STRUCT(tls_ctx_options);

    aws_tls_ctx_options_init_default_client(&tls_ctx_options, rest_client->allocator);
    if (aws_tls_ctx_options_set_alpn_list(&tls_ctx_options, ALPN_STRING) != AWS_OP_SUCCESS) {
        /* TODO: aws_raise */
        goto err_clean;
    }

    rest_client->tls_ctx = aws_tls_client_ctx_new(rest_client->allocator, &tls_ctx_options);
    if (rest_client->tls_ctx == NULL) {
        /* TODO: aws_raise */
        goto err_clean;
    }
    /* tls_ctx_options are copied, so the strucure can be cleaned up at this point */
    aws_tls_ctx_options_clean_up(&tls_ctx_options);

    aws_tls_connection_options_init_from_ctx(&rest_client->tls_connection_options, rest_client->tls_ctx);
    if (aws_tls_connection_options_set_server_name(
            &rest_client->tls_connection_options, rest_client->allocator, &configuration->host_name)) {
        /* TODO: aws_raise */
        goto err_clean;
    }

    /* TODO: Should the el_group be set by the caller instead? */
    if (aws_event_loop_group_default_init(&rest_client->el_group, rest_client->allocator, 0) != AWS_OP_SUCCESS) {
        /* TODO: aws_raise */
        goto err_clean;
    }
    /* TODO: Resolver should not be needed when using endpoints */
    if (aws_host_resolver_init_default(&rest_client->resolver, rest_client->allocator, 8, &rest_client->el_group) !=
        AWS_OP_SUCCESS) {
        /* TODO: aws_raise */
        goto err_clean;
    }

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = &rest_client->el_group,
        .host_resolver = &rest_client->resolver,
    };
    rest_client->bootstrap = aws_client_bootstrap_new(rest_client->allocator, &bootstrap_options);
    if (rest_client->bootstrap == NULL) {
        /* TODO: aws_raise */
        goto err_clean;
    }

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = CONNECT_TIMEOUT_MS,
        .keep_alive_timeout_sec = 0,
        .keepalive = false,
        .keep_alive_interval_sec = 0,
    };

    struct aws_http_client_connection_options http_client_options = {
        .self_size = sizeof(struct aws_http_client_connection_options),
        .socket_options = &socket_options,
        .allocator = rest_client->allocator,
        .port = 443,
        .host_name = configuration->host_name,
        .bootstrap = rest_client->bootstrap,
        .initial_window_size = SIZE_MAX,
        .tls_options = &rest_client->tls_connection_options,
        .user_data = rest_client,
        .on_setup = s_on_client_connection_setup,
        .on_shutdown = s_on_client_connection_shutdown,
    };

    if (configuration->endpoint) {
        socket_options.domain = configuration->domain;
        http_client_options.port = configuration->endpoint->port;
        http_client_options.host_name = aws_byte_cursor_from_c_str(configuration->endpoint->address);
    }

    if (aws_http_client_connect(&http_client_options) != AWS_OP_SUCCESS) {
        /* TODO: aws_raise */
        goto err_clean;
    }

    aws_mutex_lock(&rest_client->mutex);
    aws_condition_variable_wait(&rest_client->c_var, &rest_client->mutex);
    aws_mutex_unlock(&rest_client->mutex);

    if (rest_client->connection == NULL) {
        /* TODO: aws_raise */
        goto err_clean;
    }

    return rest_client;
err_clean:
    if (rest_client->connection != NULL) {
        aws_http_connection_release(rest_client->connection);
    }
    if (rest_client->bootstrap != NULL) {
        aws_client_bootstrap_release(rest_client->bootstrap);
    }

    aws_tls_connection_options_clean_up(&rest_client->tls_connection_options);
    if (rest_client->tls_ctx != NULL) {
        aws_tls_ctx_destroy(rest_client->tls_ctx);
    }

    aws_host_resolver_clean_up(&rest_client->resolver);
    aws_event_loop_group_clean_up(&rest_client->el_group);

    aws_mutex_clean_up(&rest_client->mutex);
    aws_condition_variable_clean_up(&rest_client->c_var);

    aws_mem_release(rest_client->allocator, rest_client);
    return NULL;
}

void aws_nitro_enclaves_rest_client_destroy(struct aws_nitro_enclaves_rest_client *rest_client) {
    AWS_PRECONDITION(rest_client);
    aws_http_connection_release(rest_client->connection);
    aws_client_bootstrap_release(rest_client->bootstrap);
    aws_host_resolver_clean_up(&rest_client->resolver);
    aws_event_loop_group_clean_up(&rest_client->el_group);
    aws_tls_connection_options_clean_up(&rest_client->tls_connection_options);
    aws_tls_ctx_destroy(rest_client->tls_ctx);
    aws_mutex_clean_up(&rest_client->mutex);
    aws_condition_variable_clean_up(&rest_client->c_var);
    aws_mem_release(rest_client->allocator, rest_client);
}
