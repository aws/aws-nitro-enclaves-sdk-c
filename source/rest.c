/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/rest.h>

#include <aws/auth/credentials.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_result.h>
#include <aws/common/assert.h>
#include <aws/http/connection.h>
#include <aws/http/request_response.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/stream.h>
#include <aws/io/tls_channel_handler.h>

#include <inttypes.h>

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
    AWS_PRECONDITION(aws_string_is_valid(configuration->service));
    AWS_PRECONDITION(aws_string_is_valid(configuration->region));
    AWS_PRECONDITION(configuration->credentials != NULL || configuration->credentials_provider != NULL);

    char host_name_str[256];
    snprintf(
        host_name_str,
        sizeof(host_name_str),
        "%s.%s.amazonaws.com",
        aws_string_c_str(configuration->service),
        aws_string_c_str(configuration->region));
    struct aws_byte_cursor host_name = aws_byte_cursor_from_c_str(host_name_str);

    struct aws_nitro_enclaves_rest_client *rest_client =
        aws_mem_calloc(configuration->allocator, 1, sizeof(struct aws_nitro_enclaves_rest_client));
    if (rest_client == NULL) {
        /* TODO: aws_raise */
        return NULL;
    }
    rest_client->allocator = configuration->allocator;

    rest_client->service = aws_string_clone_or_reuse(rest_client->allocator, configuration->service);
    rest_client->region = aws_string_clone_or_reuse(rest_client->allocator, configuration->region);
    rest_client->host_name = aws_string_new_from_c_str(rest_client->allocator, host_name_str);
    if (rest_client->service == NULL || rest_client->region == NULL || rest_client->host_name == NULL) {
        goto err_clean;
    }

    if (configuration->credentials_provider != NULL) {
        aws_credentials_provider_acquire(configuration->credentials_provider);
    }

    if (configuration->credentials != NULL) {
        aws_credentials_acquire(configuration->credentials);
    }

    rest_client->credentials = configuration->credentials;
    rest_client->credentials_provider = configuration->credentials_provider;

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
            &rest_client->tls_connection_options, rest_client->allocator, &host_name)) {
        // TODO: aws_raise
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
        .host_name = host_name,
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
    aws_http_connection_release(rest_client->connection);
    aws_client_bootstrap_release(rest_client->bootstrap);

    aws_tls_connection_options_clean_up(&rest_client->tls_connection_options);
    aws_tls_ctx_destroy(rest_client->tls_ctx);

    aws_host_resolver_clean_up(&rest_client->resolver);
    aws_event_loop_group_clean_up(&rest_client->el_group);

    aws_mutex_clean_up(&rest_client->mutex);
    aws_condition_variable_clean_up(&rest_client->c_var);

    aws_string_destroy(rest_client->host_name);

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
    aws_string_destroy(rest_client->service);
    aws_string_destroy(rest_client->region);
    aws_string_destroy(rest_client->host_name);
    aws_credentials_release(rest_client->credentials);
    aws_credentials_provider_release(rest_client->credentials_provider);
    aws_mem_release(rest_client->allocator, rest_client);
}

struct request_ctx {
    struct aws_nitro_enclaves_rest_client *rest_client;

    struct aws_nitro_enclaves_rest_response *response;

    struct aws_http_message *request;
    struct aws_input_stream *request_data_stream;

    /* Track request status */
    bool response_code_written;
    int error_code;

    /* For synchronization */
    struct aws_condition_variable c_var;
    struct aws_mutex mutex;
};

static int s_on_incoming_headers_fn(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers,
    void *user_data) {
    (void)stream;
    int status = 0;
    int rc = 0;

    struct request_ctx *ctx = user_data;
    if (!ctx->response_code_written) {
        rc = aws_http_stream_get_incoming_response_status(stream, &status);
        if (rc != AWS_OP_SUCCESS) {
            return rc;
        }
        rc = aws_http_message_set_response_status(ctx->response->response, status);
        if (rc != AWS_OP_SUCCESS) {
            return rc;
        }
        ctx->response_code_written = true;
    }

    if (header_block != AWS_HTTP_HEADER_BLOCK_MAIN) {
        return AWS_OP_SUCCESS;
    }

    return aws_http_headers_add_array(aws_http_message_get_headers(ctx->response->response), header_array, num_headers);
}

static int s_on_incoming_header_block_done_fn(
    struct aws_http_stream *stream,
    enum aws_http_header_block header_block,
    void *user_data) {
    (void)stream;
    (void)header_block;
    (void)user_data;

    return AWS_OP_SUCCESS;
}

static void s_on_stream_complete_fn(struct aws_http_stream *stream, int error_code, void *user_data) {
    (void)error_code;
    struct request_ctx *ctx = user_data;
    aws_http_stream_release(stream);
    ctx->error_code = error_code;

    if (error_code == AWS_OP_SUCCESS) {
        ctx->response->__cursor = aws_byte_cursor_from_buf(&ctx->response->__data);
        aws_http_message_set_body_stream(
            ctx->response->response,
            aws_input_stream_new_from_cursor(ctx->response->allocator, &ctx->response->__cursor));
    }

    aws_condition_variable_notify_all(&ctx->c_var);
}

static int s_on_incoming_body_fn(struct aws_http_stream *stream, const struct aws_byte_cursor *data, void *user_data) {
    (void)stream;
    (void)data;
    struct request_ctx *ctx = user_data;

    return aws_byte_buf_append_dynamic(&ctx->response->__data, data);
}

static struct aws_http_message *s_make_request(
    struct aws_nitro_enclaves_rest_client *rest_client,
    struct aws_byte_cursor method,
    struct aws_byte_cursor path,
    struct aws_byte_cursor target,
    struct aws_input_stream *request_data_stream) {

    struct aws_http_message *request = aws_http_message_new_request(rest_client->allocator);

    struct aws_http_header host_header = {.name = aws_byte_cursor_from_c_str("host"),
                                          .value = aws_byte_cursor_from_string(rest_client->host_name)};
    aws_http_message_add_header(request, host_header);

    struct aws_http_header content_type = {.name = aws_byte_cursor_from_c_str("content-type"),
                                           .value = aws_byte_cursor_from_c_str("application/x-amz-json-1.1")};
    aws_http_message_add_header(request, content_type);

    struct aws_http_header target_header = {.name = aws_byte_cursor_from_c_str("x-amz-target"), .value = target};
    aws_http_message_add_header(request, target_header);

    aws_http_message_set_request_method(request, method);
    aws_http_message_set_request_path(request, path);

    int64_t content_length = 0;
    char content_length_str[64];
    AWS_ZERO_ARRAY(content_length_str);

    aws_input_stream_get_length(request_data_stream, &content_length);
    sprintf(content_length_str, "%" PRIi64, content_length);

    struct aws_http_header content_length_header = {.name = aws_byte_cursor_from_c_str("content-length"),
                                                    .value = aws_byte_cursor_from_c_str(content_length_str)};
    aws_http_message_add_header(request, content_length_header);

    aws_http_message_set_body_stream(request, request_data_stream);

    return request;
}

static void s_on_sign_complete(struct aws_signing_result *signing_result, int error_code, void *userdata) {
    struct request_ctx *ctx = userdata;

    if (error_code != AWS_OP_SUCCESS) {
        goto err_clean;
    }

    if (aws_apply_signing_result_to_http_request(ctx->request, ctx->rest_client->allocator, signing_result) !=
        AWS_OP_SUCCESS) {
        goto err_clean;
    }

    struct aws_http_make_request_options request_options = {
        .self_size = sizeof(request_options),
        .user_data = ctx,
        .request = ctx->request,
        .on_response_headers = s_on_incoming_headers_fn,
        .on_response_header_block_done = s_on_incoming_header_block_done_fn,
        .on_response_body = s_on_incoming_body_fn,
        .on_complete = s_on_stream_complete_fn,
    };

    struct aws_http_stream *stream = aws_http_connection_make_request(ctx->rest_client->connection, &request_options);

    if (stream == NULL || aws_http_stream_activate(stream) != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed to create request.");
        goto err_clean;
    }

    return;
err_clean:
    ctx->error_code = AWS_OP_ERR;
    aws_http_stream_release(stream);
    aws_condition_variable_notify_all(&ctx->c_var);
}

struct aws_nitro_enclaves_rest_response *aws_nitro_enclaves_rest_client_request_blocking(
    struct aws_nitro_enclaves_rest_client *rest_client,
    struct aws_byte_cursor method,
    struct aws_byte_cursor path,
    struct aws_byte_cursor target,
    struct aws_byte_cursor data) {
    AWS_PRECONDITION(rest_client);
    AWS_PRECONDITION(rest_client->connection);

    struct request_ctx ctx;
    AWS_ZERO_STRUCT(ctx);

    if (aws_mutex_init(&ctx.mutex) != AWS_OP_SUCCESS || aws_condition_variable_init(&ctx.c_var) != AWS_OP_SUCCESS) {
        goto err_clean;
    }

    ctx.request_data_stream = aws_input_stream_new_from_cursor(rest_client->allocator, &data);

    ctx.request = s_make_request(rest_client, method, path, target, ctx.request_data_stream);
    ctx.rest_client = rest_client;

    ctx.response = aws_mem_calloc(rest_client->allocator, 1, sizeof(struct aws_nitro_enclaves_rest_response));
    if (ctx.response == NULL) {
        goto err_clean;
    }
    ctx.response->allocator = rest_client->allocator;
    ctx.response->response = aws_http_message_new_response(ctx.response->allocator);
    if (ctx.response->response == NULL) {
        goto err_clean;
    }
    aws_byte_buf_init(&ctx.response->__data, rest_client->allocator, 0);

    struct aws_signable *sign_request = aws_signable_new_http_request(rest_client->allocator, ctx.request);

    struct aws_signing_config_aws signing_config = {
        .config_type = AWS_SIGNING_CONFIG_AWS,
        .algorithm = AWS_SIGNING_ALGORITHM_V4,
        .signature_type = AWS_ST_HTTP_REQUEST_HEADERS,
        .region = aws_byte_cursor_from_string(rest_client->region),
        .service = aws_byte_cursor_from_string(rest_client->service),
        .credentials = rest_client->credentials,
        .credentials_provider = rest_client->credentials_provider,
        .signed_body_value = AWS_SBVT_PAYLOAD,
        .signed_body_header = AWS_SBHT_X_AMZ_CONTENT_SHA256,
    };

    aws_date_time_init_now(&signing_config.date);

    if (aws_sign_request_aws(
            rest_client->allocator,
            sign_request,
            (const struct aws_signing_config_base *)&signing_config,
            s_on_sign_complete,
            &ctx) != AWS_OP_SUCCESS) {
        goto err_clean;
    }

    aws_mutex_lock(&ctx.mutex);
    aws_condition_variable_wait(&ctx.c_var, &ctx.mutex);
    aws_mutex_unlock(&ctx.mutex);

    if (ctx.error_code != AWS_OP_SUCCESS) {
        fprintf(stderr, "failed  to process request");
        goto err_clean;
    }

    aws_http_message_destroy(ctx.request);
    aws_input_stream_destroy(ctx.request_data_stream);
    aws_signable_destroy(sign_request);

    return ctx.response;
err_clean:
    aws_http_message_destroy(ctx.request);
    aws_input_stream_destroy(ctx.request_data_stream);
    aws_signable_destroy(sign_request);

    aws_nitro_enclaves_rest_response_destroy(ctx.response);
    return NULL;
}

void aws_nitro_enclaves_rest_response_destroy(struct aws_nitro_enclaves_rest_response *response) {
    if (response == NULL) {
        return;
    }

    AWS_PRECONDITION(aws_byte_buf_is_valid(&response->__data));
    AWS_PRECONDITION(aws_http_message_is_response(response->response));

    struct aws_input_stream *stream = aws_http_message_get_body_stream(response->response);

    aws_http_message_release(response->response);
    aws_byte_buf_clean_up_secure(&response->__data);
    aws_input_stream_destroy(stream);

    aws_mem_release(response->allocator, response);
}
