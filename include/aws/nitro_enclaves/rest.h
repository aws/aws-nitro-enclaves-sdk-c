#ifndef AWS_NITRO_ENCLAVES_REST_H
#define AWS_NITRO_ENCLAVES_REST_H
/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/nitro_enclaves/exports.h>

#include <aws/auth/credentials.h>
#include <aws/common/allocator.h>
#include <aws/common/condition_variable.h>
#include <aws/common/logging.h>
#include <aws/common/macros.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/http/request_response.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

struct aws_nitro_enclaves_rest_client_configuration {
    struct aws_allocator *allocator;

    /* The service and region are used to determine the host name. Used in TLS and signing. */
    const struct aws_string *service;
    const struct aws_string *region;

    /* Optional endpoint to use instead of the DNS endpoint. */
    struct aws_socket_endpoint *endpoint;
    /* Optional. Specifies the domain of the given endpoint, if the endpoint is set. */
    enum aws_socket_domain domain;

    /*
     * Signing key control:
     *
     *   (1) If "credentials" is valid, use it
     *   (2) Else if "credentials_provider" is valid, query credentials from the provider and use the result
     *   (3) Else fail
     *
     */
    struct aws_credentials *credentials;

    struct aws_credentials_provider *credentials_provider;
};

/**
 * Configuration of a rest client, used to create new connections and process REST requests.
 */
struct aws_nitro_enclaves_rest_client {
    /* The associated allocator from which to allocate internally. */
    struct aws_allocator *allocator;

    /* Internal variables required for creating new connections. */
    struct aws_tls_ctx *tls_ctx;
    struct aws_client_bootstrap *bootstrap;
    struct aws_event_loop_group el_group;
    struct aws_host_resolver resolver;
    struct aws_tls_connection_options tls_connection_options;

    /* Variables required for sync-ing client on creation. */
    struct aws_mutex mutex;
    struct aws_condition_variable c_var;

    /* An open connection that is used to create connection streams. */
    struct aws_http_connection *connection;

    /* The service and region are used to determine the host name. Used in TLS and signing. */
    struct aws_string *service;
    struct aws_string *region;
    struct aws_string *host_name;

    /*
     * Signing key control:
     *
     *   (1) If "credentials" is valid, use it
     *   (2) Else if "credentials_provider" is valid, query credentials from the provider and use the result
     *   (3) Else fail
     *
     */
    struct aws_credentials *credentials;

    struct aws_credentials_provider *credentials_provider;
};

/**
 * The response from a REST request. The `response` field is the useable part of this structure, __data is purely
 * internal. Do not call aws_http_message_acquire on the response field.
 */
struct aws_nitro_enclaves_rest_response {
    struct aws_allocator *allocator;

    /* Contains the response from the REST request. */
    struct aws_http_message *response;

    /* This is the backings store of the aws_input_stream found in the response.
     * TODO: make a version of aws_input_stream that owns its own data instead.
     */
    struct aws_byte_cursor __cursor;
    struct aws_byte_buf __data;
};

AWS_EXTERN_C_BEGIN

/* Creates a new aws_nitro_enclaves_rest_client using the given configuration and some
 * safe defaults, including TLS.
 *
 * @param[in]    configuration    configuration is no longer required after the client is constructed.
 *
 * @return                        Returns a configured and functional REST client.
 */
AWS_NITRO_ENCLAVES_API
struct aws_nitro_enclaves_rest_client *aws_nitro_enclaves_rest_client_new(
    struct aws_nitro_enclaves_rest_client_configuration *configuration);

/**
 * Frees the resources associated with a rest client.
 *
 * @param[in]    rest_client    The REST client to destroy.
 */
AWS_NITRO_ENCLAVES_API
void aws_nitro_enclaves_rest_client_destroy(struct aws_nitro_enclaves_rest_client *rest_client);

AWS_NITRO_ENCLAVES_API
struct aws_nitro_enclaves_rest_response *aws_nitro_enclaves_rest_client_request_blocking(
    struct aws_nitro_enclaves_rest_client *rest_client,
    struct aws_byte_cursor method,
    struct aws_byte_cursor path,
    struct aws_byte_cursor target,
    struct aws_byte_cursor data);

/**
 * Frees the resources associated with a REST response.
 *
 * @param[in]    response    The REST response to destroy.
 */
AWS_NITRO_ENCLAVES_API
void aws_nitro_enclaves_rest_response_destroy(struct aws_nitro_enclaves_rest_response *response);

AWS_EXTERN_C_END

#endif /* AWS_NITRO_ENCLAVES_REST_H */
