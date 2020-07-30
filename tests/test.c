/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/http/request_response.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/rest.h>

AWS_STATIC_STRING_FROM_LITERAL(s_test_service, "kms");
AWS_STATIC_STRING_FROM_LITERAL(s_test_region, "us-east-1");
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id_test_value, "My Access Key");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key_test_value, "SekritKey");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token_test_value, "Some Session Token");

static int s_test_basic_rest_client(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_nitro_enclaves_library_init(allocator);

    struct aws_credentials *credentials = aws_credentials_new_from_string(
        allocator, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value, UINT64_MAX);
    struct aws_nitro_enclaves_rest_client_configuration client_conf = {
        .allocator = allocator,
        .service = s_test_service,
        .region = s_test_region,
        .credentials = credentials,
    };

    struct aws_nitro_enclaves_rest_client *rest_client = aws_nitro_enclaves_rest_client_new(&client_conf);
    ASSERT_NOT_NULL(rest_client);
    aws_nitro_enclaves_rest_client_destroy(rest_client);
    aws_credentials_release(credentials);
    aws_nitro_enclaves_library_clean_up();
    return 0;
}
AWS_TEST_CASE(test_basic_rest_client, s_test_basic_rest_client)

static int s_test_rest_call_blocking(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_nitro_enclaves_library_init(allocator);

    struct aws_credentials *credentials = aws_credentials_new_from_string(
        allocator, s_access_key_id_test_value, s_secret_access_key_test_value, s_session_token_test_value, UINT64_MAX);

    struct aws_nitro_enclaves_rest_client_configuration client_conf = {
        .allocator = allocator,
        .service = s_test_service,
        .region = s_test_region,
        .credentials = credentials,
    };

    struct aws_nitro_enclaves_rest_client *rest_client = aws_nitro_enclaves_rest_client_new(&client_conf);
    ASSERT_NOT_NULL(rest_client);
    struct aws_nitro_enclaves_rest_response *response = aws_nitro_enclaves_rest_client_request_blocking(
        rest_client,
        aws_http_method_post,
        aws_byte_cursor_from_c_str("/"),
        aws_byte_cursor_from_c_str("TrentService.GenerateRandom"),
        aws_byte_cursor_from_c_str("{\"NumberOfBytes\": 32}"));

    ASSERT_NOT_NULL(response);
    ASSERT_NOT_NULL(response->response);
    struct aws_input_stream *request_stream = aws_http_message_get_body_stream(response->response);
    ASSERT_NOT_NULL(request_stream);

    aws_nitro_enclaves_rest_response_destroy(response);

    aws_nitro_enclaves_rest_client_destroy(rest_client);
    aws_credentials_release(credentials);
    aws_nitro_enclaves_library_clean_up();
    return 0;
}
AWS_TEST_CASE(test_rest_call_blocking, s_test_rest_call_blocking)
