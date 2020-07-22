/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/http/request_response.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include <aws/nitro_enclaves/rest.h>

static int s_test_basic_rest_client(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_nitro_enclaves_library_init(allocator);

    struct aws_nitro_enclaves_rest_client_configuration client_conf = {
        .allocator = allocator,
        .host_name = aws_byte_cursor_from_c_str("kms.us-east-1.amazonaws.com"),
    };

    struct aws_nitro_enclaves_rest_client *rest_client = aws_nitro_enclaves_rest_client_new(&client_conf);
    ASSERT_NOT_NULL(rest_client);
    aws_nitro_enclaves_rest_client_destroy(rest_client);
    aws_nitro_enclaves_library_clean_up();
    return 0;
}
AWS_TEST_CASE(test_basic_rest_client, s_test_basic_rest_client)
