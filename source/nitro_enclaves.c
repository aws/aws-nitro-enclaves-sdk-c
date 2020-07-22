/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/auth/auth.h>
#include <aws/common/allocator.h>
#include <aws/http/http.h>

static bool s_library_initialized = false;

void aws_nitro_enclaves_library_init(struct aws_allocator *allocator) {
    if (s_library_initialized) {
        return;
    }
    s_library_initialized = true;

    aws_auth_library_init(allocator);
    aws_http_library_init(allocator);
    /* TODO: Initialize NSM */
}

void aws_nitro_enclaves_library_clean_up(void) {
    if (!s_library_initialized) {
        return;
    }
    s_library_initialized = false;

    aws_auth_library_clean_up();
    aws_http_library_clean_up();
}
