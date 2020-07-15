/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

AWS_TEST_CASE(check_test, s_check_test)
static int s_check_test(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;
    return 0;
}
