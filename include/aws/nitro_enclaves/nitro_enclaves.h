#ifndef AWS_NITRO_ENCLAVES_NITRO_ENCLAVES_H
#define AWS_NITRO_ENCLAVES_NITRO_ENCLAVES_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/allocator.h>
#include <aws/common/macros.h>

AWS_EXTERN_C_BEGIN

void aws_nitro_enclaves_library_init(struct aws_allocator *allocator);
void aws_nitro_enclaves_library_clean_up(void);

AWS_EXTERN_C_END

#endif
