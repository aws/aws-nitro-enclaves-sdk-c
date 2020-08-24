#ifndef AWS_NITRO_ENCLAVES_NITRO_ENCLAVES_H
#define AWS_NITRO_ENCLAVES_NITRO_ENCLAVES_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/nitro_enclaves/exports.h>

#include <aws/common/allocator.h>
#include <aws/common/macros.h>

/**
 * TODO: This should be the only external API. Simple and powerful
 * TODO: Naming convention (i.e. aws_ne_* etc.)
 */

AWS_EXTERN_C_BEGIN

/**
 * Initializes the library.
 *
 * @param[in]    allocator    Optional parameter to override default allocator. If this parameter is set to null, a
 *                            default allocator is used instead.
 */
AWS_NITRO_ENCLAVES_API
void aws_nitro_enclaves_library_init(struct aws_allocator *allocator);

AWS_NITRO_ENCLAVES_API
void aws_nitro_enclaves_library_clean_up(void);

AWS_NITRO_ENCLAVES_API
int aws_nitro_enclaves_library_seed_entropy(uint64_t bytes);

/**
 * Returns the allocator of the library, as set by aws_nitro_enclaves_library_init.
 *
 * @return Returns the allocator used by the library.
 */
AWS_NITRO_ENCLAVES_API
struct aws_allocator *aws_nitro_enclaves_get_allocator(void);

AWS_EXTERN_C_END

#endif
