#ifndef AWS_NITRO_ENCLAVES_NITRO_ENCLAVES_H
#define AWS_NITRO_ENCLAVES_NITRO_ENCLAVES_H

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * @mainpage
 *
 * # AWS Nitro Enclaves SDK for C
 *
 * This SDK allows you to use the functionality of AWS Nitro Enclaves and provides simple APIs for seeding
 * system entropy or calling into AWS KMS using attestation.
 *
 * To instantiate the library, call aws_nitro_enclaves_library_init() first.
 * To seed entropy, use aws_nitro_enclaves_library_seed_entropy().
 *
 * ## AWS KMS
 * To use AWS KMS functionality, create an aws_kms_client using aws_nitro_enclaves_kms_client_new(),
 * afterwards, call aws_kms_decrypt_blocking(), aws_kms_generate_random_blocking() and
 * aws_kms_generate_data_key_blocking(), depending on needs.
 *
 * Additional documentation and sample can be found in the main
 * [Github repository](https://github.com/aws/aws-nitro-enclaves-sdk-c) or
 * on AWS documentation website for
 * [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
 */

#include <aws/nitro_enclaves/exports.h>

#include <aws/common/allocator.h>
#include <aws/common/macros.h>

/**
 * @file
 * Initialize the library and main enclave functionality.
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

/**
 * Seeds the entropy pool of the system with entropy from the NitroSecureModule device attached to the enclave.
 * In practical situations, the functionality should be called when entropy is required but the system pool
 * doesn't have sufficient entropy available, or on a given timer, depending on requirements.
 *
 * @param[in]    bytes      The number of bytes to seed.
 * @return                  AWS_OP_SUCCESS if the operation has succeeded.
 */
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
