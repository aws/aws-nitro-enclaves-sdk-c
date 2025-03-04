#ifndef KMSTOOL_TYPE_H
#define KMSTOOL_TYPE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

struct app_ctx {
    /* Allocator to use for memory allocations. */
    struct aws_allocator *allocator;

    /* Logger to use for logging. */
    struct aws_logger * logger;

    /* Enclave kms client*/
    struct aws_credentials *aws_credentials;
    struct aws_nitro_enclaves_kms_client *kms_client;

    /* KMS region to use. */
    struct aws_string *region;
    /* vsock port on which vsock-proxy is available in parent. */
    uint32_t proxy_port;

    /* KMS credentials */
    struct aws_string *aws_access_key_id;
    struct aws_string *aws_secret_access_key;
    struct aws_string *aws_session_token;

    /* Data parameters */
    struct aws_string *key_id;
    struct aws_string *encryption_algorithm;
};


#endif //KMSTOOL_TYPE_H