#ifndef KMSTOOL_DECRYPT_H
#define KMSTOOL_DECRYPT_H

#include "../kmstool_enclave_lib.h"
#include "kmstool_type.h"
#include "kmstool_utils.h"
#include <aws/common/encoding.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

int app_lib_decrypt(
    const struct app_ctx *ctx,
    const struct kmstool_decrypt_params *params,
    uint8_t **plaintext_out,
    size_t *plaintext_out_len);

#endif // KMSTOOL_DECRYPT_H