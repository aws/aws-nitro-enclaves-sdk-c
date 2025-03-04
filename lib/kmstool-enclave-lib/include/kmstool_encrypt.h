#ifndef KMSTOOL_ENCRYP_H
#define KMSTOOL_ENCRYP_H

#include "../kmstool_enclave_lib.h"
#include "kmstool_type.h"
#include "kmstool_utils.h"
#include <aws/common/encoding.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

int app_lib_encrypt(
    const struct app_ctx *ctx,
    const struct kmstool_encrypt_params *params,
    uint8_t **ciphertext_out,
    size_t *ciphertext_out_len);

#endif // KMSTOOL_ENCRYP_H
