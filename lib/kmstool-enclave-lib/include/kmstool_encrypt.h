#ifndef KMSTOOL_ENCRYP_H
#define KMSTOOL_ENCRYP_H

#include <aws/common/encoding.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include "kmstool_type.h"
#include "kmstool_utils.h"
#include "../kmstool_enclave_lib.h"

int app_lib_encrypt(const struct app_ctx *ctx, const struct kmstool_encrypt_params *params, char **ciphertext_b64_out);

#endif //KMSTOOL_ENCRYP_H
