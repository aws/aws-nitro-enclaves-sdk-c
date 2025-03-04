#ifndef KMSTOOL_DECRYPT_H
#define KMSTOOL_DECRYPT_H

#include <aws/common/encoding.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include "kmstool_type.h"
#include "kmstool_utils.h"
#include "../kmstool_enclave_lib.h"

int app_lib_decrypt(const struct app_ctx *ctx, const struct kmstool_decrypt_params *params, char **plaintext_b64_out);

#endif //KMSTOOL_DECRYPT_H