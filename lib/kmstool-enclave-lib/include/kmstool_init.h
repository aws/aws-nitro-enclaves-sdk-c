#ifndef KMSTOOL_INIT_H
#define KMSTOOL_INIT_H

#include <aws/common/encoding.h>
#include <aws/common/logging.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
//#include <linux/vm_sockets.h>
//#include <stdio.h>
#include "kmstool_type.h"
#include "../kmstool_enclave_lib.h"

int app_lib_init(struct app_ctx *ctx, const struct kmstool_init_params *params);
int app_lib_clean_up(struct app_ctx *ctx);
int app_lib_update_aws_key(struct app_ctx *ctx, const struct kmstool_update_aws_key_params *params);

#endif //KMSTOOL_INIT_H