#ifndef KMSTOOL_UTILS_H
#define KMSTOOL_UTILS_H

#include <aws/common/encoding.h>
#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>
#include "kmstool_type.h"

int encode_b64(const struct app_ctx *ctx, const struct aws_byte_buf *text, struct aws_byte_buf *text_b64);
int decode_b64(const struct app_ctx *ctx, const struct aws_string *text_b64, struct aws_byte_buf *text);

#endif //KMSTOOL_UTILS_H
