/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/auth/auth.h>
#include <aws/common/allocator.h>
#include <aws/http/http.h>

#include <fcntl.h>
#include <linux/random.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <nsm-lib.h>

/* Maximum number of bytes NSM random response returns. */
#define NSM_RANDOM_REQ_SIZE (256)

static bool s_library_initialized = false;

void aws_nitro_enclaves_library_init(struct aws_allocator *allocator) {
    if (s_library_initialized) {
        return;
    }
    s_library_initialized = true;

    aws_auth_library_init(allocator);
    aws_http_library_init(allocator);
    /* TODO: Initialize NSM */
}

void aws_nitro_enclaves_library_clean_up(void) {
    if (!s_library_initialized) {
        return;
    }
    s_library_initialized = false;

    aws_auth_library_clean_up();
    aws_http_library_clean_up();
}

int aws_nitro_enclaves_library_seed_entropy(uint64_t num_bytes) {

    int nsm_fd = nsm_lib_init();
    if (nsm_fd < 0)
        return -1;

    int dev_fd = open("/dev/random", O_WRONLY);
    if (dev_fd < 0) {
        nsm_lib_exit(nsm_fd);
        return -1;
    }

    uint64_t count = 0;

    while (count != num_bytes) {
        uint8_t buf[NSM_RANDOM_REQ_SIZE];
        size_t buf_len = sizeof(buf) > (num_bytes - count) ?
            (num_bytes - count) : sizeof(buf);

        /* Yields up to 256 bytes */
        int rc = nsm_get_random(nsm_fd, buf, &buf_len);
        if (rc)
            goto err;

        if (buf_len == 0) {
            /* NSM starts yielding zero entropy */
            goto err;
        }

        if ((ssize_t)buf_len != write(dev_fd, buf, buf_len))
            goto err;

        int bits = buf_len * 8;
        rc = ioctl(dev_fd, RNDADDTOENTCNT, &bits);
        if (rc < 0)
            goto err;

        count += buf_len;
    }

    close(dev_fd);
    nsm_lib_exit(nsm_fd);

    return 0;

err:
    close(dev_fd);
    nsm_lib_exit(nsm_fd);

    return -1;
}
