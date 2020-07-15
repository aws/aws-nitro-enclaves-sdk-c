#ifndef AWS_NITRO_ENCLAVES_EXPORTS_H
#define AWS_NITRO_ENCLAVES_EXPORTS_H
/**
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#if ((__GNUC__ >= 4) || defined(__clang__)) && defined(AWS_NITRO_ENCLAVES_USE_IMPORT_EXPORT) &&                        \
    defined(AWS_NITRO_ENCLAVES_EXPORTS)
#    define AWS_NITRO_ENCLAVES_API __attribute__((visibility("default")))
#else
#    define AWS_NITRO_ENCLAVES_API
#endif /* __GNUC__ >= 4 || defined(__clang__) */

#ifdef AWS_NO_STATIC_IMPL
#    define AWS_STATIC_IMPL AWS_NITRO_ENCLAVES_API
#endif

#ifndef AWS_STATIC_IMPL
/*
 * In order to allow us to export our inlinable methods in a DLL/.so, we have a designated .c
 * file where this AWS_STATIC_IMPL macro will be redefined to be non-static.
 */
#    define AWS_STATIC_IMPL static inline
#endif

#endif /* AWS_NITRO_ENCLAVES_EXPORTS_H */
