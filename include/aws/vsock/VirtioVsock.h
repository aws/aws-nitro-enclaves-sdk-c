#pragma once

/**
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef VIRTIOVSOCK_H
#define VIRTIOVSOCK_H

#include <WinSock2.h>

#define VSOCK_PROVIDER_NAME             "AWS VirtIO Vsock Provider"
#define VSOCK_PROVIDER_WNAME            L"AWS VirtIO Vsock Provider"

// This family is not reserved on Microsoft Windows.  Given that it is 
// in use in multiple public projects and other operating systems, it is 
// likely that the purpose of this family will not be assigned to other 
// purposes by Windows.
#ifndef AF_VSOCK
#define AF_VSOCK                        40
#endif

#define SOCKADDR_VM_CID_ANY             (~0U)
#define SOCKADDR_VM_PORT_ANY            (0U)

#define SOCKADDR_VM_CID_HYPERVISOR      0
#define SOCKADDR_VM_CID_RESERVED        1
#define SOCKADDR_VM_CID_HOST            2

// Defined to be compatible with the Linux sockaddr_vm struct from the Linux
// man pages.
struct sockaddr_vm {
    u_short svm_family;
    u_short svm_reserved1;
    u_int   svm_port;
    u_int   svm_cid;
};
typedef struct sockaddr_vm SOCKADDR_VM, *PSOCKADDR_VM;

#endif // VIRTIOVSOCK_H