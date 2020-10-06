# vock-sample

A hello-world example for vsock server and client communication.

## Prerequisites

1. Get the __vsock-sample__ code. __vsock-sample__ is an application
that can be run either as a server or a client. The client sends the
“Hello, world!” message to the server. The server receives the message
and prints it to the standard output.
__Note__: You can change the behavior by replacing the code marked with *TODO*. 

2. Because the code is written in Rust, you need to install __cargo__
(Rust’s build system and package manager) and add the __x86_64-unknown-linux-musl__
target. You can easily do that using *rustup*, a command line tool
for managing Rust versions and associated tools.

```
$ curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
$ rustup target add x86_64-unknown-linux-musl
```

3. Compile the code using __cargo__. You can find the resulting binary
at  __vsock-sample/target/x86_64-unknown-linux-musl/release/vsock-sample__.

```
$ cargo build --target=x86_64-unknown-linux-musl --release
```
## How to use the enclave as server and the parent instance as client

1. Build the Enclave Image File (EIF) starting from a Dockerfile
similar to the one below. We chose to start from the alpine distro
to keep the enclave image as small as possible, but you can also
use ubuntu. Then copy the __vsock-sample__ binary and use it to
start the server inside the enclave.

```
FROM alpine:latest
COPY vsock-sample .
CMD ./vsock-sample server --cid $ENCLAVE_CID --port 5005
```
__Notes__:
* if the enclave CID is auto-generated, just skip the __--cid__ argument
* you can use other port number

```
$ ./nitro-cli build-enclave --docker-dir path_to_dockerfile --docker-uri vsock-sample-server --output-file vsock_sample_server.eif
```

2. Configure the pool of memory and vCPUs (the __nitro-cli-config__ 
script can be used) and run the enclave using the built EIF.

```
// 2 vCPUs and 256 MiB memory
$ ./nitro-cli-config -t 2 -m 256
$ ./nitro-cli run-enclave --eif-path vsock_sample_server.eif --cpu-count 2 --memory 256 --debug-mode
```

3. Connect to the enclave console using __nitro-cli__

```
$ ./nitro-cli console --enclave-id $ENCLAVE_ID
```

4. In another terminal, run the client

```
$ ./vsock-sample client --cid $ENCLAVE_CID --port 5005
```

5. The console output should look like this

```
[    0.127079] Freeing unused kernel memory: 476K
[    0.127631] nsm: loading out-of-tree module taints kernel.
[    0.128055] nsm: module verification failed: signature and/or required key missing - tainting kernel
[    0.154010] random: vsock-sample: uninitialized urandom read (16 bytes read)
Hello, world!
```

## How to use the parent instance as server and the enclave as client

1. Build the Enclave Image File (EIF) starting from a Dockerfile
similar to the one below. We chose to start from the alpine distro
to keep the enclave image as small as possible, but you can also
use ubuntu. Then copy the __vsock-sample__ binary and use it to
start the server inside the enclave.

```
FROM alpine:latest
COPY vsock-sample .
CMD ./vsock-sample client --cid 3 --port 5005
```
__Notes__:
* 3 is the CID of the parent instance
* you can use other port number
```
$ ./nitro-cli build-enclave --docker-dir path_to_dockerfile --docker-uri vsock-sample-client --output-file vsock_sample_client.eif
```

2. Run the server inside the parent instance

```
$ ./vsock-sample server --cid 3 --port 5005
```

3. Configure the pool of memory and vCPUs (the __nitro-cli-config__
script can be used) and run the enclave using the built EIF.

```
// 2 vCPUs and 256 MiB memory
$ ./nitro-cli-config -t 2 -m 256
$ ./nitro-cli run-enclave --eif-path vsock_sample_client.eif --cpu-count 2 --memory 256 --debug-mode
```

4. The server should print __Hello, world!__

```
$ ./vsock-sample server --cid 3 --port 5005
Hello, world!
```

Now you can replace the client/server code with your own code.
