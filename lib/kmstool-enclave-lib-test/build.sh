#!/bin/bash

set -e

docker build --target kmstool-enclave-lib-test -t kmstool-enclave-lib-test -f ../../containers/Dockerfile.al2 ../..
CONTAINER_ID=$(docker create kmstool-enclave-lib-test)
docker cp $CONTAINER_ID:/kmstool_enclave_lib_test ./
docker cp $CONTAINER_ID:/usr/lib64/libnsm.so ./
docker rm $CONTAINER_ID
