#!/bin/bash

set -e

docker build --target kmstool-enclave-lib -t kmstool-enclave-lib -f ../../containers/Dockerfile.al2 ../..
CONTAINER_ID=$(docker create kmstool-enclave-lib)
docker cp $CONTAINER_ID:/libkmstool-enclave-lib.so ./
docker cp $CONTAINER_ID:/usr/lib64/libnsm.so ./
docker rm $CONTAINER_ID
