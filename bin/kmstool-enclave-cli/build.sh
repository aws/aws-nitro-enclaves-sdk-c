#!/bin/bash

set -e

docker build --target kmstool-enclave-cli -t kmstool-enclave-cli -f ../../containers/Dockerfile.al2 ../..
CONTAINER_ID=$(docker create kmstool-enclave-cli)
docker cp $CONTAINER_ID:/kmstool_enclave_cli ./
docker cp $CONTAINER_ID:/usr/lib64/libnsm.so ./
docker rm $CONTAINER_ID
