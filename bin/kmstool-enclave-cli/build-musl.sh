#!/bin/bash

set -e

docker build --target kmstool-enclave-cli -t kmstool-enclave-cli -f ../../containers/Dockerfile.alpine ../..
CONTAINER_ID=$(docker create kmstool-enclave-cli)
docker cp $CONTAINER_ID:/kmstool_enclave_cli ./
docker rm $CONTAINER_ID
