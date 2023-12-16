#!/bin/sh

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.

# This script builds the current repo and runs a quick smoke test against KMS.
# Prerequisites:
# * aws-nitro-enclaves-cli and aws-nitro-enclaves-cli-devel packages installed
# * a KMS Key configured for debug mode (all zeroes)
# * docker
# * vsock-proxy running
# * nitro-enclaves-allocator with at least 1G RAM and 2 CPUs
#
# Usage:
# KMS_KEY_ARN=arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab ./tests/kmstool-enclaves/integration/test_kms.sh

set -eu

cleanup() {
    docker rmi kmstool-instance:$RAND_TAG &>/dev/null ||:
    docker rmi kmstool-enclave:$RAND_TAG &>/dev/null ||:

    rm -rf "$TEMP_DIR" &>/dev/null ||:

    if [[ ! -z "${ENCLAVE_ID+x}" ]]; then
        nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" &>/dev/null ||:
    fi
}

fail() {
    echo "$(tput bold)$(tput setaf 1) $1 $(tput sgr0)"
    echo "TEST: FAILED"
    exit 1
}

nitro-cli --version || fail "aws-nitro-enclaves-cli not installed"
test -c /dev/nitro_enclaves || fail "not running on an instance with Nitro Enclaves enabled"
test ! -z "${KMS_KEY_ARN+x}" || fail "KMS_KEY_ARN not set"

readonly RAND_TAG=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64 | tr -cd "[[:alnum:]]")
readonly RAND_MSG=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64)
readonly TEMP_DIR=$(mktemp -d)
readonly KMS_KEY_REGION=${KMS_KEY_REGION:-us-east-1}

trap cleanup EXIT

docker build -f containers/Dockerfile.al2 --target kmstool-instance -t "kmstool-instance:$RAND_TAG" . || fail "Unable to build kmstool-instance"
docker build -f containers/Dockerfile.al2 --target kmstool-enclave -t "kmstool-enclave:$RAND_TAG" .  || fail "Unable to build kmstool-enclave"

nitro-cli build-enclave --docker-uri kmstool-enclave:$RAND_TAG --output-file $TEMP_DIR/test.eif | jq . || fail "Unable to build EIF"

ENCLAVE_ID=$(nitro-cli run-enclave --eif-path $TEMP_DIR/test.eif --memory 1024 --cpu-count 2 --enclave-cid 7777 --debug-mode  | jq -r .EnclaveID) || fail "Unable to start enclave"

MESSAGE="Test message: $RAND_MSG"
BASE64_MESSAGE=$(echo "$MESSAGE" | base64)

ENCRYPTED=$(aws kms encrypt --key-id "$KMS_KEY_ARN" --plaintext "$BASE64_MESSAGE" --query CiphertextBlob --output text)
docker run --network host -t kmstool-instance:$RAND_TAG bash -c "/kmstool_instance --cid 7777 '$ENCRYPTED' 2>/dev/null | grep -q '$MESSAGE'" || fail "Message could not be decrypted"


echo "TEST: SUCCESS"
