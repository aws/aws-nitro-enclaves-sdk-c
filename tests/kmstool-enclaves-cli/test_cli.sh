#!/bin/sh

# This script builds the kmstool-enclave-cli binary and runs a quick smoke test against KMS.
# Prerequisites:
# * An EC2 instance with Amazon Linux 2023
# * aws-nitro-enclaves-cli and aws-nitro-enclaves-cli-devel packages installed
# * IAM role attached to the EC2 instance and has the following permissions:
#    * kms:GenerateRandom
#    * kms:Encrypt
# * a KMS Key configured for debug mode (i.e. PCR0 = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
# * docker
# * socat
# * nitro-enclaves-allocator with at least 2G RAM and 2 CPUs
#
# Usage:
# KMS_KEY_ARN=arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab ./tests/kmstool-enclaves-cli/test_cli.sh

set -eu

cleanup() {
    docker rmi kmstool-enclave-cli:$RAND_TAG &>/dev/null ||:

    rm -rf "$TEMP_DIR" &>/dev/null ||:

    if [[ ! -z "${ENCLAVE_ID+x}" ]]; then
        nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" &>/dev/null ||:
    fi

    # Terminate vsock-proxy
    if [[ ! -z "${VSOCK_PROXY_PID+x}" ]]; then
        kill -9 ${VSOCK_PROXY_PID} &>/dev/null ||:
    fi
}

fail() {
    echo "$(tput bold)$(tput setaf 1) $1 $(tput sgr0)"
    echo "TEST: FAILED"
    exit 1
}

# Test for pre-requisites
nitro-cli --version || fail "aws-nitro-enclaves-cli not installed"
test -c /dev/nitro_enclaves || fail "not running on an instance with Nitro Enclaves enabled"
test ! -z "${KMS_KEY_ARN+x}" || fail "KMS_KEY_ARN not set"

# Initialize variables
readonly RAND_TAG=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64 | tr -cd "[[:alnum:]]")
readonly RAND_MSG=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64)
readonly TEMP_DIR=$(mktemp -d)
readonly KMS_KEY_REGION=${KMS_KEY_REGION:-us-east-1}

trap cleanup EXIT

CURRENT_DIR=$(pwd)

# Build the kmstool-enclave-cli binary
cd ../../bin/kmstool-enclave-cli
./build.sh

# Copy the binary into test folder
cp -f kmstool_enclave_cli ${CURRENT_DIR}/test-enclave/
cp -f libnsm.so ${CURRENT_DIR}/test-enclave/

# Build the test enclave
cd ${CURRENT_DIR}/test-enclave
nitro-cli build-enclave --docker-dir ./ --docker-uri kmstool-enclave-cli:$RAND_TAG --output-file $TEMP_DIR/test.eif

# Run vsock-proxy
nohup vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 >/dev/null 2>&1 &
VSOCK_PROXY_PID=$!

# Run the test enclave
ENCLAVE_ID=$(nitro-cli run-enclave --eif-path $TEMP_DIR/test.eif --memory 1024 --cpu-count 2 --enclave-cid 7777 --debug-mode  | jq -r .EnclaveID) || fail "Unable to start enclave"

# Get AWS credential
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_PROFILE_NAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
AWS_CREDENTIAL=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/${INSTANCE_PROFILE_NAME}")

ACCESS_KEY_ID=$(echo ${AWS_CREDENTIAL} | jq -r '.AccessKeyId')
SECRET_ACCESS_KEY=$(echo ${AWS_CREDENTIAL} | jq -r '.SecretAccessKey')
SESSION_TOKEN=$(echo ${AWS_CREDENTIAL} | jq -r '.Token')

# Encrypt a random message for testing decrypt command
MESSAGE="Test message: $RAND_MSG"
BASE64_MESSAGE=$(echo "$MESSAGE" | base64)
ENCRYPTED=$(aws kms encrypt --key-id "$KMS_KEY_ARN" --plaintext "$BASE64_MESSAGE" --query CiphertextBlob --output text)

# Generate payload for test enclave
PAYLOAD="{\"AccessKeyId\":\"${ACCESS_KEY_ID}\",\"SecretAccessKey\":\"${SECRET_ACCESS_KEY}\",\"Token\":\"${SESSION_TOKEN}\",\"KMSKeyArn\":\"${KMS_KEY_ARN}\",\"Ciphertext\":\"${ENCRYPTED}\"}"

# Send AWS credential to test enclave
sleep 10
echo "${PAYLOAD}" | socat VSOCK-CONNECT:7777:8001 -

# Open debug console
nitro-cli console --enclave-id ${ENCLAVE_ID} --disconnect-timeout 10
