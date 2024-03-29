#!/bin/bash

set -e

# Receive payload from parent instance
socat VSOCK-LISTEN:8001 OPEN:payload.json,creat,trunc

ACCESS_KEY_ID=$(cat payload.json | jq -r '.AccessKeyId')
SECRET_ACCESS_KEY=$(cat payload.json | jq -r '.SecretAccessKey')
SESSION_TOKEN=$(cat payload.json | jq -r '.Token')
KMS_KEY_ARN=$(cat payload.json | jq -r '.KMSKeyArn')
CIPHERTEXT=$(cat payload.json | jq -r '.Ciphertext')

# Set library path to app directory for libnsm.so
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app

# Run decrypte
echo "======================================================================================"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                      Decrypt                                       |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "======================================================================================"

set +e

/app/kmstool_enclave_cli decrypt \
    --region us-east-1 \
    --proxy-port 8000 \
    --aws-access-key-id ${ACCESS_KEY_ID} \
    --aws-secret-access-key ${SECRET_ACCESS_KEY} \
    --aws-session-token ${SESSION_TOKEN} \
    --ciphertext ${CIPHERTEXT}

if [[ $? -eq 0 ]];then
    DECRYPT_SUCCESS=1
else
    DECRYPT_SUCCESS=0
fi

set -e

# Run genkey
echo "======================================================================================"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                       Genkey                                       |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "======================================================================================"

set +e

/app/kmstool_enclave_cli genkey \
    --region us-east-1 \
    --proxy-port 8000 \
    --aws-access-key-id ${ACCESS_KEY_ID} \
    --aws-secret-access-key ${SECRET_ACCESS_KEY} \
    --aws-session-token ${SESSION_TOKEN} \
    --key-id ${KMS_KEY_ARN} \
    --key-spec "AES-256"

if [[ $? -eq 0 ]];then
    GENKEY_SUCCESS=1
else
    GENKEY_SUCCESS=0
fi

set -e

# Run genrandom
echo "======================================================================================"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                     GenRandom                                      |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "======================================================================================"

set +e

/app/kmstool_enclave_cli genrandom \
    --region us-east-1 \
    --proxy-port 8000 \
    --aws-access-key-id ${ACCESS_KEY_ID} \
    --aws-secret-access-key ${SECRET_ACCESS_KEY} \
    --aws-session-token ${SESSION_TOKEN} \
    --length 1024

if [[ $? -eq 0 ]];then
    GENRANDOM_SUCCESS=1
else
    GENRANDOM_SUCCESS=0
fi

set -e

echo "======================================================================================"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                    TEST RESULT                                     |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "|                                                                                    |"
echo "======================================================================================"

if [[ ${DECRYPT_SUCCESS} == 1 ]]; then
    echo "Decrypt: SUCCESS"
else
    echo "Decrypt: FAIL"
fi

if [[ ${GENKEY_SUCCESS} == 1 ]]; then
    echo "GenKey: SUCCESS"
else
    echo "GenKey: FAIL"
fi

if [[ ${GENRANDOM_SUCCESS} == 1 ]]; then
    echo "GenRandom: SUCCESS"
else
    echo "GenRandom: FAIL"
fi

echo "================"
if [[ ${DECRYPT_SUCCESS} == 1 && ${GENKEY_SUCCESS} == 1 && ${GENRANDOM_SUCCESS} == 1 ]]; then
    echo "Status: SUCCESS"
else
    echo "Status: FAIL"
fi

# Wait before exit so the parent instance can inspect the log via console
sleep 10
