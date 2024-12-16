# 0.4.2

Features:
* Extend kmstool-instance and kmstool-enclave to support Encryption Context from CLI arguments (fixes issues #35, #143)
* Add new API functions for Encrypt/Decrypt operations with context and prepared requests:
  - `aws_kms_decrypt_blocking_with_context`
  - `aws_kms_encrypt_blocking_with_context`
  - `aws_kms_encrypt_blocking_from_request`
  - `aws_kms_decrypt_blocking_from_request`
* Add `genrandom` command to kmstool-enclave-cli (fixes issue #131)

Fixes:
* Fix kmstool-enclave-cli test script location reference
* Apply stricter compilation options (-Wall, -Werror, -Wpedantic) to SDK library

Updates:
* Add test scripts for kmstool-enclave-cli
* Add test summary in smoke test script
* Add GitHub Actions workflow for building and running tests

Docs:
* Update kmstool documentation for Docker 24.x `vsock` socket restrictions
* Update README for kmstool-enclave-cli
  - Fix incorrect content on `genkey` command
  - Improve formatting
* Update success messages in test script README

# 0.4.1

Fixes:
* Containers: Fallback to older releases for some dependencies
  - Specifically, revert to aws-c-io v0.11.0 due to runtime issues in newer versions
  - This addresses a limitation described in https://github.com/awslabs/aws-c-io/issues/576

# 0.4.0

Updates:
* Update aws-nitro-enclaves-nsm-api from v0.3.0 to v0.4.0
* Update Rust version to 1.63 in containers (fixes issue #115)
* Use shallow clones for dependencies to reduce build time
* Update multiple dependencies and README.md file

Fixes:
* Fix build failures related to `CBS_get_any_ber_asn1_element` function

Changes:
* Replace DockerHub images with AWS ECR images to avoid rate limiting

# 0.3.2

Fixes:
* re-add support of `--key-id` to kmstool-enclave-cli

Updates:
* Update aws-nitro-enclaves-nsm-api dependency

Documentation:
* Update README for kmstool-enclave-cli and add troubleshooting section

Other:
* add test scripts

# 0.3.1

Features:
* Added GenerateDataKey option to kmstool-enclave-cli

Fixes:
* Miscellaneous fixes and optimizations

Updates:
* Updated dependencies to newer versions

# 0.3.0

Features:
* Add key-id and algorithm to kmstool-enclave-cli

Fixes:
* Cleanup secrets securely

# 0.2.1

Features:
* kmstool-enclave: allow endpoint configuration
* kms: add host_name override for endpoint.
* rest: add user-agent string

Fixes:
* kms: allow unknown fields in KMS response

Updates:
* update aws-nitro-enclaves-nsm-api
* containers: update rust version
* update dependencies
* deps: update aws-lc to v1.0.2

Docs:
* Add "Security Issue Notifications" section to README
