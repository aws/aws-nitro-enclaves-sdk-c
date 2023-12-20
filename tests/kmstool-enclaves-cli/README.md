# Test script for kmstool-enclave-cli

## Pre-requisites

* An EC2 instance:

   * With Nitro Enclaves support

   * Running Amazon Linux 2023

   * An IAM role attached, with the following permissions:

      * `kms:Decrypt`
      * `kms:GenerateRandom`
      * `kms:GenerateDataKey`
      * `kms:Encrypt`

* A KMS key which the enclave in the EC2 instance has permission to perform the following actions:

   * `kms:Decrypt`
   * `kms:GenerateDataKey`

   If `kms:RecipientAttestation` condition is set in the key policy, make sure it's set to `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`

## Testing steps

1. Run the following scripts on the EC2 instance to install the pre-requisite softwares:

   ```bash
   yum install -y aws-nitro-enclaves-cli-devel aws-nitro-enclaves-cli socat
   
   cat <<EOF > /etc/nitro_enclaves/allocator.yaml
   ---
   # Enclave configuration file.
   #
   # How much memory to allocate for enclaves (in MiB).
   memory_mib: 2048
   #
   # How many CPUs to reserve for enclaves.
   cpu_count: 2
   #
   # Alternatively, the exact CPUs to be reserved for the enclave can be explicitely
   # configured by using ``cpu_pool`` (like below), instead of ``cpu_count``.
   # Note: cpu_count and cpu_pool conflict with each other. Only use exactly one of them.
   # Example of reserving CPUs 2, 3, and 6 through 9:
   # cpu_pool: 2,3,6-9
   EOF
   
   systemctl enable --now nitro-enclaves-allocator.service
   systemctl enable --now docker
   ```

1. Clone this repository

1. Run the test script:

   ```bash
   export KMS_KEY_ARN=<kms_key_arn>
   tests/kmstool-enclaves-cli/test_cli.sh
   ```

1. If all test cases pass, the console will show the following:

   ```
   ======================================================================================
   |                                                                                    |
   |                                                                                    |
   |                                                                                    |
   |                                                                                    |
   |                                                                                    |
   |                                    TEST RESULT                                     |
   |                                                                                    |
   |                                                                                    |
   |                                                                                    |
   |                                                                                    |
   |                                                                                    |
   ======================================================================================
   Decrypt: SUCCESS
   GenKey: SUCCESS
   GenRandom: SUCCESS
   ================
   Status: SUCCESS
   ```
