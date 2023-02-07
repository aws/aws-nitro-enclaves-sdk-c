# kmstool-enclave-cli

`kmstool-enclave-cli` is a rewrite version of `kmstool-enclave`.

The difference between two is that `kmstool-enclave-cli` doesn't communicate with `kmstool-instance`. Instead, it receive information, like AWS credential, ciphertext, etc. from command line input.

By doing that, this tool can be used by any programming langauge that can interact with shell console. Developers don't need to rewrite the tool in their own language. This improves the flexibilty of the tool.

## How to use it

1. Run the build script
   ```
   $ cd bin/kmstool-enclave-cli
   $ ./build.sh
   ```

1. Copy the generated files to your enclave application directory
   ```
   $ cp kmstool_enclave_cli <your_enclave_app_directory>/
   $ cp libnsm.so <your_enclave_app_directory>/
   ```

1. Modify your enclave applicaton `Dockerfile` to include those generated files. For example:
   ```
   COPY kmstool_enclave_cli ./
   COPY libnsm.so ./
   ```

   You can include `libnsm.so` by:

   1. Copying `libnsm.so` into the default library path depending your application's base image e.g. `/usr/lib64/`
   
   1. Setting library path environment variable before your enclave application start. E.g.
      ```
      $ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path_of_the_directory_containing_nsmlib.so>
      ```

1. Use any subprocess method from your chosen programming language to interact with `kmstool-enclave-cli`

   The **`decrypt`** call takes the following parameters:
   1. `decrypt` command

   2. `--region` AWS region to use for KMS

   3. `--proxy-port` Connect to KMS proxy on PORT. Default: 8000

   4. `--aws-access-key-id` AWS access key ID

   5. `--aws-secret-access-key` AWS secret access key

   6. `--aws-session-token` Session token associated with the access key ID

   7. `--ciphertext` Base64-encoded ciphertext that need to decrypt

   8. `--key-id KEY_ID` decrypt key id (for symmetric keys, is optional)

   9. `--encryption-algorithm` encryption algorithm for ciphertext (required if `--key-id` has been set)


   and outputs the base64-encoded plaintext with `PLAINTEXT: ` as prefix if the execution succeeds.

   ```shell
   PLAINTEXT: <base64-encoded plaintext>
   ```

   Below is an example for Python using `subprocess`

   ```
   proc = subprocess.Popen(
       [
           "/kmstool_enclave_cli",
           "decrypt",
           "--region", "us-east-1",
           "--proxy-port", "8000",
           "--aws-access-key-id", access_key_id,
           "--aws-secret-access-key", secret_access_key,
           "--aws-session-token", token,
           "--ciphertext", ciphertext,
       ],
       stdout=subprocess.PIPE
   )

   result_b64 = proc.communicate()[0].decode()
   plaintext_b64 = result.split(":")[1].strip()
   ```

   The **`genkey`** call takes the following parameters:
   1.  `genkey` command

   2. `--region` AWS region to use for KMS

   3. `--proxy-port` Connect to KMS proxy on PORT. Default: 8000

   4. `--aws-access-key-id` AWS access key ID

   5. `--aws-secret-access-key` AWS secret access key

   6. `--aws-session-token` Session token associated with the access key ID

   7. `--key-id` KMS key ID to be used

   8. `--key-spec` The key spec used to create the key (AES-256 or AES-128)

   and outputs the base64-encoded datakey with `CIPHERTEXT: ` as prefix if the execution succeeds.

   ```shell
   CIPHERTEXT: <base64-encoded datakey>
   ```

   Below is an example for Python using `subprocess`

   ```
   proc = subprocess.Popen(
       [
           "/kmstool_enclave_cli",
           "genkey",
           "--region", "us-east-1",
           "--proxy-port", "8000",
           "--aws-access-key-id", access_key_id,
           "--aws-secret-access-key", secret_access_key,
           "--aws-session-token", token,
           "--ciphertext", ciphertext,
       ],
       stdout=subprocess.PIPE
   )

   result_b64 = proc.communicate()[0].decode()
   plaintext_b64 = result_b64.split(":")[1].strip()
   ```
