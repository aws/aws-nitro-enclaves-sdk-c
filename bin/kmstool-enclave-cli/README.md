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

   1. The **`decrypt`** call takes the following parameters:
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

      ```python
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

      result = proc.communicate()[0].decode()
      plaintext_b64 = result.split(":")[1].strip()
      ```

   1. The **`genkey`** call takes the following parameters:
      1.  `genkey` command

      2. `--region` AWS region to use for KMS

      3. `--proxy-port` Connect to KMS proxy on PORT. Default: 8000

      4. `--aws-access-key-id` AWS access key ID

      5. `--aws-secret-access-key` AWS secret access key

      6. `--aws-session-token` Session token associated with the access key ID

      7. `--key-id` KMS key ID to be used

      8. `--key-spec` The key spec used to create the key (AES-256 or AES-128)

      and outputs the base64-encoded encrypted datakey with `CIPHERTEXT: ` as prefix, and base64-encoded plaintext datakey with `PLAINTEXT: ` as prefix if the execution succeeds.

      ```shell
      CIPHERTEXT: <base64-encoded encrypted datakey>
      PLAINTEXT: <base64-encoded plaintext datakey>
      ```

      Below is an example for Python using `subprocess`

      ```python
      proc = subprocess.Popen(
          [
              "/kmstool_enclave_cli",
              "genkey",
              "--region", "us-east-1",
              "--proxy-port", "8000",
              "--aws-access-key-id", access_key_id,
              "--aws-secret-access-key", secret_access_key,
              "--aws-session-token", token,
              "--key-id", key_id,
              "--key-spec", key_spec,
          ],
          stdout=subprocess.PIPE
      )

      result = proc.communicate()[0].decode()

      ciphertext_b64 = result.split("\n")[0].split(":")[1].strip()
      plaintext_b64 = result.split("\n")[1].split(":")[1].strip()
      ```

   1. The **`genrandom`** call takes the following parameters:
      1.  `genrandom` command

      2. `--region` AWS region to use for KMS

      3. `--proxy-port` Connect to KMS proxy on PORT. Default: 8000

      4. `--aws-access-key-id` AWS access key ID

      5. `--aws-secret-access-key` AWS secret access key

      6. `--aws-session-token` Session token associated with the access key ID

      7. `--length` The length of the random byte string (in bytes)

      and outputs the base64-encoded random bytes with `PLAINTEXT: ` as prefix if the execution succeeds.

      ```shell
      PLAINTEXT: <base64-encoded random bytes>
      ```

      Below is an example for Python using `subprocess`

      ```python
      proc = subprocess.Popen(
          [
              "/kmstool_enclave_cli",
              "genrandom",
              "--region", "us-east-1",
              "--proxy-port", "8000",
              "--aws-access-key-id", access_key_id,
              "--aws-secret-access-key", secret_access_key,
              "--aws-session-token", token,
              "--length", length,
          ],
          stdout=subprocess.PIPE
      )

      result = proc.communicate()[0].decode()
      plaintext_b64 = result.split(":")[1].strip()
      ```

## Troubleshooting

### Missing Common CA Certificates
If you are running `kmstool-enclave-cli` in an environment that does not have the common CA certificates installed, you will face the following error:
```shell
[ERROR] [2023-02-23T15:16:21Z] [00007efd15f94840] [tls-handler] - ctx: configuration error: Error initializing trust store (Error encountered in /tmp/crt-builder/s2n-tls/tls/s2n_x509_validator.c:120)
[ERROR] [2023-02-23T15:16:21Z] [00007efd15f94840] [tls-handler] - Failed to set ca_path: (null) and ca_file (null)
```

To solve the problem, use a docker image that has common CA certificates pre-installed like `amazonlinux:2023`. [`kmstool-enclave`](https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/docs/kmstool.md) explicitly gets the common CA certificates [installed during the build process](https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/containers/Dockerfile.al2#L90) to enable a minimal enclave build from [`scratch`](https://docs.docker.com/build/building/base-images/#create-a-simple-parent-image-using-scratch).

If you want to use a generic docker image with a smaller initial footprint, e.g. `debian:buster-slim`, you have to install the CA certificates during the docker build step similar to this:
```shell
RUN apt-get update && apt-get install -y ca-certificates
```