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

1. Use generate random API  
   
   `--region` AWS region to use for KMS

   `--proxy-port` Connect to KMS proxy on PORT. Default: 8000

   `--aws-access-key-id` AWS access key ID

   `--aws-secret-access-key` AWS secret access key

   `--aws-session-token` Session token associated with the access key ID

   `--number_of_bytes` The length of the random byte string. This parameter is required(1-1024)

   And output the base64-encoded plaintext if the execution success
   Output Sample:
   ```shell
   RANDOM: *********
   ```

   Below is an example for command line

   ```
           /kmstool_enclave_cli genrand 
           --region us-east-1 
           --proxy-port 8000 
           --aws-access-key-id access_key_id
           --aws-secret-access-key secret_access_key 
           --aws-session-token token
           --number_of_bytes 24
   ```
1. Use KMS decrypt API

   `--region` AWS region to use for KMS

   `--proxy-port` Connect to KMS proxy on PORT. Default: 8000

   `--aws-access-key-id` AWS access key ID

   `--aws-secret-access-key` AWS secret access key

   `--aws-session-token` Session token associated with the access key ID

   `--ciphertext` base64-encoded ciphertext that need to decrypt

   `--key-id` decrypt key id (for symmetric keys, is optional)

   `--encryption-algorithm` encryption algorithm for ciphertext

   And output the base64-encoded plaintext if the execution success
   
   Output Sample:
   ```shell
   PLAINTEXT: *********
   ```

   Below is an example for command line

   ```
           /kmstool_enclave_cli decrypt 
           --region us-east-1 
           --proxy-port 8000 
           --aws-access-key-id access_key_id
           --aws-secret-access-key secret_access_key 
           --aws-session-token token
           --ciphertext xxxxxx
           --key-id  xxxx
           --encryption-algorithm xxx
   ```
1. Use generate data key API

   `--region` AWS region to use for KMS

   `--proxy-port` Connect to KMS proxy on PORT. Default: 8000

   `--aws-access-key-id` AWS access key ID

   `--aws-secret-access-key` AWS secret access key

   `--aws-session-token` Session token associated with the access key ID

   `--key-id` KEY_ID: key id

   `--key-spec` KEY_SPEC: The key spec used to create the key (AES-256 or AES-128)

   And output the base64-encoded plaintext if the execution success
   Output Sample:
   ```shell
   CIPHERTEXT: **************
   PLAINTEXT: xxxxxxxx
   ```

   Below is an example for command line

   ```
           /kmstool_enclave_cli genrand 
           --region us-east-1 
           --proxy-port 8000 
           --aws-access-key-id access_key_id
           --aws-secret-access-key secret_access_key 
           --aws-session-token token
           --number_of_bytes 24
   ```
1. Python Sample code:
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
    stdout=subprocess.PIPE)
    plaintext = proc.communicate()[0].decode()
   ```
1. Java Sample Code:
```javascript
         String[] cmd = new String[] {
                 this.kmsToolEnvlaveCli,
                 "decrypt",
                 "--region", credential.getRegion(),
                 "--aws-access-key-id", credential.getAccessKeyId(),
                 "--aws-secret-access-key", credential.getSecretAccessKey(),
                 "--aws-session-token", credential.getSessionToken(),
                 "--ciphertext", content
         };
         ProcessBuilder builder = new ProcessBuilder(Arrays.asList(cmd));
         builder.inheritIO().redirectOutput(ProcessBuilder.Redirect.PIPE);
         Process process = builder.start();
         String procOutput = IOUtils.toString(process.getInputStream(), StandardCharsets.UTF_8);
```