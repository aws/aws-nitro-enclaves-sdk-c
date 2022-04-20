# AWS Nitro Enclaves SDK for C

## License

This project is licensed under the Apache-2.0 License.

## Dependencies
| name                       | version              | link                                              |
|----------------------------|----------------------|---------------------------------------------------|
| aws-lc                     | v1.0.2               | https://github.com/awslabs/aws-lc/                |
| S2N                        | v1.3.11              | https://github.com/aws/s2n-tls.git                |
| aws-c-common               | v0.6.20              | https://github.com/awslabs/aws-c-common           |
| aws-c-sdkutils             | v0.1.2               | https://github.com/awslabs/aws-c-sdkutils         |
| aws-c-io                   | v0.10.21             | https://github.com/awslabs/aws-c-io               |
| aws-c-compression          | v0.2.14              | https://github.com/awslabs/aws-c-compression      |
| aws-c-http                 | v0.6.13              | https://github.com/awslabs/aws-c-http             |
| aws-c-cal                  | v0.5.17              | https://github.com/awslabs/aws-c-cal              |
| aws-c-auth                 | v0.6.11              | https://github.com/awslabs/aws-c-auth             |
| aws-nitro-enclaves-nsm-api | v0.2.1               | https://github.com/aws/aws-nitro-enclaves-nsm-api |
| json-c                     | json-c-0.16-20220414 | https://github.com/json-c/json-c                  |

## Building

### Linux - Using containers:
The simplest way to use this SDK is by using one of the available containers as a base:
```
docker build -f containers/Dockerfile.al2 --target builder -t aws-nitro-enclaves-sdk-c .
```

### Windows
Note that this SDK is currently not supported on Windows.  Only the client side sample application (kmstool_instance) is supported on Windows.

## Samples
 * [kmstool](docs/kmstool.md)
 * [kmstool-enclave-cli](docs/kmstool.md#kmstool-enclave-cli)

## Security issue notifications

If you discover a potential security issue in the Nitro Enclaves SDK for C, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.
