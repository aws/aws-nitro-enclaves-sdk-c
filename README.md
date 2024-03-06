# AWS Nitro Enclaves SDK for C

## License

This project is licensed under the Apache-2.0 License.

## Dependencies
| name                       | version              | link                                              |
|----------------------------|----------------------|---------------------------------------------------|
| aws-lc                     | v1.12.0              | https://github.com/awslabs/aws-lc/                |
| s2n-tls                    | v1.3.46              | https://github.com/aws/s2n-tls.git                |
| aws-c-common               | v0.8.0               | https://github.com/awslabs/aws-c-common           |
| aws-c-sdkutils             | v0.1.2               | https://github.com/awslabs/aws-c-sdkutils         |
| aws-c-io                   | v0.11.0              | https://github.com/awslabs/aws-c-io               |
| aws-c-compression          | v0.2.14              | https://github.com/awslabs/aws-c-compression      |
| aws-c-http                 | v0.7.6               | https://github.com/awslabs/aws-c-http             |
| aws-c-cal                  | v0.5.18              | https://github.com/awslabs/aws-c-cal              |
| aws-c-auth                 | v6.15.0              | https://github.com/awslabs/aws-c-auth             |
| aws-nitro-enclaves-nsm-api | v0.4.0               | https://github.com/aws/aws-nitro-enclaves-nsm-api |
| json-c                     | json-c-0.16-20220414 | https://github.com/json-c/json-c                  |

## Building

### Linux - Using containers:
The simplest way to use this SDK is by using one of the available containers as a base:
```
docker build -f containers/Dockerfile.al2 --target builder -t aws-nitro-enclaves-sdk-c .
```

### Windows
Note that this SDK is currently not supported on Windows.

## Samples
 * [kmstool-enclave-cli](bin/kmstool-enclave-cli/README.md)

## Security issue notifications

If you discover a potential security issue in the Nitro Enclaves SDK for C, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.
