# AWS Nitro Enclaves SDK for C

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

## Dependencies
| name                       | version              | link                                              |
|----------------------------|----------------------|---------------------------------------------------|
| aws-lc                     | v0.1-beta            | https://github.com/awslabs/aws-lc/                |
| S2N                        | v0.10.21             | https://github.com/awslabs/s2n                    |
| aws-c-common               | v0.4.59              | https://github.com/awslabs/aws-c-common           |
| aws-c-io                   | v0.7.0               | https://github.com/awslabs/aws-c-io               |
| aws-c-compression          | v0.2.10              | https://github.com/awslabs/aws-c-compression       |
| aws-c-http                 | v0.5.17              | https://github.com/awslabs/aws-c-http             |
| aws-c-cal                  | v0.3.3               | https://github.com/awslabs/aws-c-cal              |
| aws-c-auth                 | v0.4.6               | https://github.com/awslabs/aws-c-auth             |
| aws-nitro-enclaves-nsm-api | v0.1.0               | https://github.com/aws/aws-nitro-enclaves-nsm-api |
| json-c                     | json-c-0.15-20200726 | https://github.com/json-c/json-c                  |

## Building

### Using containers:
The simplest way to use this SDK is by using one of the available containers as a base:
```
docker build -f --target builder -t aws-nitro-enclaves-sdk-c containers/Dockerfile.al2 .
```


## Samples
 * [kmstool](docs/kmstool.md)
 * [kmstool-enclave-cli](docs/kmstool.md#kmstool-enclave-cli)

