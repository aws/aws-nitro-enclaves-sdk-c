# KMS Tool

KMS Tool is a small example application for aws-nitro-enclaves-sdk-c that is
able to connect to KMS and decrypt an encrypted KMS message.

This application has two parts:

1. **kmstool-enclave** is the application that runs in an enclave and
calls the KMS using attestation, decrypting a message received from the
instance side. Since this is a sample, it only allows one connection at
a time, in order to simplify the workflow.  This is supported only on Linux.

2. **kmstool-instance** runs on the instance and connects to
**kmstool-enclave**, passing credentials to the enclave and then
requesting that the enclave decrypt a base64-encoded message.

The protocol between the two sides is based on a standard `AF_VSOCK` socket
(similar to any posix SOCK_STREAM socket) and a simple JSON schema,
with messages separated by the 0 byte.

There are two message types:

1. command: This is the message sent by **kmstool-instance** to the
enclave, and contains an `Operation` field that can be
`SetClient` or `Decrypt`.
    1. `SetClient` operation requires `AwsAccessKeyId` and
`AwsSecretAccessKey` fields to be set to the corresponding
IAM Credentials, as well as `AwsSessionToken` if available.
Additionaly, it can specify `AwsRegion` to allow client to change region, if
enclave does not already have a specific region set. If neither side sets a
specific region, "us-east-1" is used.
Example: `{"Operation": "SetClient", "AwsAccessKeyId": "AKIAIOSFODNN7EXAMPLE",
"AwsSecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AwsRegion": "us-east-1"}`.
    2. `Decrypt` operation requires a `Ciphertext` fields to be set.
Ciphertext is a base64-encoded bytestream that is the result of a KMS Encrypt operation.
Example: `{"Operation": "Decrypt", "Ciphertext": "AQICAHiFvOgLomqhXP8y..NkRa4CGQ=="}`
2. reply: This message is set by **kmstool-enclave** after the execution of
a command. It always contains a `Status` that is either `Ok` or `Error` and it
can optionally include a `Message`. If `Status` is `Ok` and the command was
`Decrypt`, `Message` contains the result. If `Status` is `Error`, `Message`
might contain a description of the error.

## Prerequisites - Linux
To run Nitro Enclaves and follow this guide, you will need an enclave-enabled
EC2 instance. It's recommended to use an up-to-date Amazon Linux 2 AMI for this
purpose, as the repositories already provide the required packages.
Follow the documentation on how to start an instance
[here](https://docs.aws.amazon.com/enclaves/latest/user/create-enclave.html#launch-parent).

The next steps will be run inside that instance.
The guide will also assume you have an IAM role attached to the instance.

Nitro Enclaves can be built from a docker container, alongside a kernel and
an init process. For this step you need to install
[docker](https://docs.docker.com/get-docker/) and
[aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli/).

On Amazon Linux 2, you can run:
```sh
sudo amazon-linux-extras install docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -a -G docker ec2-user
sudo amazon-linux-extras enable aws-nitro-enclaves-cli
sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
```

On other Linux distros, you will have to compile aws-nitro-enclaves-cli from
source. Follow the
[guide](https://github.com/aws/aws-nitro-enclaves-cli/blob/master/README.md)
in the repo.

## Prerequisites - Windows
The enclave image file used for this sample must be built following the Linux build steps.
Building the image for the enclave is not supported on Windows.
The enclave image build steps will be run on Linux. Once you have the EIF file, 
copy it over to an enclave-enabled EC2 instance running Windows.

Follow the documentation on how to start a Windows EC2 instance
[here](https://docs.aws.amazon.com/enclaves/latest/user/create-enclave.html#launch-parent).

To build the kmstool-instance sample on Windows, you will need to install 
visual studio build tools, cmake and git.  These can be installed using [Chocolatey](https://chocolatey.org/install).
Installation requires administrator privileges. Once you have Chocolatey installed, install the tools needed for build by running:
```powershell
choco install visualcpp-build-tools -y
choco install cmake -y
choco install git -y
```
To run enclaves on Windows, you will need to install
[aws-nitro-enclaves-cli](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install-win.html).
This will install the necessary drivers, vsock-proxy, vsock service provider, and nitro-cli.

## Building

To build the enclave, there is an already provided Dockerfile: 
[Dockerfile.al2](../containers/Dockerfile.al2). From the root of
this repo run:

```sh
docker build --target kmstool-instance -t kmstool-instance -f containers/Dockerfile.al2 .
docker build --target kmstool-enclave -t kmstool-enclave -f containers/Dockerfile.al2 .
```

This builds the container to be run in the enclave, as well as a container
that has kmstool-instance and tags them appropriately.

Next, you will have to build the EIF (Enclave Image Format) which is the bootable enclave format:
```sh
nitro-cli build-enclave --docker-uri kmstool-enclave --output-file kmstool.eif
```

If this step succeeds, you will get an output similar to:
```
Enclave Image successfully created.
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "287b24930a9f0fe14b01a71ecdc00d8be8fad90f9834d547158854b8279c74095c43f8d7f047714e98deb7903f20e3dd",
    "PCR1": "aca6e62ffbf5f7deccac452d7f8cee1b94048faf62afc16c8ab68c9fed8c38010c73a669f9a36e596032f0b973d21895",
    "PCR2": "0315f483ae1220b5e023d8c80ff1e135edcca277e70860c31f3003b36e3b2aaec5d043c9ce3a679e3bbd5b3b93b61d6f"
  }
}
```

Save the value of PCR0, as this will be relevant in the KMS policy that will be created in the `Set up KMS` section.
If you intend to run the enclave on Windows, copy the EIF file to the Windows instance.

## Building kmstool-instance on Windows

kmstool-instance can be built using the build.ps1 PowerShell script.
To build run:
```powershell
.\build.ps1 -BuildEverything $true
```
This will clone the needed dependencies and compile everything, generating kmstool_instance.exe.
You can find this under this path: `.\buildbase\KmsToolInstall\release\bin`

## Set up KMS

To test, you will need to create a KMS CMK with a specific policy that allows
the enclave to do KMS Decrypt, but does not allow others to do so. Your EC2
Instance Role will need to have permission to create an AWS KMS key (but
consider using another role for this purpose, as a best practice). Do not give
your AWS KMS Instance Role the ability to encrypt or decrypt, this will be done
through the Key Policy.
You can find out more about AWS KMS Key Policies in the
[AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html).

Write the following policy to `test-enclave-policy.json` file, where you have to replace:
 * `INSTANCE_ROLE_ARN` to the role that you associated with your instance
 * `KMS_ADMINISTRATOR_ROLE` to the role that is allowed to administer the KMS key.
*Note*: In practice, `INSTANCE_ROLE_ARN` and `KMS_ADMINISTRATOR_ROLE` should be
separate, but for the purpose of this tutorial they can be the same.

Please notice that "kms:RecipientAttestation:ImageSha384" is set to
"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".
This value is a hex number coresponding to the hash over the bootable parts of
the EIF. In debug mode it's always 0, to diferentiate between production-mode
and debug-mode enclaves. It is equivalent to PCR0 that is returned when
building the enclave and can also be set with the
"kms:RecipientAttestation:PCR0" key in the policy.

```
{
  "Version" : "2012-10-17",
  "Id" : "key-default-1",
  "Statement" : [
  {
    "Sid" : "Enable decrypt from enclave",
    "Effect" : "Allow",
    "Principal" : { "AWS" : INSTANCE_ROLE_ARN },
    "Action" : "kms:Decrypt",
    "Resource" : "*",
    "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:ImageSha384": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        }
    }
  },
  {
    "Sid" : "Enable encrypt from instance",
    "Effect" : "Allow",
    "Principal" : { "AWS" : INSTANCE_ROLE_ARN },
    "Action" : "kms:Encrypt",
    "Resource" : "*"
  },
  {
    "Sid": "Allow access for Key Administrators",
    "Effect": "Allow",
    "Principal": {"AWS": KMS_ADMINISTRATOR_ROLE },
    "Action": [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
    ],
    "Resource": "*"
  }
 ]
}
```

Create a KMS key: 
```sh
KMS_KEY_ARN=$(aws kms create-key --description "Nitro Enclaves Test Key" --policy file://test-enclave-policy.json --query KeyMetadata.Arn --output text)
echo $KMS_KEY_ARN
```

## Encrypt test message

Encrypt some data: 
```sh
MESSAGE="Hello, KMS\!"
CIPHERTEXT=$(aws kms encrypt --key-id "$KMS_KEY_ARN" --plaintext "$MESSAGE" --query CiphertextBlob --output text)
echo $CIPHERTEXT
```

On Windows, set the $KeyArn variable to the arn created in `Set up KMS` section and use AWS PowerShell tools to encrypt:
```powershell
$Message = "Hello, KMS!"
$CipherText = [System.Convert]::ToBase64String($(Invoke-KMSEncrypt -Plaintext $Message -KeyId $KeyArn -Select CiphertextBlob).ToArray())
```

### Security considerations
Here we allow the instance to only encrypt and the enclave to only decrypt,
and the root user of the account to do everything. Please read through [KMS
Security Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/kms-security.html)
and [Security Best Practices for Nitro Enclaves with KMS](https://docs.aws.amazon.com/enclaves/latest/user/security.html)
for securing and managing production applications.

## Running in debug mode

The instructions for running the sample are given for both Linux and Windows.
Windows instructions are preceded with `PowerShell`

Start the enclave:
```sh
nitro-cli run-enclave --eif-path kmstool.eif --memory 512 --cpu-count 2 --debug-mode
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r .[0].EnclaveID)
# Connect to the enclave's terminal
nitro-cli console --enclave-id $ENCLAVE_ID
```
PowerShell:
```powershell
nitro-cli run-enclave --eif-path kmstool.eif --memory 512 --cpu-count 2 --debug-mode
$EnclaveID=$(nitro-cli describe-enclaves | ConvertFrom-Json).EnclaveID
```

Start vsock-proxy on port 8000. This allows the enclave egress to
kms.us-east-1.amazonaws.com. To change regions, you will need to update the `CMK_REGION` variable,
and also change the region for the client similarly. You can find more details
[here](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md).

```sh
CMK_REGION=us-east-1 # The region where you created your AWS KMS CMK
vsock-proxy 8000 kms.$CMK_REGION.amazonaws.com 443
```
PowerShell:
```powershell
$CMK_REGION="us-east-1" # the region where you created your AWS KMS CMK
vsock-proxy 8000 kms.$CMK_REGION.amazonaws.com 443
```

In a separate terminal or PowerShell, connected to the instance:
```sh
CMK_REGION=us-east-1 # Must match above
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r .[0].EnclaveCID)
# Run docker with network host to allow it to fetch IAM credentials with IMDSv2
docker run --network host -it kmstool-instance \
    /kmstool_instance --cid "$ENCLAVE_CID" --region "$CMK_REGION" "$CIPHERTEXT"
```
PowerShell:
```powershell
$CMK_REGION="us-east-1" # Must match above
$EnclaveCID=$(nitro-cli describe-enclaves | ConvertFrom-Json).EnclaveCID
kmstool_instance --cid $EnclaveCID --region $CMK_REGION
```

At the end, you should be able to get back the message set above, in this case,
"Hello, KMS!".

## Running in production mode

Once you have tested the enclave and confirmed it worked in debug mode, you are
ready to switch to production mode and limit access to only your enclave.
You should create a new key with an updated policy, just as before, but with
the condition updateded to match the output received from building the EIF previously.
Please replace PCR0_VALUE_FROM_EIF_BUILD to reflect PCR0 value received during that
step. If you don't remember what it is, you can rebuild the image. The output should
be identical.

`enclave-policy.json`: 
```
{
  "Version" : "2012-10-17",
  "Id" : "key-default-1",
  "Statement" : [
  {
    "Sid" : "Enable decrypt from enclave",
    "Effect" : "Allow",
    "Principal" : { "AWS" : INSTANCE_ROLE_ARN },
    "Action" : "kms:Decrypt",
    "Resource" : "*",
    "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:ImageSha384": PCR0_VALUE_FROM_EIF_BUILD
        }
    }
  },
  {
    "Sid" : "Enable encrypt from instance",
    "Effect" : "Allow",
    "Principal" : { "AWS" : INSTANCE_ROLE_ARN },
    "Action" : "kms:Encrypt",
    "Resource" : "*"
  },
  {
    "Sid": "Allow access for Key Administrators",
    "Effect": "Allow",
    "Principal": {"AWS": KMS_ADMINISTRATOR_ROLE },
    "Action": [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
    ],
    "Resource": "*"
  }
 ]
}
```

```sh
KMS_KEY_ARN=$(aws kms create-key --description "Nitro Enclaves Production Key" --policy file://test-enclave-policy.json --query KeyMetadata.Arn --output text)
```

From this point forward, all steps are the same, except that you will not be able
to connect to the console of the enclave.

## kmstool-enclave-cli
There is a rewrite version of **kmstool-enclave** that run as a standalone application, which can directly interact with different application running in an enclave.
See more detail in `bin/kmstool-enclave-cli`

## Troubleshooting

### Connectivity issues
If you get back `Object = { "Status": "Error", "Message": "Could not create new client" }`
from kmstool-instance there are a few reasons why this might happen:
1. vsock-proxy is not running. Check [Running in debug mode](#running-in-debug-mode)
section for information on how to set it up.
2. Region mismatch between vsock-proxy and kmstool. This failure also shows
`AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE` in the enclave console. Check
[Running in debug mode](#running-in-debug-mode) section for information
on how to set up the connections.
