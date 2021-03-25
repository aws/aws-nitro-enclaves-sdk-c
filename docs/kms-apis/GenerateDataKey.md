# GenerateDataKey

Generates a unique symmetric data key for client-side encryption. This operation returns a plaintext copy of the data
key and a copy that is encrypted under a customer master key (CMK) that you specify. You can use the plaintext key to
encrypt your data outside of AWS KMS and store the encrypted data key with the encrypted data.

`GenerateDataKey` returns a unique data key for each request. The bytes in the plaintext key are not related to the
caller or the CMK.

To generate a data key, specify the symmetric CMK that will be used to encrypt the data key. You cannot use an
asymmetric CMK to generate data keys. To get the type of your CMK, use the
[DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) operation. You must also
specify the length of the data key. Use either the `KeySpec` or `NumberOfBytes` parameters (but not both). For 128-bit
and 256-bit data keys, use the `KeySpec` parameter.

To get only an encrypted copy of the data key, use
[GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).
To generate an asymmetric data key pair, use the
[GenerateDataKeyPair](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html) or
[GenerateDataKeyPairWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPairWithoutPlaintext.html)
operation. To get a cryptographically secure random byte string, use
[GenerateRandom](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateRandom.html).

You can use the optional encryption context to add additional security to the encryption operation. If you specify an
`EncryptionContext`, you must specify the same encryption context (a case-sensitive exact match) when decrypting the
encrypted data key. Otherwise, the request to decrypt fails with an `InvalidCiphertextException`. For more
information, see [Encryption
Context](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context) in the *AWS Key
Management Service Developer Guide*.

The CMK that you use for this operation must be in a compatible key state. For details, see [Key state: Effect on your
CMK](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html) in the *AWS Key Management Service
Developer Guide*.

##### How to use your data key

We recommend that you use the following pattern to encrypt data locally in your application. You can write your own
code or use a client-side encryption library, such as the [AWS Encryption
SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/), the [Amazon DynamoDB Encryption
Client](https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/), or [Amazon S3 client-side
encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingClientSideEncryption.html) to do these tasks for you.

To encrypt data outside of AWS KMS:

1. Use the `GenerateDataKey` operation to get a data key.

2. Use the plaintext data key (in the `Plaintext` field of the response) to encrypt your data outside of AWS KMS. Then
   erase the plaintext data key from memory.

3. Store the encrypted data key (in the `CiphertextBlob` field of the response) with the encrypted data.

To decrypt data outside of AWS KMS:

1. Use the [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) operation to decrypt the
   encrypted data key. The operation returns a plaintext copy of the data key.

2. Use the plaintext data key to decrypt data outside of AWS KMS, then erase the plaintext data key from memory.

**Cross-account use**: Yes. To perform this operation with a CMK in a different AWS account, specify the key ARN or alias ARN in the value of the `KeyId` parameter.

**Required permissions**: [kms:GenerateDataKey](https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html) (key policy)

Related operations:
* [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html)

* [Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html)

* [GenerateDataKeyPair](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html)

* [GenerateDataKeyPairWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPairWithoutPlaintext.html)

* [GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html)

## Request Syntax
```json
{
   "EncryptionContext": { 
      "string" : "string" 
   },
   "GrantTokens": [ "string" ],
   "KeyId": "string",
   "KeySpec": "string",
   "NumberOfBytes": number,
   "Recipient": { 
      "AttestationDocument": blob,
      "KeyEncryptionAlgorithm": "string"
   }
}
```

## Request Parameters

For information about the parameters that are common to all actions, see [Common
Parameters](https://docs.aws.amazon.com/kms/latest/APIReference/CommonParameters.html).

The request accepts the following data in JSON format.
> **Note**
>
> In the following list, the required parameters are described first.

#### KeyId

Identifies the symmetric CMK that encrypts the data key.

To specify a CMK, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. When using an alias name,
prefix it with `"alias/"`. To specify a CMK in a different AWS account, you must use the key ARN or alias ARN.

For example:

* Key ID: `1234abcd-12ab-34cd-56ef-1234567890ab`

* Key ARN: `arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`

* Alias name: `alias/ExampleAlias`

* Alias ARN: `arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`

To get the key ID and key ARN for a CMK, use [ListKeys](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html) or [DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html). To get the alias name and alias ARN, use [ListAliases](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListAliases.html).

Type: String

Length Constraints: Minimum length of 1. Maximum length of 2048.

Required: Yes

#### EncryptionContext

Specifies the encryption context that will be used when encrypting the data key.

An *encryption context* is a collection of non-secret key-value pairs that represents additional authenticated data.
When you use an encryption context to encrypt data, you must specify the same (an exact case-sensitive match)
encryption context to decrypt the data. An encryption context is optional when encrypting with a symmetric CMK, but it
is highly recommended.

For more information, see [Encryption
Context](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context) in the *AWS Key
Management Service Developer Guide*.

Type: String to string map

Required: No
    
#### GrantTokens

A list of grant tokens.

Use a grant token when your permission to call this operation comes from a new grant that has not yet achieved
*eventual consistency*. For more information, see [Grant
token](https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token) in the *AWS Key
Management Service Developer Guide*.

Type: Array of strings

Array Members: Minimum number of 0 items. Maximum number of 10 items.

Length Constraints: Minimum length of 1. Maximum length of 8192.

Required: No
    
#### KeySpec

Specifies the length of the data key. Use `AES_128` to generate a 128-bit symmetric key, or `AES_256` to generate a
256-bit symmetric key.

You must specify either the `KeySpec` or the `NumberOfBytes` parameter (but not both) in every `GenerateDataKey`
request.

Type: String

Required: No
    
#### NumberOfBytes

Specifies the length of the data key in bytes. For example, use the value 64 to generate a 512-bit data key (64 bytes
is 512 bits). For 128-bit (16-byte) and 256-bit (32-byte) data keys, use the `KeySpec` parameter.

You must specify either the `KeySpec` or the `NumberOfBytes` parameter (but not both) in every `GenerateDataKey` request.

Type: Integer

Valid Range: Minimum value of 1. Maximum value of 1024.

Required: No

#### Recipient

When `Recipient` is included in the request, the response will contain `CiphertextForRecipient` instead of
`Plaintext`, and the response is encrypted with the public key included in the `AttestationDocument` parameter.

If `Recipient` is specified in the request, then it must contain the `AttestationDocument` and
`KeyEncryptionAlgorithm`.

Type: [RecipientRequest](./RecipientRequest.md) object

Required: No


## Response Syntax
```json
{
   "CiphertextBlob": blob,
   "CiphertextForRecipient": blob,
   "KeyId": "string",
   "Plaintext": blob
}
```
## Response Elements

If the action is successful, the service sends back an HTTP 200 response.

The following data is returned in JSON format by the service.

#### CiphertextBlob

The encrypted copy of the data key. When you use the HTTP API or the AWS CLI, the value is Base64-encoded. Otherwise,
it is not Base64-encoded.

Type: Base64-encoded binary data object

Length Constraints: Minimum length of 1. Maximum length of 6144.

#### KeyId

The Amazon Resource Name ([key
ARN](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN)) of the CMK that encrypted
the data key.

Type: String

Length Constraints: Minimum length of 1. Maximum length of 2048.

#### Plaintext

The plaintext data key. When you use the HTTP API or the AWS CLI, the value is Base64-encoded. Otherwise, it is not
Base64-encoded. Use this data key to encrypt your data outside of KMS. Then, remove it from memory as soon as
possible.

Type: Base64-encoded binary data object

Length Constraints: Minimum length of 1. Maximum length of 4096.

#### CiphertextForRecipient

If `Recipient` is specified in the Request, then `CiphertextForRecipient` is returned instead of `Plaintext`, which
the requester has to decrypt with the private key corresponding to the public key contained in the `Recipient`'s
`AttestationDocument` field.

`CiphertextForRecipient` is a RecipientInfo structure, as described in [RFC5652 Section
6](https://tools.ietf.org/html/rfc5652#section-6) encoded as Base64.

Type: Base64-encoded binary data object.

Length Constraints: Minimum length of 1. Maximum length of 6144.

## Errors

For information about the errors that are common to all actions, see Common Errors.

#### DependencyTimeoutException

The system timed out while trying to fulfill the request. The request can be retried.

HTTP Status Code: 500

#### DisabledException

The request was rejected because the specified CMK is not enabled.

HTTP Status Code: 400

#### InvalidGrantTokenException

The request was rejected because the specified grant token is not valid.

HTTP Status Code: 400

#### InvalidKeyUsageException

The request was rejected for one of the following reasons:

* The `KeyUsage` value of the CMK is incompatible with the API operation.

* The encryption algorithm or signing algorithm specified for the operation is incompatible with the type of key
  material in the CMK (`CustomerMasterKeySpec`).

For encrypting, decrypting, re-encrypting, and generating data keys, the `KeyUsage` must be `ENCRYPT_DECRYPT`. For
signing and verifying, the `KeyUsage` must be `SIGN_VERIFY`. To find the `KeyUsage` of a CMK, use the
[DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) operation.

To find the encryption or signing algorithms supported for a particular CMK, use the
[DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) operation.

HTTP Status Code: 400

#### KeyUnavailableException

The request was rejected because the specified CMK was not available. You can retry the request.

HTTP Status Code: 500

#### KMSInternalException

The request was rejected because an internal exception occurred. The request can be retried.

HTTP Status Code: 500

#### KMSInvalidStateException

The request was rejected because the state of the specified resource is not valid for this request.

For more information about how key state affects the use of a CMK, see [How Key State Affects Use of a Customer Master
Key](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html) in the *AWS Key Management Service
Developer Guide*.

HTTP Status Code: 400

#### NotFoundException

The request was rejected because the specified entity or resource could not be found.

HTTP Status Code: 400

## Examples

The following examples are formatted for legibility.
### Example Request

This example illustrates one usage of GenerateDataKey.
```http
POST / HTTP/1.1
Host: kms.us-east-2.amazonaws.com
Content-Length: 50
X-Amz-Target: TrentService.GenerateDataKey
X-Amz-Date: 20161112T000940Z
Content-Type: application/x-amz-json-1.1
Authorization: AWS4-HMAC-SHA256\
 Credential=AKIAI44QH8DHBEXAMPLE/20161112/us-east-2/kms/aws4_request,\
 SignedHeaders=content-type;host;x-amz-date;x-amz-target,\
 Signature=815ac4ccbb5c53b8ca015f979704c7953bb0068bf53f4e0b7c6886ed5b0a8fe4

{
  "KeyId": "alias/ExampleAlias",
  "KeySpec": "AES_256"
}
```
### Example Response

This example illustrates one usage of GenerateDataKey.
```http
HTTP/1.1 200 OK
Server: Server
Date: Sat, 12 Nov 2016 00:09:40 GMT
Content-Type: application/x-amz-json-1.1
Content-Length: 390
Connection: keep-alive
x-amzn-RequestId: 4e6fc242-a86c-11e6-aff0-8333261e2fbd

{
  "CiphertextBlob": "AQEDAHjRYf5WytIc0C857tFSnBaPn2F8DgfmThbJlGfR8P3WlwAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEFogLqPWZconQhwHAIBEIA7d9AC7GeJJM34njQvg4Wf1d5sw0NIo1MrBqZa+YdhV8MrkBQPeac0ReRVNDt9qleAt+SHgIRF8P0H+7U=",
  "KeyId": "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
  "Plaintext": "VdzKNHGzUAzJeRBVY+uUmofUGGiDzyB3+i9fVkh3piw="
}
```
