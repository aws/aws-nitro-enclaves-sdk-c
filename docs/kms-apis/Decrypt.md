# Decrypt


Decrypts ciphertext that was encrypted by a AWS KMS customer master key (CMK) using any of the following operations:

* [Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html)
* [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
* [GenerateDataKeyPair](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html)
* [GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html)
* [GenerateDataKeyPairWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPairWithoutPlaintext.html)

You can use this operation to decrypt ciphertext that was encrypted under a
symmetric or asymmetric CMK. When the CMK is asymmetric, you must specify the
CMK and the encryption algorithm that was used to encrypt the ciphertext. For
information about symmetric and asymmetric CMKs, see [Using Symmetric and
Asymmetric CMKs](https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html)
in the *AWS Key Management Service Developer Guide*.

The `Decrypt` operation also decrypts ciphertext that was encrypted outside of AWS KMS by the public key in an AWS KMS
asymmetric CMK. However, it cannot decrypt ciphertext produced by other libraries, such as the [AWS Encryption
SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/) or [Amazon S3 client-side
encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingClientSideEncryption.html). These libraries return a
ciphertext format that is incompatible with AWS KMS.

If the ciphertext was encrypted under a symmetric CMK, the `KeyId` parameter is optional. AWS KMS can get this
information from metadata that it adds to the symmetric ciphertext blob. This feature adds durability to your
implementation by ensuring that authorized users can decrypt ciphertext decades after it was encrypted, even if
they've lost track of the CMK ID. However, specifying the CMK is always recommended as a best practice. When you use
the `KeyId` parameter to specify a CMK, AWS KMS only uses the CMK you specify. If the ciphertext was encrypted under a
different CMK, the `Decrypt` operation fails. This practice ensures that you use the CMK that you intend.

Whenever possible, use key policies to give users permissions to call the `Decrypt` operation on a particular CMK,
instead of using IAM policies. Otherwise, you might create an IAM user policy that gives the user `Decrypt` permission
on all CMKs. This user could decrypt ciphertext that was encrypted by CMKs in other accounts if the key policy for the
cross-account CMK permits it. If you must use an IAM policy for `Decrypt` permissions, limit the user to particular
CMKs or particular trusted accounts. For details, see [Best practices for IAM
policies](https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies.html#iam-policies-best-practices) in the
*AWS Key Management Service Developer Guide*.

The CMK that you use for this operation must be in a compatible key state. For details, see [Key state: Effect on your
CMK](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html) in the *AWS Key Management Service
Developer Guide*.

**Cross-account use**: Yes. You can decrypt a ciphertext using a CMK in a different AWS account.

**Required permissions**: [kms:Decrypt](https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html) (key policy)

**Related operations**:
* [Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html)
* [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html)
* [GenerateDataKeyPair](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html)
* [ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)

## Request Syntax
```json
{
   "CiphertextBlob": blob,
   "EncryptionAlgorithm": "string",
   "EncryptionContext": { 
      "string" : "string" 
   },
   "GrantTokens": [ "string" ],
   "KeyId": "string"
}
```

## Request Parameters

For information about the parameters that are common to all actions, see
[Common Parameters](https://docs.aws.amazon.com/kms/latest/APIReference/CommonParameters.html).

The request accepts the following data in JSON format.

> **Note**  
> In the following list, the required parameters are described first.

#### CiphertextBlob

 Ciphertext to be decrypted. The blob includes metadata.

Type: Base64-encoded binary data object

Length Constraints: Minimum length of 1. Maximum length of 6144.

Required: Yes

#### EncryptionAlgorithm

Specifies the encryption algorithm that will be used to decrypt the ciphertext. Specify the same algorithm that was
used to encrypt the data. If you specify a different algorithm, the `Decrypt` operation fails.

This parameter is required only when the ciphertext was encrypted under an asymmetric CMK. The default value,
`SYMMETRIC_DEFAULT`, represents the only supported algorithm that is valid for symmetric CMKs.

Type: String

Valid Values: `SYMMETRIC_DEFAULT | RSAES_OAEP_SHA_1 | RSAES_OAEP_SHA_256`

Required: No

#### EncryptionContext

Specifies the encryption context to use when decrypting the data. An encryption context is valid only for
[cryptographic
operations](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations) with a
symmetric CMK. The standard asymmetric encryption algorithms that AWS KMS uses do not support an encryption context.

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

Use a grant token when your permission to call this operation comes from a newly created grant that has not yet
achieved eventual consistency. Use a grant token when your permission to call this operation comes from a new grant
that has not yet achieved eventual consistency. For more information, see [Grant
token](https://docs.aws.amazon.com/kms/latest/developerguide/grant-manage.html#using-grant-token) in the *AWS Key
Management Service Developer Guide*.

Type: Array of strings

Array Members: Minimum number of 0 items. Maximum number of 10 items.

Length Constraints: Minimum length of 1. Maximum length of 8192.

Required: No

#### KeyId

Specifies the customer master key (CMK) that AWS KMS uses to decrypt the ciphertext. Enter a key ID of the CMK that was used to encrypt the ciphertext.

This parameter is required only when the ciphertext was encrypted under an asymmetric CMK. If you used a symmetric
CMK, AWS KMS can get the CMK from metadata that it adds to the symmetric ciphertext blob. However, it is always
recommended as a best practice. This practice ensures that you use the CMK that you intend.

To specify a CMK, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. When using an alias name,
prefix it with `"alias/"`. To specify a CMK in a different AWS account, you must use the key ARN or alias ARN.

For example:
* Key ID: `1234abcd-12ab-34cd-56ef-1234567890ab`
* Key ARN: `arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`
* Alias name: `alias/ExampleAlias`
* Alias ARN: `arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`

To get the key ID and key ARN for a CMK, use
[ListKeys](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html) or
[DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html). To get the alias name and
alias ARN, use [ListAliases](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListAliases.html).

Type: String

Length Constraints: Minimum length of 1. Maximum length of 2048.

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
   "EncryptionAlgorithm": "string",
   "KeyId": "string",
   "Plaintext": blob
}
```

## Response Elements

If the action is successful, the service sends back an HTTP 200 response.

The following data is returned in JSON format by the service.

#### EncryptionAlgorithm

The encryption algorithm that was used to decrypt the ciphertext.

Type: String

Valid Values: `SYMMETRIC_DEFAULT | RSAES_OAEP_SHA_1 | RSAES_OAEP_SHA_256`

#### KeyId

The Amazon Resource Name ([key
ARN](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN)) of the CMK that was used to
decrypt the ciphertext.

Type: String

Length Constraints: Minimum length of 1. Maximum length of 2048.

#### Plaintext

Decrypted plaintext data. When you use the HTTP API or the AWS CLI, the value is Base64-encoded. Otherwise, it is not
Base64-encoded.

Type: Base64-encoded binary data object

Length Constraints: Minimum length of 1. Maximum length of 4096.

#### CiphertextForRecipient

If `Recipient` is specified in the Request, then `CiphertextForRecipient` is returned instead of `Plaintext`, which
the requester has to decrypt with the private key corresponding to the public key contained in the `Recipient`'s
`AttestationDocument` field.

`CiphertextForRecipient` is a `RecipientInfo` structure, as described in [RFC5652 Section
6](https://tools.ietf.org/html/rfc5652#section-6) encoded as Base64.

Type: Base64-encoded binary data object.

Length Constraints: Minimum length of 1. Maximum length of 6144.


## Errors

For information about the errors that are common to all actions, see [Common
Errors](https://docs.aws.amazon.com/kms/latest/APIReference/CommonErrors.html).

##### DependencyTimeoutException

The system timed out while trying to fulfill the request. The request can be retried.

HTTP Status Code: 500

##### DisabledException

The request was rejected because the specified CMK is not enabled.

HTTP Status Code: 400

##### IncorrectKeyException

The request was rejected because the specified CMK cannot decrypt the data. The `KeyId` in a
[Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) request and the `SourceKeyId` in a
[ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html) request must identify the same CMK
that was used to encrypt the ciphertext.

HTTP Status Code: 400

##### InvalidCiphertextException

From the [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) or
[ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html) operation, the request was
rejected because the specified ciphertext, or additional authenticated data incorporated into the ciphertext, such as
the encryption context, is corrupted, missing, or otherwise invalid.

From the [ImportKeyMaterial](https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html)
operation, the request was rejected because AWS KMS could not decrypt the encrypted (wrapped) key material.

HTTP Status Code: 400

##### InvalidGrantTokenException

The request was rejected because the specified grant token is not valid.

HTTP Status Code: 400

##### InvalidKeyUsageException

The request was rejected for one of the following reasons:

* The `KeyUsage` value of the CMK is incompatible with the API operation.
* The encryption algorithm or signing algorithm specified for the operation is incompatible with the type of key
  material in the CMK (`CustomerMasterKeySpec`).

For encrypting, decrypting, re-encrypting, and generating data keys, the KeyUsage must be ENCRYPT_DECRYPT. For signing
and verifying, the `KeyUsage` must be `SIGN_VERIFY`. To find the `KeyUsage` of a CMK, use the
[DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) operation.

To find the encryption or signing algorithms supported for a particular CMK, use the
[DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) operation.

HTTP Status Code: 400

##### KeyUnavailableException

The request was rejected because the specified CMK was not available. You can retry the request.

HTTP Status Code: 500

##### KMSInternalException

The request was rejected because an internal exception occurred. The request can be retried.

HTTP Status Code: 500

##### KMSInvalidStateException

The request was rejected because the state of the specified resource is not valid for this request.

For more information about how key state affects the use of a CMK, see [How Key State Affects Use of a Customer Master
Key](https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html) in the *AWS Key Management Service
Developer Guide*.

HTTP Status Code: 400

##### NotFoundException

The request was rejected because the specified entity or resource could not be found.

HTTP Status Code: 400

## Examples

The following examples are formatted for legibility.

### Example Request

This example illustrates one usage of Decrypt.

```http
POST / HTTP/1.1
Host: kms.us-west-2.amazonaws.com
Content-Length: 293
X-Amz-Target: TrentService.Decrypt
X-Amz-Date: 20160517T204035Z
Content-Type: application/x-amz-json-1.1
Authorization: AWS4-HMAC-SHA256\
 Credential=AKIAI44QH8DHBEXAMPLE/20160517/us-west-2/kms/aws4_request,\
 SignedHeaders=content-type;host;x-amz-date;x-amz-target,\
 Signature=545b0c3bfd9223b8ef7e6293ef3ccac37a83d415ee3112d2e5c70727d2a49c46

{
  "KeyId": "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",  
  "CiphertextBlob": "CiDPoCH188S65r5Cy7pAhIFJMXDlU7mewhSlYUpuQIVBrhKmAQEBAgB4z6Ah9fPEuua+Qsu6QISBSTFw5VO5nsIUpWFKbkCFQa4AAAB9MHsGCSqGSIb3DQEHBqBuMGwCAQAwZwYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxLc9b6QThC9jB/ZjYCARCAOt8la8qXLO5wB3JH2NlwWWzWRU2RKqpO9A/0psE5UWwkK6CnwoeC3Zj9Q0A66apZkbRglFfY1lTY+Tc="
}
```

### Example Response

This example illustrates one usage of Decrypt.

```http
HTTP/1.1 200 OK
Server: Server
Date: Tue, 17 May 2016 20:40:40 GMT
Content-Type: application/x-amz-json-1.1
Content-Length: 146
Connection: keep-alive
x-amzn-RequestId: 9e02f41f-1c6f-11e6-af63-ab8791945da7

{
  "KeyId": "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
  "Plaintext": "VGhpcyBpcyBEYXkgMSBmb3IgdGhlIEludGVybmV0Cg==",
  "EncryptionAlgorithm": "SYMMETRIC_DEFAULT" 
}
```
