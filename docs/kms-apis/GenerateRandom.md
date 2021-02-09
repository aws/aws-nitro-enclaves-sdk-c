# GenerateRandom

Returns a random byte string that is cryptographically secure.

By default, the random byte string is generated in AWS KMS. To generate the byte string in the AWS CloudHSM cluster
that is associated with a [custom key
store](https://docs.aws.amazon.com/kms/latest/developerguide/custom-key-store-overview.html), specify the custom key
store ID.

For more information about entropy and random number generation, see [AWS Key Management Service Cryptographic
Details](https://docs.aws.amazon.com/kms/latest/cryptographic-details/).

Required permissions:
[kms:GenerateRandom](https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html) (IAM
policy) 

## Request Syntax
```json
Request Syntax

{
   "CustomKeyStoreId": "string",
   "NumberOfBytes": number
}
```

## Request Parameters

For information about the parameters that are common to all actions, see [Common
Parameters](https://docs.aws.amazon.com/kms/latest/APIReference/CommonParameters.html).

The request accepts the following data in JSON format.
> **Note**
>
> In the following list, the required parameters are described first.

#### CustomKeyStoreId

Generates the random byte string in the AWS CloudHSM cluster that is associated with the specified custom key store.
To find the ID of a custom key store, use the DescribeCustomKeyStores operation.

Type: String

Length Constraints: Minimum length of 1. Maximum length of 64.

Required: No

#### NumberOfBytes

The length of the byte string.

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
   "Plaintext": blob
}
```
## Response Elements

If the action is successful, the service sends back an HTTP 200 response.

The following data is returned in JSON format by the service.

#### Plaintext

The random byte string. When you use the HTTP API or the AWS CLI, the value is Base64-encoded. Otherwise, it is not
Base64-encoded.

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

#### CustomKeyStoreInvalidStateException

The request was rejected because of the ConnectionState of the custom key store. To get the ConnectionState of a
custom key store, use the
[DescribeCustomKeyStores](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeCustomKeyStores.html)
operation.

This exception is thrown under the following conditions:

  * You requested the [CreateKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html) or
    [GenerateRandom](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateRandom.html) operation in a
custom key store that is not connected. These operations are valid only when the custom key store `ConnectionState` is
`CONNECTED`.

  * You requested the
    [UpdateCustomKeyStore](https://docs.aws.amazon.com/kms/latest/APIReference/API_UpdateCustomKeyStore.html) or
[DeleteCustomKeyStore](https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteCustomKeyStore.html) operation on
a custom key store that is not disconnected. This operation is valid only when the custom key store `ConnectionState`
is `DISCONNECTED`.

  * You requested the
    [ConnectCustomKeyStore](https://docs.aws.amazon.com/kms/latest/APIReference/API_ConnectCustomKeyStore.html)
operation on a custom key store with a `ConnectionState` of `DISCONNECTING` or `FAILED`. This operation is valid for
all other `ConnectionState` values.

HTTP Status Code: 400

#### CustomKeyStoreNotFoundException

The request was rejected because AWS KMS cannot find a custom key store with the specified key store name or ID.

HTTP Status Code: 400

#### DependencyTimeoutException

The system timed out while trying to fulfill the request. The request can be retried.

HTTP Status Code: 500

#### KMSInternalException

The request was rejected because an internal exception occurred. The request can be retried.

HTTP Status Code: 500

## Examples

The following examples are formatted for legibility.
### Example Request

This example illustrates one usage of GenerateRandom.
```http
POST / HTTP/1.1
Host: kms.us-east-2.amazonaws.com
Content-Length: 21
X-Amz-Target: TrentService.GenerateRandom
X-Amz-Date: 20161114T215101Z
Content-Type: application/x-amz-json-1.1
Authorization: AWS4-HMAC-SHA256\
 Credential=AKIAI44QH8DHBEXAMPLE/20161114/us-east-2/kms/aws4_request,\
 SignedHeaders=content-type;host;x-amz-date;x-amz-target,\
 Signature=e3a0cfdbfb71fae5c89e422ad8322b6a44aed85bf68e3d11f3f315bbaa82ad22

{"NumberOfBytes": 32}
```
### Example Response

This example illustrates one usage of GenerateDataKey.
```http
HTTP/1.1 200 OK
Server: Server
Date: Mon, 14 Nov 2016 21:51:02 GMT
Content-Type: application/x-amz-json-1.1
Content-Length: 60
Connection: keep-alive
x-amzn-RequestId: 6f79b0ad-aab4-11e6-971f-0f7b7e5b6782

{"Plaintext":"+Q2hxK6OBuU6K6ZIIBucFMCW2NJkhiSWDySSQyWp9zA="}
```
