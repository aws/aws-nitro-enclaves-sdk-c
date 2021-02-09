# KMS APIs for AWS Nitro Enclaves

To enable AWS Nitro Enclaves to exchange secrets with AWS KMS using
cryptographic attestation, `Recipient` request and `CiphertextForRecipient` response parameters have been added to
the following AWS KMS APIs:
 * [Decrypt](./Decrypt.md)
 * [GenerateDataKey](./GenerateDataKey.md)
 * [GenerateRandom](./GenerateRandom.md)

The `Recipient` request parameter must specify an `AttestationDocument` that includes a public key. After AWS KMS uses
the CMK to decrypt the `CiphertextBlob` in the request, or to generate the Data Key or Random number, AWS KMS
re-encrypts the resulting `Plaintext` blob using the public key included in the `AttestationDocument`. AWS KMS then
returns the data encrypted under the public key to the requesting enclave in the `CiphertextForRecipient` response
paramter.  `CiphertextForRecipient` is a RecipientInfo structure, as described in [RFC5652 Section
6](https://tools.ietf.org/html/rfc5652#section-6) encoded as Base64. The encrypted data can only be decrypted with the
private key corresponding to the public key added in the `AttestationDocument`.  This private key never leaves the
enclave. In this case, the `Plaintext` field is eliminated from the response. Examples for the new requests are
provided below.

These APIs allow an AWS Nitro Enclave to decrypt, encrypt (via `GenerateDataKey`) data and generate a random number if
they match the AWS KMS policy set in place, and then provide a response from AWS KMS that only the enclave can use.

Cryptographic attestation allows restricting access to an AWS KMS CMK based on a set of additional conditions that can
be verified only by providing a valid `AttestationDocument`. Access is then given if the `AttestationDocument` is
validly signed by the Nitro hypervisor, and if it contains a public key and the PCRs listed in the `AttestationDocument`
match the PCRs in the policy. An [example policy](#example-policy) is provided below, which allows the role `ROLE_ARN`
to use the decrypt operation if it can provide a valid `AttestationDocument` containing `ImageSha384` (`PCR0`) and
`PCR3` and their respective values. Additional information can be found in [Using cryptographic attestation with AWS
KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html)

## Example Requests

### Decrypt

```json
{
   "CiphertextBlob": blob,
   "EncryptionAlgorithm": "string",
   "EncryptionContext": { 
      "string" : "string" 
   },
   "GrantTokens": [ "string" ],
   "KeyId": "string",
   "Recipient": {
     "AttestationDocument": blob,
     "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"
   }
}
```

### GenerateDataKey
```json
{
   "EncryptionContext": { 
      "string" : "string" 
   },
   "GrantTokens": [ "string" ],
   "KeyId": "string",
   "KeySpec": "string",
   "NumberOfBytes": number
   "Recipient": {
     "AttestationDocument": blob,
     "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"
   }
}
```

## Example Response

### Decrypt
```json
{
   "EncryptionAlgorithm": "string",
   "KeyId": "string",
   "CiphertextForRecipient": blob
}
```

### GenerateDataKey

```json
{
   "CiphertextBlob": blob,
   "KeyId": "string",
   "CiphertextForRecipient": blob
}
```

## Example Policy
```json
{
  "Version" : "2012-10-17",
  "Id" : "key-default-1",
  "Statement" : [
    {
      "Sid" : "Enable decrypt from enclave",
      "Effect" : "Allow",
      "Principal" : { "AWS" : ROLE_ARN },
      "Action" : "kms:Decrypt",
      "Resource" : "*",
      "Condition": {
          "StringEqualsIgnoreCase": {
            "kms:RecipientAttestation:ImageSha384": "1234567890abcdeffedcba09876543211234567890abcdeffedcba09876543211234567890abcdeffedcba0987654321",
            "kms:RecipientAttestation:PCR3": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
          }
      }
    }
  ]
}
```
