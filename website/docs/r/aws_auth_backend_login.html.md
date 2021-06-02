---
layout: "vault"
page_title: "Vault: vault_aws_auth_backend_login resource"
sidebar_current: "docs-vault-resource-aws-auth-backend-login"
description: |-
  Manages Vault tokens acquired using the AWS auth backend.
---

# vault\_aws\_auth\_backend\_login

Logs into a Vault server using an AWS auth backend. Login can be
accomplished using a signed identity request from IAM or using ec2
instance metadata. For more information, see the [Vault
documentation](https://www.vaultproject.io/docs/auth/aws.html).

## Example Usage

```hcl
resource "vault_auth_backend" "aws" {
  type = "aws"
  path = "aws"
}

resource "vault_aws_auth_backend_client" "example" {
  backend    = vault_auth_backend.aws.path
  access_key = "123456789012"
  secret_key = "AWSSECRETKEYGOESHERE"
}

resource "vault_aws_auth_backend_role" "example" {
  backend                         = vault_auth_backend.aws.path
  role                            = "test-role"
  auth_type                       = "ec2"
  bound_ami_ids                   = ["ami-8c1be5f6"]
  bound_account_ids               = ["123456789012"]
  bound_vpc_ids                   = ["vpc-b61106d4"]
  bound_subnet_ids                = ["vpc-133128f1"]
  bound_iam_instance_profile_arns = ["arn:aws:iam::123456789012:instance-profile/MyProfile"]
  token_ttl                       = 60
  token_max_ttl                   = 120
  token_policies                  = ["default", "dev", "prod"]

  depends_on = [vault_aws_auth_backend_client.example]
}

resource "vault_aws_auth_backend_login" "example" {
  backend   = vault_auth_backend.aws.path
  role      = vault_aws_auth_backend_role.example.role
  identity  = "BASE64ENCODEDIDENTITYDOCUMENT"
  signature = "BASE64ENCODEDSHA256IDENTITYDOCUMENTSIGNATURE"
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Optional) The unique name of the AWS auth backend. Defaults to
  'aws'.

* `role` - (Optional) The name of the AWS auth backend role to create tokens
  against.

* `identity` - (Optional) The base64-encoded EC2 instance identity document to
  authenticate with. Can be retrieved from the EC2 metadata server.

* `signature` - (Optional) The base64-encoded SHA256 RSA signature of the
  instance identity document to authenticate with, with all newline characters
  removed. Can be retrieved from the EC2 metadata server.

* `pkcs7` - (Optional) The PKCS#7 signature of the identity document to
  authenticate with, with all newline characters removed. Can be retrieved from
  the EC2 metadata server.

* `nonce` - (Optional) The unique nonce to be used for login requests. Can be
  set to a user-specified value, or will contain the server-generated value
  once a token is issued. EC2 instances can only acquire a single token until
  the whitelist is tidied again unless they keep track of this nonce.

* `iam_http_request_method` - (Optional) The HTTP method used in the signed IAM
  request.

* `iam_request_url` - (Optional) The base64-encoded HTTP URL used in the signed
  request.

* `iam_request_body` - (Optional) The base64-encoded body of the signed
  request.

* `iam_request_headers` - (Optional) The base64-encoded, JSON serialized
  representation of the GetCallerIdentity HTTP request headers.

## Attributes Reference

In addition to the fields above, the following attributes are also exposed:

* `lease_duration` - The duration in seconds the token will be valid, relative
  to the time in `lease_start_time`.

* `lease_start_time` - The approximate time at which the token was created,
  using the clock of the system where Terraform was running.

* `renewable` - Set to true if the token can be extended through renewal.

* `metadata` - A map of information returned by the Vault server about the
  authentication used to generate this token.

* `auth_type` - The authentication type used to generate this token.

* `policies` - The Vault policies assigned to this token.

* `accessor` - The token's accessor.

* `client_token` - The token returned by Vault.
