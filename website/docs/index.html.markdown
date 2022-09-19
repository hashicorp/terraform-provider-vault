---
layout: "vault"
page_title: "Provider: Vault"
sidebar_current: "docs-vault-index"
description: |-
  The Vault provider allows Terraform to read from, write to, and configure HashiCorp Vault
---

# Vault Provider

The Vault provider allows Terraform to read from, write to, and configure
[HashiCorp Vault](https://vaultproject.io/).

~> **Important** Interacting with Vault from Terraform causes any secrets
that you read and write to be persisted in both Terraform's state file
*and* in any generated plan files. For any Terraform module that reads or
writes Vault secrets, these files should be treated as sensitive and
protected accordingly.

This provider serves two pretty-distinct use-cases, which each have their
own security trade-offs and caveats that are covered in the sections that
follow. Consider these carefully before using this provider within your
Terraform configuration.

-> Visit the [Inject secrets into Terraform using the Vault provider](https://learn.hashicorp.com/tutorials/terraform/secrets-vault?utm_source=WEBSITE&utm_medium=WEB_IO&utm_offer=ARTICLE_PAGE&utm_content=DOCS) Learn tutorial to learn how to use
short-lived credentials from Vault's AWS Secrets Engine to authenticate the
AWS provider.

## Best Practices

We recommend that you avoid placing secrets in your Terraform config or state file wherever possible, and if placed there, you take steps to reduce and manage your risk. We have created a practical guide on how to do this with our opensource versions in Best Practices for Using HashiCorp Terraform with HashiCorp Vault:

[![Best Practices for Using HashiCorp Terraform with HashiCorp Vault](https://img.youtube.com/vi/fOybhcbuxJ0/0.jpg)](https://www.youtube.com/watch?v=fOybhcbuxJ0)

This webinar walks you through how to protect secrets when using Terraform with Vault. Additional security measures are available in paid Terraform versions as well.

## Configuring and Populating Vault

Terraform can be used by the Vault administrators to configure Vault and
populate it with secrets. In this case, the state and any plans associated
with the configuration must be stored and communicated with care, since they
will contain in cleartext any values that were written into Vault.

Currently Terraform has no mechanism to redact or protect secrets
that are provided via configuration, so teams choosing to use Terraform
for populating Vault secrets should pay careful attention to the notes
on each resource's documentation page about how any secrets are persisted
to the state and consider carefully whether such usage is compatible with
their security policies.

Except as otherwise noted, the resources that write secrets into Vault are
designed such that they require only the *create* and *update* capabilities
on the relevant resources, so that distinct tokens can be used for reading
vs. writing and thus limit the exposure of a compromised token.

## Using Vault credentials in Terraform configuration

Most Terraform providers require credentials to interact with a third-party
service that they wrap. This provider allows such credentials to be obtained
from Vault, which means that operators or systems running Terraform need
only access to a suitably-privileged Vault token in order to temporarily
lease the credentials for other providers.

Currently Terraform has no mechanism to redact or protect secrets that
are returned via data sources, so secrets read via this provider will be
persisted into the Terraform state, into any plan files, and in some cases
in the console output produced while planning and applying. These artifacts
must therefore all be protected accordingly.

To reduce the exposure of such secrets, the provider requests a Vault token
with a relatively-short TTL (20 minutes, by default) which in turn means
that where possible Vault will revoke any issued credentials after that
time, but in particular it is unable to retract any static secrets such as
those stored in Vault's "generic" secret backend.

The requested token TTL can be controlled by the `max_lease_ttl_seconds`
provider argument described below. It is important to consider that Terraform
reads from data sources during the `plan` phase and writes the result into
the plan. Thus a subsequent `apply` will likely fail if it is run after the
intermediate token has expired, due to the revocation of the secrets that
are stored in the plan.

Except as otherwise noted, the resources that read secrets from Vault
are designed such that they require only the *read* capability on the relevant
resources.

## Provider Arguments

The provider configuration block accepts the following arguments.
In most cases it is recommended to set them via the indicated environment
variables in order to keep credential information out of the configuration.

* `address` - (Required) Origin URL of the Vault server. This is a URL
  with a scheme, a hostname and a port but with no path. May be set
  via the `VAULT_ADDR` environment variable.

* `add_address_to_env` - (Optional) If `true` the environment variable
  `VAULT_ADDR` in the Terraform process environment will be set to the
  value of the `address` argument from this provider. By default, this is false.

* `token` - (Optional) Vault token that will be used by Terraform to
  authenticate. May be set via the `VAULT_TOKEN` environment variable.
  If none is otherwise supplied, Terraform will attempt to read it from
  `~/.vault-token` (where the vault command stores its current token).
  Terraform will issue itself a new token that is a child of the one given,
  with a short TTL to limit the exposure of any requested secrets, unless
  `skip_child_token` is set to `true` (see below). Note that
  the given token must have the update capability on the auth/token/create
  path in Vault in order to create child tokens.  A token is required for
  the provider.  A token can explicitly set via token argument, alternatively 
  a token can be dynamically set via an `auth_login*` block.

* `token_name` - (Optional) Token name, that will be used by Terraform when
  creating the child token (`display_name`). This is useful to provide a reference of the
  Terraform run traceable in vault audit log, e.g. commit hash or id of the CI/CD
  execution job. May be set via the `VAULT_TOKEN_NAME` environment variable.
  Default value will be `terraform` if not set or empty.

* `ca_cert_file` - (Optional) Path to a file on local disk that will be
  used to validate the certificate presented by the Vault server.
  May be set via the `VAULT_CACERT` environment variable.

* `ca_cert_dir` - (Optional) Path to a directory on local disk that
  contains one or more certificate files that will be used to validate
  the certificate presented by the Vault server. May be set via the
  `VAULT_CAPATH` environment variable.

* `auth_login_userpass` - (Optional) Utilizes the `userpass` authentication engine. *[See usage details below.](#userpass)*

* `auth_login_aws` - (Optional) Utilizes the `aws` authentication engine. *[See usage details below.](#aws)*

* `auth_login_cert` - (Optional) Utilizes the `cert` authentication engine. *[See usage details below.](#tls-certificate)*

* `auth_login_gcp` - (Optional) Utilizes the `gcp` authentication engine. *[See usage details below.](#gcp)*

* `auth_login` - (Optional) A configuration block, described below, that
  attempts to authenticate using the `auth/<method>/login` path to
  acquire a token which Terraform will use. Terraform still issues itself
  a limited child token using auth/token/create in order to enforce a short
  TTL and limit exposure. *[See usage details below.](#generic)*

* `client_auth` - (Optional) A configuration block, described below, that
  provides credentials used by Terraform to authenticate with the Vault
  server. At present there is little reason to set this, because Terraform
  does not support the TLS certificate authentication mechanism.
  *Deprecated, use `auth_login_cert` instead.

* `skip_tls_verify` - (Optional) Set this to `true` to disable verification
  of the Vault server's TLS certificate. This is strongly discouraged except
  in prototype or development environments, since it exposes the possibility
  that Terraform can be tricked into writing secrets to a server controlled
  by an intruder. May be set via the `VAULT_SKIP_VERIFY` environment variable.

* `tls_server_name` - (Optional) Name to use as the SNI host when connecting
  via TLS. May be set via the `VAULT_TLS_SERVER_NAME` environment variable.

* `skip_child_token` - (Optional) Set this to `true` to disable
  creation of an intermediate ephemeral Vault token for Terraform to
  use. Enabling this is strongly discouraged since it increases
  the potential for a renewable Vault token being exposed in clear text.
  Only change this setting when the provided token cannot be permitted to
  create child tokens and there is no risk of exposure from the output of
  Terraform. May be set via the `TERRAFORM_VAULT_SKIP_CHILD_TOKEN` environment
  variable. **Note**: Setting to `true` will cause `token_name`
  and `max_lease_ttl_seconds` to be ignored.
  Please see [Using Vault credentials in Terraform configuration](#using-vault-credentials-in-terraform-configuration)
  before enabling this setting.

* `max_lease_ttl_seconds` - (Optional) Used as the duration for the
  intermediate Vault token Terraform issues itself, which in turn limits
  the duration of secret leases issued by Vault. Defaults to 20 minutes
  and may be set via the `TERRAFORM_VAULT_MAX_TTL` environment variable.
  See the section above on *Using Vault credentials in Terraform configuration*
  for the implications of this setting.

* `max_retries` - (Optional) Used as the maximum number of retries when a 5xx
  error code is encountered. Defaults to `2` retries and may be set via the
  `VAULT_MAX_RETRIES` environment variable.

* `max_retries_ccc` - (Optional) Maximum number of retries for _Client Controlled Consistency_
  related operations. Defaults to `10` retries and may also be set via the
  `VAULT_MAX_RETRIES_CCC` environment variable. See
  [Vault Eventual Consistency](https://www.vaultproject.io/docs/enterprise/consistency#vault-eventual-consistency)
  for more information.   
  *As of Vault Enterprise 1.10 changing this parameter should no longer be required
  See [Vault Eventual Consistency - Vault 1.10 Mitigations](https://www.vaultproject.io/docs/enterprise/consistency#vault-1-10-mitigations)
  for more information.*

* `namespace` - (Optional) Set the namespace to use. May be set via the
  `VAULT_NAMESPACE` environment variable.
  See [namespaces](https://www.vaultproject.io/docs/enterprise/namespaces) for more info.
  *Available only for Vault Enterprise*.

* `headers` - (Optional) A configuration block, described below, that provides headers
to be sent along with all requests to the Vault server.  This block can be specified
multiple times.

The `client_auth` configuration block accepts the following arguments:

* `cert_file` - (Required) Path to a file on local disk that contains the
  PEM-encoded certificate to present to the server.

* `key_file` - (Required) Path to a file on local disk that contains the
  PEM-encoded private key for which the authentication certificate was issued.

The `headers` configuration block accepts the following arguments:

* `name` - (Required) The name of the header.

* `value` - (Required) The value of the header.

## Vault Authentication Configuration Options

The Vault provider supports the following Vault authentication engines.

### Userpass

Provides support for authenticating to Vault using the Username & Password authentication engine.

*For more details see: [Userpass Auth Method (HTTP API)](https://www.vaultproject.io/api-docs/auth/userpass#userpass-auth-method-http-api)*

The `auth_login_userpass` configuration block accepts the following arguments:

* `namespace` - (Optional) The path to the namespace that has the mounted auth method.
  This defaults to the root namespace. Cannot contain any leading or trailing slashes.
  *Available only for Vault Enterprise*.

* `mount` - (Optional) The name of the  authentication engine mount.  
  Default: `userpass`

* `username` - (Required) The username to log into Vault with.
  Can be specified with the `TERRAFORM_VAULT_USERNAME` environment variable.

* `password` - (Optional) The password to log into Vault with.
  Can be specified with the `TERRAFORM_VAULT_PASSWORD` environment variable. *Cannot be specified with `password_file`*.

* `password_file` - (Optional) A file containing the password to log into Vault with.
  Can be specified with the `TERRAFORM_VAULT_PASSWORD_FILE` environment variable. *Cannot be specified with `password`*

### AWS

Provides support for authenticating to Vault using the AWS authentication engine.

*For more details see: [AWS Auth Method (API)](https://www.vaultproject.io/api-docs/auth/aws#aws-auth-method-api)*

The `auth_login_aws` configuration block accepts the following arguments:

* `namespace` - (Optional) The path to the namespace that has the mounted auth method.
  This defaults to the root namespace. Cannot contain any leading or trailing slashes.
  *Available only for Vault Enterprise*.

* `mount` - (Optional) The name of the authentication engine mount.  
  Default: `aws`

* `role` - (Optional) The IAM role to use when logging into Vault.

* `identity` - (Optional) The base64 encoded EC2 instance identity document.

* `signature` - (Optional) The base64 encoded SHA256 RSA signature of the instance identity document.

* `pkcs7` - (Optional) PKCS#7 signature of the identity document.

* `nonce` - (Optional) The nonce to be used for subsequent login requests.

* `iam_http_request_method` - (Optional) The HTTP method used in the signed request.  
  `POST` is is the only supported method.

* `iam_http_request_url` - (Optional) The base64 encoded HTTP URL used in the signed request.

* `iam_http_request_body` - (Optional) The base64 encoded body of the signed request.

* `iam_http_request_headers` - (Optional) Mapping of extra IAM specific HTTP request login headers.

### TLS Certificate

Provides support for authenticating to Vault using the TLS Certificate authentication engine.

*For more details see: [TLS Certificate Auth Method (API)](https://www.vaultproject.io/api-docs/auth/cert#tls-certificate-auth-method-api)*


The `auth_login_cert` configuration block accepts the following arguments:

* `namespace` - (Optional) The path to the namespace that has the mounted auth method.
  This defaults to the root namespace. Cannot contain any leading or trailing slashes.
  *Available only for Vault Enterprise*.

* `mount` - (Optional) The name of the  authentication engine mount.  
  Default: `cert`

* `cert_file` - (Required) Path to a file on local disk that contains the
  PEM-encoded certificate to present to the server.

* `key_file` - (Required) Path to a file on local disk that contains the
  PEM-encoded private key for which the authentication certificate was issued.

*This login configuration honors the top-level TLS configuration parameters:
[ca_cert_file](#ca_cert_file), [ca_cert_dir](#ca_cert_dir), [skip_tls_verify](#skip_tls_verify), [tls_server_name](#tls_server_name)*

### GCP

Provides support for authenticating to Vault using the Google Cloud Auth engine.

*For more details see: [Google Cloud Auth Method (API)](https://www.vaultproject.io/api-docs/auth/gcp#google-cloud-auth-method-api)*


The `auth_login_gcp` configuration block accepts the following arguments:

* `namespace` - (Optional) The path to the namespace that has the mounted auth method.
  This defaults to the root namespace. Cannot contain any leading or trailing slashes.
  *Available only for Vault Enterprise*.

* `mount` - (Optional) The name of the  authentication engine mount.  
  Default: `cert`

* `role` - (Required) The name of the role against which the login is being attempted.

* `jwt` - (Optional) The signed JSON Web Token against which the login is being attempted.

* `credentials` - (Optional) Path to the Google Cloud credentials to use when getting the signed 
  JWT token from the IAM service.  
*conflicts with `jwt`*

* `service_account` - (Optional) Name of the service account to issue the JWT token for.  
*requires `credentials`*

*This login configuration will attempt to get a signed JWT token if `jwt` is not specified. 
It supports both the IAM and GCE meta-data services as the token source.*

### Generic

Provides support for path based authentication to Vault.

~> It is recommended to use one of the authentication engine specific configurations above.
This configuration can be used for custom authentication engines, or in the case where an official authentication
engine is not yet supported by the provider

The path-based `auth_login` configuration block accepts the following arguments:

* `path` - (Required) The login path of the auth backend. For example, login with
  approle by setting this path to `auth/approle/login`. Additionally, some mounts use parameters
  in the URL, like with `userpass`: `auth/userpass/login/:username`.

* `namespace` - (Optional) The path to the namespace that has the mounted auth method.
  This defaults to the root namespace. Cannot contain any leading or trailing slashes.
  *Available only for Vault Enterprise*.

* `method` - (Optional) When configured, will enable auth method specific operations.
  For example, when set to `aws`, the provider will automatically sign login requests
  for AWS authentication. Valid values include: `aws`.

* `parameters` - (Optional) A map of key-value parameters to send when authenticating
  against the auth backend. Refer to [Vault API documentation](https://www.vaultproject.io/api-docs/auth) for a particular auth method
  to see what can go here.

## Provider Debugging

Terraform supports various logging options by default.
These are documented [here](https://www.terraform.io/docs/internals/debugging.html).

~> The environment variables below can be configured to provide extended log output. The Terraform log level must 
be set to `DEBUG` or higher. It's important to note that any extended log output 
may **reveal secrets**, so please exercise caution when enabling any of the following:

* `TERRAFORM_VAULT_LOG_BODY` - when set to `true` both the request and response body will be logged.

* `TERRAFORM_VAULT_LOG_REQUEST_BODY` - when set to `true` the request body will be logged.

* `TERRAFORM_VAULT_LOG_RESPONSE_BODY` - when set to `true` the response body will be logged.

## Example Usage

```hcl
provider "vault" {
  # It is strongly recommended to configure this provider through the
  # environment variables described above, so that each user can have
  # separate credentials set in the environment.
  #
  # This will default to using $VAULT_ADDR
  # But can be set explicitly
  # address = "https://vault.example.net:8200"
}

resource "vault_generic_secret" "example" {
  path = "secret/foo"

  data_json = jsonencode(
    {
      "foo"   = "bar",
      "pizza" = "cheese"
    }
  )
}
```

### Example `auth_login` Usage
With the `userpass` backend:

```hcl
variable login_username {}
variable login_password {}

provider "vault" {
  auth_login {
    path = "auth/userpass/login/${var.login_username}"

    parameters = {
      password = var.login_password
    }
  }
}
```

Or, using `approle`:

```hcl
variable login_approle_role_id {}
variable login_approle_secret_id {}

provider "vault" {
  auth_login {
    path = "auth/approle/login"

    parameters = {
      role_id   = var.login_approle_role_id
      secret_id = var.login_approle_secret_id
    }
  }
}
```

### Example `auth_login` With AWS Signing

Sign AWS metadata for instance profile login requests:

```hcl
provider "vault" {
  address = "http://127.0.0.1:8200"
  auth_login {
    path = "auth/aws/login"
    method = "aws"
    parameters = {
      role = "dev-role-iam"
    }
  }
}
```

If the Vault server's AWS auth method requires the `X-Vault-AWS-IAM-Server-ID` header to be set by clients, specify the server ID in `header_value` within the `parameters` block:

```hcl
provider "vault" {
  address = "http://127.0.0.1:8200"
  auth_login {
    path = "auth/aws/login"
    method = "aws"
    parameters = {
      role = "dev-role-iam"
      header_value = "vault.example.com"
    }
  }
}
```

## Namespace support

The Vault provider supports managing [Namespaces][namespaces] (a feature of
Vault Enterprise), as well as creating resources in those namespaces by
utilizing [Provider Aliasing][aliasing]. The `namespace` option in the [provider
block][provider-block] enables the management of  resources in the specified
namespace. 
In addition, all resources and data sources support specifying their own `namespace`. 
All resource's `namespace` will be made relative to the `provider`'s configured namespace.

### Importing namespaced resources

Importing a namespaced resource is done by providing the `namespace` from 
the `TERRAFORM_VAULT_NAMESPACE_IMPORT` environment variable.

Given the following sample Terraform:

```hcl
provider vault{}

resource "vault_mount" "secret" {
  namespace = "namespace1"
  path      = "secrets"
  type      = "kv"
  options = {
    version = "2"
  }
}
```

One would run the following import command:

```shell
TERRAFORM_VAULT_NAMESPACE_IMPORT=namespace1 terraform import vault_mount.secret secrets
```

~> The import namespace will always be made relative to the `namespace` of the `provider{}` block.  
The `TERRAFORM_VAULT_NAMESPACE_IMPORT` should only ever be set when importing a Vault resource.


### Simple namespace example
```hcl
provider vault{}

resource "vault_namespace" "secret" {
  path = "secret_ns"
}

resource "vault_mount" "secret" {
  namespace = vault_namespace.secret.path
  path      = "secrets"
  type      = "kv"
  options = {
    version = "1"
  }
}

resource "vault_generic_secret" "secret" {
  namespace = vault_mount.secret.namespace
  path      = "${vault_mount.secret.path}/secret"
  data_json = jsonencode(
    {
      "ns" = "secret"
    }
  )
}
```

### Using Provider Aliases

~> It is advisable to set the `namespace` on individual resources and data sources,
rather than having to manage multiple `provider` aliases.
See [vault_namespace](r/namespace.html) for more information.

The configuration below is a simple example of using the provider block's
`namespace` attribute to configure an aliased provider and create a resource
within that namespace. 

```hcl
# main provider block with no namespace
provider vault {}

# create the "everyone" namespace in the default root namespace
resource "vault_namespace" "everyone" {
  path = "everyone"
}

# configure an aliased provider, scope to the new namespace.
provider vault {
  alias     = "everyone"
  namespace = vault_namespace.everyone.path
}

# create a policy in the "everyone" namespace
resource "vault_policy" "example" {
  provider = vault.everyone

  depends_on = [vault_namespace.everyone]
  name       = "vault_everyone_policy"
  policy     = data.vault_policy_document.list_secrets.hcl
}

data "vault_policy_document" "list_secrets" {
  rule {
    path         = "secret/*"
    capabilities = ["list"]
    description  = "allow List on secrets under everyone/"
  }
}
```

Using this alias configuration, the policy `list_secrets` is created under the
`everyone` namespace, but not under the "root" namespace:

```
$ vault policy list -namespace=everyone
default
vault_everyone_policy

$ vault policy list
default
root
```

### Nested Namespaces

The example below relies on setting the `namespace` per resource from a single `provider{}` block. 
See the [vault_namespace](/docs/providers/vault/r/namespace.html#nested-namespaces) documentation for a slightly less elaborate example.

```hcl
provider vault {}

variable "everyone_ns" {
  default = "everyone"
}

variable "engineering_ns" {
  default = "engineering"
}

variable "vault_team_ns" {
  default = "vault-team"
}

data "vault_policy_document" "public_secrets" {
  rule {
    path         = "secret/*"
    capabilities = ["list"]
    description  = "allow List on secrets under everyone/ namespace"
  }
}

data "vault_policy_document" "vault_team_secrets" {
  rule {
    path         = "secret/*"
    capabilities = ["create", "read", "update", "delete", "list"]
    description  = "allow all on secrets under everyone/engineering/vault-team/"
  }
}

resource "vault_namespace" "everyone" {
  path = var.everyone_ns
}

resource "vault_namespace" "engineering" {
  namespace = vault_namespace.everyone.path
  path      = var.engineering_ns
}

resource "vault_namespace" "vault_team" {
  namespace = vault_namespace.engineering.path_fq
  path      = var.vault_team_ns
}


resource "vault_policy" "everyone" {
  namespace = vault_namespace.everyone.path
  name     = "vault_everyone_policy"
  policy   = data.vault_policy_document.vault_team_secrets.hcl
}

resource "vault_policy" "vault_team" {
  namespace = vault_namespace.vault_team.path_fq
  name     = "vault_team_policy"
  policy   = data.vault_policy_document.vault_team_secrets.hcl
}
```

Using this configuration, the namespace and policy structure looks like so:

```
<root>/
  default
  root
  /everyone/
   default
   vault_everyone_policy
    /engineering/
      default
      /vault-team/
      default
      vault_team_policy
```

Verify the structure with `vault` directly:

```
$ vault namespace list
Keys
----
everyone/

$ vault namespace list -namespace=everyone
Keys
----
engineering/

$ vault namespace list -namespace=everyone/engineering
Keys
----
vault-team/

$ vault namespace list -namespace=everyone/engineering/vault-team
No namespaces found

$ vault policy list -namespace=everyone/engineering/vault-team
default
vault_team_policy
```

## Tutorials 

Refer to the [Codify Management of Vault Enterprise Using Terraform](https://learn.hashicorp.com/tutorials/vault/codify-mgmt-enterprise) tutorial for additional examples using Vault namespaces.


[namespaces]: https://www.vaultproject.io/docs/enterprise/namespaces#vault-enterprise-namespaces
[aliasing]: https://www.terraform.io/docs/configuration/providers.html#alias-multiple-provider-configurations
[provider-block]: /docs#provider-arguments
