terraform {
}

provider "vault" {
}

variable "address" {
  type        = string
  description = "Origin URL of the Vault server"
  default     = null
}

variable "token" {
  type        = string
  description = "Vault token that will be used by Terrafokjrm to authenticate"
  default     = null
}

variable "token_name" {
  type        = string
  description = "Token name that will be used by Terraform when creating the child token"
  default     = null
}

variable "ca_cert_file" {
  type        = string
  description = "Path to a file on local disk that will be used to validate the certificate presented by the Vault server"
  default     = null
}

variable "ca_cert_dir" {
  type        = string
  description = "Path to a directory on local disk that contains one or more certificate files that will be used to validate the certificate presented by the Vault server"
  default     = null
}

variable "skip_tls_verify" {
  type        = bool
  description = "Set this to `true` to disable verification of the Vault server's TLS certificate"
  default     = false
}

variable "max_lease_ttl_seconds" {
  type        = number
  description = "Used as the duration for the intermediate Vault token Terraform issues itself, which in turn limits the duration of secret leases issued by Vault"
  default     = 1200
}

variable "max_retries" {
  type        = number
  description = "Used as the maximum number of retries when a 5xx error code is encountered"
  default     = 2
}

variable "namespace" {
  type        = string
  description = "Set the namespace to use"
  default     = null
}

variable "okta" {
  type = object({
    path         = string
    organization = string
    token        = string
    description  = string
  })
  description = "Okta auth method configuration"
  default     = null
}

resource "vault_okta_auth_backend" "okta" {
  description  = "Testing the Terraform okta auth backend (baz)"
  path         = "okta-20210728135830937400000001"
  organization = "example"
  ttl          = "1h"
  max_ttl      = "2h"
  group {
    group_name = "dummy"
    policies   = ["one", "two", "default"]
  }
  user {
    username = "foo"
    groups   = ["dummy"]
  }
}
