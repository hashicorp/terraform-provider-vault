# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# single provider block
provider "vault" {}

locals {
  # provide namespaces as a set
  namespaces = toset(var.namespaces)
}

resource "vault_namespace" "demo" {
  # leverage the for_each meta-argument
  for_each = local.namespaces
  path     = each.key
}

resource "vault_mount" "demo" {
  for_each  = local.namespaces
  namespace = vault_namespace.demo[each.key].path
  path      = "secretsv1"
  type      = "kv"
  options = {
    version = "1"
  }
}

resource "vault_generic_secret" "demo" {
  for_each = local.namespaces
  # Support namespace at the level of the resource and data source
  namespace = vault_mount.demo[each.key].namespace
  path      = "${vault_mount.demo[each.key].path}/secret"
  data_json = jsonencode(
    {
      "baz" = "qux"
    }
  )
}
