# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "mount_path" {
  value = values(vault_mount.demo)[*].path
}

output "secret_data" {
  sensitive = true
  value     = values(vault_generic_secret.demo)[*].data
}
