output "mount_path" {
  value = values(vault_mount.demo)[*].path
}

output "secret_data" {
  sensitive = true
  value     = values(vault_generic_secret.demo)[*].data
}
