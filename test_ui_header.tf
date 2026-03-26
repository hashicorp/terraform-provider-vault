# Test UI Header resource - must be in root namespace
resource "vault_config_ui_header" "test" {
  name   = "X-Test-Import-Header"
  values = ["test-value-1", "test-value-2"]
}

# Outputs
output "header_name" {
  value = vault_config_ui_header.test.name
}

output "header_values" {
  value = vault_config_ui_header.test.values
}