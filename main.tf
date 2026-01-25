
terraform {
  required_providers {
    vault = {
      source = "hashicorp/vault"
    }
  }
}

variable "vault_server_public_ip" {
  description = "Public IP address of the Vault EC2 instance"
  type        = string
  default     = "127.0.0.1"
}

variable "vault_token" {
  description = "Vault token for authentication"
  type        = string
  sensitive   = true
  default     = "root"
}

variable "vault_skip_tls_verify" {
  description = "Skip TLS verification for Vault"
  type        = bool
  default     = true
}

provider "vault" {
  address         = "http://${var.vault_server_public_ip}:8200"
  token           = var.vault_token
  skip_tls_verify = var.vault_skip_tls_verify
}

resource "vault_mount" "db" {
  path = "database"
  type = "database"
}

resource "vault_database_secret_backend_connection" "redis" {
  backend     = vault_mount.db.path
  name        = "redis-local"
  plugin_name = "redis-database-plugin"
  plugin_version = "v0.6.0+builtin"
  allowed_roles = ["redis-app"]
  skip_static_role_import_rotation = true

  redis {
    host     = "127.0.0.1"
    port     = 6379
    username = "vaultadmin"
    password = "VaultAdminPass123"
  }
}


resource "vault_database_secret_backend_static_role" "redis_app" {
  backend = vault_mount.db.path
  name    = "redis-app"
  db_name = vault_database_secret_backend_connection.redis.name

  username = "appuser"
 /* skip_import_rotation = false */
  rotation_statements = [
    "ACL SETUSER appuser on >{{password}} ~* +@all"
  ]
  rotation_period      = 3600
  skip_import_rotation =false
 
}
