#Get the AppRole auth backend details
data "vault_auth_backend" "approle" {
  path = var.mount_point
}

#Dynamic policies - one will be created for each approle
data "vault_policy_document" "role_id" {
  rule {
    path         = "auth/${data.vault_auth_backend.approle.path}/role/${vault_approle_auth_backend_role.approle.role_name}/role-id"
    capabilities = ["read"]
    description  = "Read role-id for ${vault_approle_auth_backend_role.approle.role_name}"
  }
}

data "vault_policy_document" "secret_id" {
  rule {
    path         = "auth/${data.vault_auth_backend.approle.path}/role/${vault_approle_auth_backend_role.approle.role_name}/secret-id"
    capabilities = ["update"]
    description  = "Generate secret-id for ${vault_approle_auth_backend_role.approle.role_name}"
  }
}

data "vault_approle_auth_backend_role_id" "approle" {
  depends_on = [vault_approle_auth_backend_role.approle]
  backend    = data.vault_auth_backend.approle.path
  role_name  = var.approle_name
}


resource "vault_policy" "role_id" {
  name   = "approle_${vault_approle_auth_backend_role.approle.role_name}_role_id"
  policy = data.vault_policy_document.role_id.hcl
}

resource "vault_policy" "secret_id" {
  name   = "approle_${vault_approle_auth_backend_role.approle.role_name}_secret_id"
  policy = data.vault_policy_document.secret_id.hcl
}

resource "vault_approle_auth_backend_role" "approle" {
  backend   = data.vault_auth_backend.approle.path
  role_name = var.approle_name
}

resource "vault_identity_entity" "approle" {
  name              = "${data.vault_auth_backend.approle.path}-${var.approle_name}"
  external_policies = true
}

resource "vault_identity_entity_policies" "approle" {
  policies = concat(["default"], var.policies)

  exclusive = false

  entity_id = vault_identity_entity.approle.id
}

resource "vault_identity_entity_alias" "approle" {
  canonical_id   = vault_identity_entity.approle.id
  name           = data.vault_approle_auth_backend_role_id.approle.role_id
  mount_accessor = data.vault_auth_backend.approle.accessor
}
