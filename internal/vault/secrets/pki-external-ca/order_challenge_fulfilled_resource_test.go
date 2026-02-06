// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccPKIExternalCAOrderChallengeFulfilledResource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	roleName := acctest.RandomWithPrefix("tf-role")
	accountName := acctest.RandomWithPrefix("tf-acme-account")
	identifier := "example.com"

	resourceName := "vault_pki_secret_backend_external_ca_order_challenge_fulfilled.test"

	ca, directoryUrl := setupVaultAndPebble(t)

	resource.Test(t, resource.TestCase{
		ExternalProviders: map[string]resource.ExternalProvider{
			"null": {
				Source:            "hashicorp/null",
				VersionConstraint: "3.2.4",
			},
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.PreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKIExternalCAOrderChallengeFulfilledResource_config(backend, accountName, roleName, identifier, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, "role_name", roleName),
					resource.TestCheckResourceAttr(resourceName, "challenge_type", "http-01"),
					resource.TestCheckResourceAttr(resourceName, "identifier", identifier),
					resource.TestCheckResourceAttrSet(resourceName, "order_id"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
				),
			},
		},
	})
}

func testPKIExternalCAOrderChallengeFulfilledResource_config(backend, accountName, roleName, identifier, directoryUrl, ca string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  backend        = vault_mount.test.path
  name           = "%s"
  directory_url  = "%s"
  email_contacts = ["test@example.com"]
  key_type       = "ec-256"
  trusted_ca     = <<EOT
%s
EOT
}

resource "vault_pki_secret_backend_external_ca_role" "test" {
  backend                     = vault_mount.test.path
  name                        = "%s"
  acme_account_name           = vault_pki_secret_backend_acme_account.test.name
  allowed_domains             = ["example.com", "*.example.com"]
  allowed_domains_options     = ["bare_domains", "subdomains", "wildcards"]
  allowed_challenge_types     = ["http-01", "dns-01", "tls-alpn-01"]
  csr_generate_key_type       = "ec-256"
  csr_identifier_population   = "cn_first"
  force                       = "true"
}

resource "vault_pki_secret_backend_external_ca_order" "test" {
  backend     = vault_mount.test.path
  role_name   = vault_pki_secret_backend_external_ca_role.test.name
  identifiers = ["%s"]
}

data "vault_pki_secret_backend_external_ca_order_challenge" "test" {
  backend        = vault_mount.test.path
  role_name      = vault_pki_secret_backend_external_ca_role.test.name
  order_id       = vault_pki_secret_backend_external_ca_order.test.order_id
  challenge_type = "http-01"
  identifier     = "%s"
}

resource "null_resource" "acme_challenge_server" {
  triggers = {
    token = data.vault_pki_secret_backend_external_ca_order_challenge.test.token
    key_authorization = data.vault_pki_secret_backend_external_ca_order_challenge.test.key_authorization
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p /tmp/acme-challenge/.well-known/acme-challenge
      /bin/echo -n '${data.vault_pki_secret_backend_external_ca_order_challenge.test.key_authorization}' > /tmp/acme-challenge/.well-known/acme-challenge/${data.vault_pki_secret_backend_external_ca_order_challenge.test.token}
      cd /tmp/acme-challenge && python3 -m http.server 5002 &
      echo $! > /tmp/acme-challenge-server.pid
      sleep 2
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      if [ -f /tmp/acme-challenge-server.pid ]; then
        kill $(cat /tmp/acme-challenge-server.pid) 2>/dev/null || true
        rm -f /tmp/acme-challenge-server.pid
      fi
      rm -rf /tmp/acme-challenge
    EOT
  }
}

resource "vault_pki_secret_backend_external_ca_order_challenge_fulfilled" "test" {
  backend        = vault_mount.test.path
  role_name      = vault_pki_secret_backend_external_ca_role.test.name
  order_id       = vault_pki_secret_backend_external_ca_order.test.order_id
  challenge_type = "http-01"
  identifier     = "%s"
  
  depends_on = [null_resource.acme_challenge_server]
}
`, backend, accountName, directoryUrl, ca, roleName, identifier, identifier, identifier)
}

// Made with Bob
