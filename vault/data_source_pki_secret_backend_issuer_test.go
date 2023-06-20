// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourcePKISecretIssuer(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	issuerName := acctest.RandomWithPrefix("tf-test-pki-issuer")
	dataName := "data.vault_pki_secret_backend_issuer.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKISecretIssuerDataSource(backend, issuerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldIssuerID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldKeyID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldCertificate),
				),
			},
		},
	})
}

func testPKISecretIssuerDataSource(path, issuerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
  issuer_name = "%s"
}

data "vault_pki_secret_backend_issuer" "test" {
  backend     = vault_mount.test.path
  issuer_ref  = vault_pki_secret_backend_root_cert.test.issuer_id
}`, path, issuerName)
}
