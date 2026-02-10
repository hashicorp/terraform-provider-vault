// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPCA_generate(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCA_generateConfig(path, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "31536000"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "ttl", "key_type", "key_bits"),
		},
	})
}

// TestAccKMIPCA_import is skipped because it requires a valid CA certificate
// To test import functionality, you would need to provide a real CA certificate
// func TestAccKMIPCA_import(t *testing.T) {
// 	testutil.SkipTestAccEnt(t)
// 	t.Skip("Skipping import test - requires valid CA certificate")
// }

func testKMIPCA_generateConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
  description                  = "test description"
  listen_addrs                 = ["127.0.0.1:5696"]
  server_hostnames             = ["localhost"]
  tls_ca_key_type              = "ec"
  tls_ca_key_bits              = 256
  default_tls_client_key_type  = "ec"
  default_tls_client_key_bits  = 256
  default_tls_client_ttl       = 86400
}

resource "vault_kmip_secret_ca" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "%s"
  key_type = "ec"
  key_bits = 256
  ttl      = 31536000
}`, path, name)
}

func testKMIPCA_importConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
  description                  = "test description"
  listen_addrs                 = ["127.0.0.1:5696"]
  server_hostnames             = ["localhost"]
  tls_ca_key_type              = "ec"
  tls_ca_key_bits              = 256
  default_tls_client_key_type  = "ec"
  default_tls_client_key_bits  = 256
  default_tls_client_ttl       = 86400
}

resource "vault_kmip_secret_ca" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "test-scope"
  role_name  = "test-role"
}`, path, name, caPem)
}

func testKMIPCA_importUpdateConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
  description                  = "test description"
  listen_addrs                 = ["127.0.0.1:5696"]
  server_hostnames             = ["localhost"]
  tls_ca_key_type              = "ec"
  tls_ca_key_bits              = 256
  default_tls_client_key_type  = "ec"
  default_tls_client_key_bits  = 256
  default_tls_client_ttl       = 86400
}

resource "vault_kmip_secret_ca" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "updated-scope"
  role_name  = "updated-role"
}`, path, name, caPem)
}

// Made with Bob
