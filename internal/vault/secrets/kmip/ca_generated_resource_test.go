// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPCAGenerated_basic(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca_generated"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCAGenerated_basicConfig(path, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "31536000"),
					resource.TestCheckResourceAttrSet(resourceName, "ca_pem"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKMIPCAGeneratedImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore:              []string{"ttl", "key_type", "key_bits"},
			},
		},
	})
}

func TestAccKMIPCAGenerated_rsa(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca_generated"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCAGenerated_rsaConfig(path, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "key_bits", "2048"),
					resource.TestCheckResourceAttrSet(resourceName, "ca_pem"),
				),
			},
		},
	})
}

func TestAccKMIPCAGenerated_customTTL(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca_generated"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCAGenerated_customTTLConfig(path, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "key_bits", "384"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "63072000"),
					resource.TestCheckResourceAttrSet(resourceName, "ca_pem"),
				),
			},
		},
	})
}

func testAccKMIPCAGeneratedImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/ca/%s", rs.Primary.Attributes[consts.FieldPath], rs.Primary.Attributes[consts.FieldName]), nil
	}
}

func testKMIPCAGenerated_basicConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_generated" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "%s"
  key_type = "ec"
  key_bits = 256
  ttl      = 31536000
}`, path, name)
}

func testKMIPCAGenerated_rsaConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_generated" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "%s"
  key_type = "rsa"
  key_bits = 2048
}`, path, name)
}

func testKMIPCAGenerated_customTTLConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_generated" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "%s"
  key_type = "ec"
  key_bits = 384
  ttl      = 63072000
}`, path, name)
}

// Made with Bob
