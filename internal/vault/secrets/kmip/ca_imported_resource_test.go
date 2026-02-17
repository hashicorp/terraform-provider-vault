// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPCAImported_basic(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca_imported"
	resourceName := resourceType + ".test"

	// Generate a self-signed certificate for testing
	caPem, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCAImported_basicConfig(path, name, caPem),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "scope_name", "test-scope"),
					resource.TestCheckResourceAttr(resourceName, "role_name", "test-role"),
					resource.TestCheckResourceAttrSet(resourceName, "ca_pem"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKMIPCAImportedImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore:              []string{"ca_pem"},
			},
		},
	})
}

func TestAccKMIPCAImported_update(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca_imported"
	resourceName := resourceType + ".test"

	// Generate a self-signed certificate for testing
	caPem, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCAImported_basicConfig(path, name, caPem),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "scope_name", "test-scope"),
					resource.TestCheckResourceAttr(resourceName, "role_name", "test-role"),
				),
			},
			{
				Config: testKMIPCAImported_updateConfig(path, name, caPem),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "scope_name", "updated-scope"),
					resource.TestCheckResourceAttr(resourceName, "role_name", "updated-role"),
				),
			},
		},
	})
}

func TestAccKMIPCAImported_withFields(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca_imported"
	resourceName := resourceType + ".test"

	// Generate a self-signed certificate for testing
	caPem, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCAImported_withFieldsConfig(path, name, caPem),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "scope_field", "CN"),
					resource.TestCheckResourceAttr(resourceName, "role_field", "O"),
				),
			},
		},
	})
}

func TestAccKMIPCAImported_validation(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")

	// Generate a self-signed certificate for testing
	caPem, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				// Test: both scope_name and scope_field should fail
				Config:      testKMIPCAImported_bothScopeFieldsConfig(path, name, caPem),
				ExpectError: regexp.MustCompile("Only one of.*scope_name.*scope_field.*can be specified"),
			},
			{
				// Test: neither scope_name nor scope_field should fail
				Config:      testKMIPCAImported_noScopeFieldsConfig(path, name, caPem),
				ExpectError: regexp.MustCompile("Exactly one of.*scope_name.*scope_field.*must be specified"),
			},
			{
				// Test: both role_name and role_field should fail
				Config:      testKMIPCAImported_bothRoleFieldsConfig(path, name, caPem),
				ExpectError: regexp.MustCompile("Only one of.*role_name.*role_field.*can be specified"),
			},
			{
				// Test: neither role_name nor role_field should fail
				Config:      testKMIPCAImported_noRoleFieldsConfig(path, name, caPem),
				ExpectError: regexp.MustCompile("Exactly one of.*role_name.*role_field.*must be specified"),
			},
		},
	})
}

func testAccKMIPCAImportedImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/ca/%s", rs.Primary.Attributes[consts.FieldPath], rs.Primary.Attributes[consts.FieldName]), nil
	}
}

func testKMIPCAImported_basicConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_imported" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "test-scope"
  role_name  = "test-role"
}`, path, name, caPem)
}

func testKMIPCAImported_updateConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_imported" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "updated-scope"
  role_name  = "updated-role"
}`, path, name, caPem)
}

func testKMIPCAImported_withFieldsConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_imported" "test" {
  path        = vault_kmip_secret_backend.test.path
  name        = "%s"
  ca_pem      = <<EOT
%s
EOT
  scope_field = "CN"
  role_field  = "O"
}`, path, name, caPem)
}

func testKMIPCAImported_bothScopeFieldsConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_imported" "test" {
  path        = vault_kmip_secret_backend.test.path
  name        = "%s"
  ca_pem      = <<EOT
%s
EOT
  scope_name  = "test-scope"
  scope_field = "CN"
  role_name   = "test-role"
}`, path, name, caPem)
}

func testKMIPCAImported_noScopeFieldsConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_imported" "test" {
  path      = vault_kmip_secret_backend.test.path
  name      = "%s"
  ca_pem    = <<EOT
%s
EOT
  role_name = "test-role"
}`, path, name, caPem)
}

func testKMIPCAImported_bothRoleFieldsConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_imported" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "test-scope"
  role_name  = "test-role"
  role_field = "CN"
}`, path, name, caPem)
}

func testKMIPCAImported_noRoleFieldsConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
}

resource "vault_kmip_secret_ca_imported" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "test-scope"
}`, path, name, caPem)
}

// Made with Bob
