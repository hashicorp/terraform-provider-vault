// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestGCPKMSSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_initialConfig(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
				),
			},
			{
				Config: testGCPKMSSecretBackend_updateConfig(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldScopes+".#", "2"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccGCPKMSSecretBackendImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore: []string{
					consts.FieldCredentialsWO,
					consts.FieldCredentialsWOVersion,
				},
			},
		},
	})
}

func TestGCPKMSSecretBackend_writeOnly(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_writeOnlyConfig(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "1"),
				),
			},
			{
				Config: testGCPKMSSecretBackend_writeOnlyUpdateConfig(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "2"),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackend_validation(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testGCPKMSSecretBackend_noCredentialsConfig(path),
				ExpectError: regexp.MustCompile(`(Missing required argument|Missing required attribute)`),
			},
		},
	})
}

func TestGCPKMSSecretBackend_emptyCredentials(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testGCPKMSSecretBackend_emptyCredentialsConfig(path),
				ExpectError: regexp.MustCompile(`Missing credentials`),
			},
		},
	})
}

func TestGCPKMSSecretBackend_namespace(t *testing.T) {
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	getSteps := func(path, ns string) []resource.TestStep {
		var commonChecks []resource.TestCheckFunc
		commonChecks = append(commonChecks,
			resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
		)
		if ns != "" {
			commonChecks = append(commonChecks,
				resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
			)
		}

		steps := []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_nsConfig(path, credentials, ns),
				Check:  resource.ComposeTestCheckFunc(commonChecks...),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccGCPKMSSecretBackendImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldPath,
				ImportStateVerifyIgnore: []string{
					consts.FieldCredentialsWO,
					consts.FieldCredentialsWOVersion,
				},
				PreConfig: func() {
					if ns != "" {
						t.Setenv(consts.EnvVarVaultNamespaceImport, ns)
					}
				},
			},
			{
				// Cleanup step: unset the env var and verify no drift
				Config:   testGCPKMSSecretBackend_nsConfig(path, credentials, ns),
				PlanOnly: true,
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
			},
		}
		return steps
	}

	t.Run("basic", func(t *testing.T) {
		path := acctest.RandomWithPrefix("tf-test-gcpkms")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
			ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
			Steps:                    getSteps(path, ""),
		})
	})

	t.Run("ns", func(t *testing.T) {
		path := acctest.RandomWithPrefix("tf-test-gcpkms")
		ns := acctest.RandomWithPrefix("tf-test-ns")
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
			ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
			Steps:                    getSteps(path, ns),
		})
	})
}

func testGCPKMSSecretBackend_initialConfig(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}
`, path, credentials)
}

func testGCPKMSSecretBackend_updateConfig(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
  scopes = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/cloudkms"
  ]
}
`, path, credentials)
}

func testGCPKMSSecretBackend_writeOnlyConfig(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}
`, path, credentials)
}

func testGCPKMSSecretBackend_writeOnlyUpdateConfig(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 2
}
`, path, credentials)
}

func testGCPKMSSecretBackend_noCredentialsConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path = "%s"
}
`, path)
}

func testGCPKMSSecretBackend_emptyCredentialsConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = ""
  credentials_wo_version = 1
}
`, path)
}

// testGCPKMSSecretBackend_nsConfig generates a config that mounts the backend
// inside a specific namespace when ns is non-empty, or at root when ns is "".
func testGCPKMSSecretBackend_nsConfig(path, credentials, ns string) string {
	nsBlock := ""
	namespaceAttr := ""
	if ns != "" {
		nsBlock = fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}
`, ns)
		namespaceAttr = `  namespace = vault_namespace.test.path`
	}

	return fmt.Sprintf(`
%s
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
%s
}
`, nsBlock, path, credentials, namespaceAttr)
}

func testAccGCPKMSSecretBackendImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes[consts.FieldPath], nil
	}
}
