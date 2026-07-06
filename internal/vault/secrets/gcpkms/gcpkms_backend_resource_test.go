// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
					// credentials_wo is write-only and must never appear in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCredentialsWO),
				),
			},
			{
				Config: testGCPKMSSecretBackend_updateConfig(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldScopes+".#", "2"),
					// credentials_wo must remain absent from state after update too
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCredentialsWO),
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
					// credentials_wo is write-only and must never appear in state
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCredentialsWO),
				),
			},
			{
				Config: testGCPKMSSecretBackend_writeOnlyUpdateConfig(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "2"),
					// credentials_wo must remain absent from state after credential rotation
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldCredentialsWO),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackend_mountConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_mountConfigInitial(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, consts.MountTypeGCPKMS),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "GCP KMS secrets engine"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldForceNoCache, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldListingVisibility, "hidden"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".0", "path"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".0", "accessor"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassthroughRequestHeaders+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassthroughRequestHeaders+".0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedResponseHeaders+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedResponseHeaders+".0", "X-Response-Header"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				Config: testGCPKMSSecretBackend_mountConfigUpdated(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, consts.MountTypeGCPKMS),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "Updated GCP KMS secrets engine"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "14400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldForceNoCache, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldListingVisibility, "hidden"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassthroughRequestHeaders+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedResponseHeaders+".#", "2"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
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

func TestGCPKMSSecretBackend_mountConfigImmutable(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_mountConfigImmutable(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "true"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
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

func TestGCPKMSSecretBackend_mountConfigDefaults(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_mountConfigDefaults(path, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, consts.MountTypeGCPKMS),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
					// Verify defaults are applied
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldForceNoCache, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "false"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
		},
	})
}

func TestGCPKMSSecretBackend_pathRequiresReplace(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	updatedPath := acctest.RandomWithPrefix("tf-test-gcpkms-updated")
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
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				Config: testGCPKMSSecretBackend_initialConfig(updatedPath, credentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
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

func TestGCPKMSSecretBackend_emptyCredentials(t *testing.T) {
	// This test verifies that empty credentials are accepted by Vault.
	// When empty, Vault will attempt to use Default Application Credentials.
	path := acctest.RandomWithPrefix("tf-test-gcpkms")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_emptyCredentialsConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_gcpkms_secret_backend.test", consts.FieldPath, path),
					resource.TestCheckResourceAttr("vault_gcpkms_secret_backend.test", consts.FieldCredentialsWOVersion, "1"),
					// credentials_wo is write-only and must never appear in state
					resource.TestCheckNoResourceAttr("vault_gcpkms_secret_backend.test", consts.FieldCredentialsWO),
				),
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

// TestGCPKMSSecretBackend_mountConfigEnterprise covers the Enterprise-only mount
// fields identity_token_key and delegated_auth_accessors, which require a Vault
// Enterprise server running 1.17+.
func TestGCPKMSSecretBackend_mountConfigEnterprise(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion117)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_mountConfigEnterprise(path, credentials, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDelegatedAuthAccessors+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDelegatedAuthAccessors+".0", "header1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDelegatedAuthAccessors+".1", "header2"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				Config: testGCPKMSSecretBackend_mountConfigEnterprise(path, credentials, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenKey, "tf-test-gcpkms-key"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDelegatedAuthAccessors+".#", "3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDelegatedAuthAccessors+".0", "header1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDelegatedAuthAccessors+".1", "header2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDelegatedAuthAccessors+".2", "header3"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
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

// TestGCPKMSSecretBackend_managedKeys covers the Enterprise-only mount field
// allowed_managed_keys, which requires a Vault Enterprise server and a managed
// key registered in Vault.
func TestGCPKMSSecretBackend_managedKeys(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")
	keyName := acctest.RandomWithPrefix("kms-key")
	credentials, _ := testutil.GetTestGCPKMSCreds(t)

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_managedKeysConfig(keyName, path, credentials, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedManagedKeys+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedManagedKeys+".0", keyName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
			{
				Config: testGCPKMSSecretBackend_managedKeysConfig(keyName, path, credentials, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedManagedKeys+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedManagedKeys+".0", keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedManagedKeys+".1", fmt.Sprintf("%s-2", keyName)),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAccessor),
				),
			},
		},
	})
}

func testGCPKMSSecretBackend_mountConfigInitial(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                         = "%s"
  description                  = "GCP KMS secrets engine"
  default_lease_ttl_seconds    = 3600
  max_lease_ttl_seconds        = 7200
  force_no_cache               = true
  listing_visibility           = "hidden"
  audit_non_hmac_request_keys  = ["path"]
  audit_non_hmac_response_keys = ["accessor"]
  passthrough_request_headers  = ["X-Custom-Header"]
  allowed_response_headers     = ["X-Response-Header"]
  credentials_wo               = <<-EOT
%s
EOT
  credentials_wo_version       = 1
}
`, path, credentials)
}

func testGCPKMSSecretBackend_mountConfigUpdated(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                         = "%s"
  description                  = "Updated GCP KMS secrets engine"
  default_lease_ttl_seconds    = 7200
  max_lease_ttl_seconds        = 14400
  force_no_cache               = true
  listing_visibility           = "hidden"
  audit_non_hmac_request_keys  = ["path", "data"]
  audit_non_hmac_response_keys = ["accessor", "data"]
  passthrough_request_headers  = ["X-Custom-Header", "X-Another-Header"]
  allowed_response_headers     = ["X-Response-Header", "X-Other-Header"]
  credentials_wo               = <<-EOT
%s
EOT
  credentials_wo_version       = 1
}
`, path, credentials)
}

func testGCPKMSSecretBackend_mountConfigImmutable(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                    = "%s"
  local                   = true
  seal_wrap               = true
  external_entropy_access = true
  credentials_wo          = <<-EOT
%s
EOT
  credentials_wo_version  = 1
}
`, path, credentials)
}

func testGCPKMSSecretBackend_mountConfigDefaults(path, credentials string) string {
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

func testGCPKMSSecretBackend_emptyCredentialsConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  credentials_wo         = ""
  credentials_wo_version = 1
}
`, path)
}

// testGCPKMSSecretBackend_mountConfigEnterprise generates a config exercising the
// Enterprise-only mount fields delegated_auth_accessors and (on update)
// identity_token_key.
func testGCPKMSSecretBackend_mountConfigEnterprise(path, credentials string, isUpdate bool) string {
	if !isUpdate {
		return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                     = "%s"
  delegated_auth_accessors = ["header1", "header2"]
  credentials_wo           = <<-EOT
%s
EOT
  credentials_wo_version   = 1
}
`, path, credentials)
	}

	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "test" {
  name      = "tf-test-gcpkms-key"
  algorithm = "RS256"
}

resource "vault_gcpkms_secret_backend" "test" {
  path                     = "%s"
  delegated_auth_accessors = ["header1", "header2", "header3"]
  identity_token_key       = vault_identity_oidc_key.test.name
  credentials_wo           = <<-EOT
%s
EOT
  credentials_wo_version   = 1
}
`, path, credentials)
}

// testGCPKMSSecretBackend_managedKeysConfig generates a config exercising the
// Enterprise-only mount field allowed_managed_keys.
func testGCPKMSSecretBackend_managedKeysConfig(name, path, credentials string, isUpdate bool) string {
	ret := fmt.Sprintf(`
resource "vault_managed_keys" "keys" {
  aws {
    name       = "%s"
    access_key = "ASIAKBASDADA09090"
    secret_key = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
    key_bits   = "2048"
    key_type   = "RSA"
    kms_key    = "alias/test_identifier_string"
  }

  aws {
    name       = "%s-2"
    access_key = "ASIAKBASDADA09090"
    secret_key = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
    key_bits   = "2048"
    key_type   = "RSA"
    kms_key    = "alias/test_identifier_string"
  }
}
`, name, name)

	if !isUpdate {
		ret += fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  allowed_managed_keys   = [tolist(vault_managed_keys.keys.aws)[0].name]
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}
`, path, credentials)
	} else {
		ret += fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path                   = "%s"
  allowed_managed_keys   = vault_managed_keys.keys.aws[*].name
  credentials_wo         = <<-EOT
%s
EOT
  credentials_wo_version = 1
}
`, path, credentials)
	}

	return ret
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
