// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestGCPKMSSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentials, "{\"test\":\"credentials\"}"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: testGCPKMSSecretBackend_updateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldScopes+".#", "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldCredentials,
				consts.FieldCredentialsWO,
			),
		},
	})
}

func TestGCPKMSSecretBackend_writeOnly(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcpkms")

	resourceType := "vault_gcpkms_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGCPKMSSecretBackend_writeOnlyConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWO, "{\"test\":\"credentials_wo\"}"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "1"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				Config: testGCPKMSSecretBackend_writeOnlyUpdateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWO, "{\"test\":\"updated_credentials\"}"),
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
				ExpectError: regexp.MustCompile("Missing required field"),
			},
			{
				Config:      testGCPKMSSecretBackend_conflictingCredentialsConfig(path),
				ExpectError: regexp.MustCompile("Conflicting fields"),
			},
		},
	})
}

func testGCPKMSSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = "{\"test\":\"credentials\"}"
}
`, path)
}

func testGCPKMSSecretBackend_updateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path        = "%s"
  credentials = "{\"test\":\"credentials\"}"
  scopes      = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/cloudkms"
  ]
}
`, path)
}

func testGCPKMSSecretBackend_writeOnlyConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path           = "%s"
  credentials_wo = "{\"test\":\"credentials_wo\"}"
  credentials_wo_version = 1
}
`, path)
}

func testGCPKMSSecretBackend_writeOnlyUpdateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path           = "%s"
  credentials_wo = "{\"test\":\"updated_credentials\"}"
  credentials_wo_version = 2
}
`, path)
}

func testGCPKMSSecretBackend_noCredentialsConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path = "%s"
}
`, path)
}

func testGCPKMSSecretBackend_conflictingCredentialsConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcpkms_secret_backend" "test" {
  path           = "%s"
  credentials    = "{\"test\":\"credentials\"}"
  credentials_wo = "{\"test\":\"credentials_wo\"}"
}
`, path)
}
