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

func TestGCPSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")

	resourceType := "vault_gcp_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGCP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"hello\":\"world\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			{
				Config: testGCPSecretBackend_updateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"how\":\"goes\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "true"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion117Ent), nil
				},
				Config: testGCPSecretBackend_WIFConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountEmail, "test"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDisableRemount),
		},
	})
}

func TestGCPSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")
	updatedPath := acctest.RandomWithPrefix("tf-test-gcp-updated")

	resourceType := "vault_gcp_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGCP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"hello\":\"world\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			{
				Config: testGCPSecretBackend_initialConfig(updatedPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "credentials", "{\"hello\":\"world\"}"),
					resource.TestCheckResourceAttr(resourceName, "local", "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "credentials", "disable_remount"),
		},
	})
}

func testGCPSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<EOF
{
  "hello": "world"
}
EOF
  description = "test description"
  default_lease_ttl_seconds = 3600
}`, path)
}

func testGCPSecretBackend_WIFConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path                    = "%s"
  service_account_email   = "test"
  identity_token_audience = "test"
  identity_token_ttl      = 30
}`, path)
}

func testGCPSecretBackend_updateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<EOF
{
  "how": "goes"
}
EOF
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  local = true
}`, path)
}
