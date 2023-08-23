// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const gcpJSONCredentials string = `
{
  "type": "service_account",
  "project_id": "terraform-vault-provider-a13efc8a",
  "private_key_id": "b1e1f3cdd7fc134afsdg3547828dc2bb9dff8480",
  "private_key": "-----BEGIN PRIVATE KEY-----\nABC123\n-----END PRIVATE KEY-----\n",
  "client_email": "terraform-vault-user@terraform-vault-provider-adf134rfds.iam.gserviceaccount.com",
  "client_id": "123134135242342423",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/vault-auth-checker%40terraform-vault-provider-adf134rfds.iam.gserviceaccount.com"
  }
`

func TestGCPAuthBackend_basic(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	var resAuthFirst api.AuthMount
	path := resource.PrefixedUniqueId("gcp-basic-")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials),
				Check:  testGCPAuthBackendCheck_attrs(),
			},
			{
				Config: testGCPAuthBackendConfig_update(path, gcpJSONCredentials),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAuthMountExists("vault_gcp_auth_backend.test", &resAuthFirst),
					testGCPAuthBackendCheck_attrs(),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.%", "4"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.api", "www.googleapis.com"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.iam", "iam.googleapis.com"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.crm", "cloudresourcemanager.googleapis.com"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.compute", "compute.googleapis.com"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.default_lease_ttl", "60s"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.max_lease_ttl", "3600s"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.listing_visibility", "unauth"),
					resource.TestCheckResourceAttrPtr("vault_gcp_auth_backend.test", "accessor", &resAuthFirst.Accessor),
					checkAuthMount("gcp", listingVisibility("unauth")),
					checkAuthMount("gcp", defaultLeaseTtl(60)),
					checkAuthMount("gcp", maxLeaseTtl(3600)),
				),
			},
			{
				Config: testGCPAuthBackendConfig_update_partial(path, gcpJSONCredentials),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckAuthMountExists("vault_gcp_auth_backend.test", &resAuthFirst),
					testGCPAuthBackendCheck_attrs(),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.%", "4"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.api", ""),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.iam", ""),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.crm", "example.com:9200"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.0.compute", "compute.example.com"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.default_lease_ttl", "60s"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.max_lease_ttl", "7200s"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.listing_visibility", ""),
					resource.TestCheckResourceAttrPtr("vault_gcp_auth_backend.test", "accessor", &resAuthFirst.Accessor),
					checkAuthMount("gcp", listingVisibility("unauth")),
					checkAuthMount("gcp", defaultLeaseTtl(60)),
					checkAuthMount("gcp", maxLeaseTtl(7200)),
				),
			},
			{
				ResourceName:      "vault_gcp_auth_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"credentials",
				},
			},
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials),
				Check: resource.ComposeAggregateTestCheckFunc(
					testGCPAuthBackendCheck_attrs(),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test",
						"custom_endpoint.#", "0"),
				),
			},
			{
				ResourceName:      "vault_gcp_auth_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"credentials",
				},
			},
		},
	})
}

func TestGCPAuthBackend_import(t *testing.T) {
	path := resource.PrefixedUniqueId("gcp-import-")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials),
				Check:  testGCPAuthBackendCheck_attrs(),
			},
			{
				ResourceName:      "vault_gcp_auth_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"credentials",
					"disable_remount",
				},
			},
		},
	})
}

func TestGCPAuthBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-auth-gcp")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-gcp-updated")

	resourceName := "vault_gcp_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendCheck_attrs(),
					resource.TestCheckResourceAttr(resourceName, "path", path),
				),
			},
			{
				Config: testGCPAuthBackendConfig_basic(updatedPath, gcpJSONCredentials),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendCheck_attrs(),
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "credentials", "disable_remount"),
		},
	})
}

func testGCPAuthBackendDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_auth_backend" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for gcp auth backend %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("gcp auth backend %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPAuthBackendCheck_attrs() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_gcp_auth_backend.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		return nil
	}
}

func testGCPAuthBackendConfig_basic(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
}
`, credentials, path)
}

func testGCPAuthBackendConfig_update(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  custom_endpoint {
    api     = "www.googleapis.com"
    iam     = "iam.googleapis.com"
    crm     = "cloudresourcemanager.googleapis.com"
    compute = "compute.googleapis.com"
  }
  tune {
    listing_visibility = "unauth"
    max_lease_ttl      = "3600s"
    default_lease_ttl  = "60s"
  }
}
`, credentials, path)
}

func testGCPAuthBackendConfig_update_partial(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  custom_endpoint {
    crm     = "example.com:9200"
    compute = "compute.example.com"
  }
  tune {
    max_lease_ttl      = "7200s"
    default_lease_ttl  = "60s"
  }
}
`, credentials, path)
}
