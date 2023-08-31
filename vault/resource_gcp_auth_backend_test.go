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
					testutil.TestAccCheckAuthMountExists("vault_gcp_auth_backend.test",
						&resAuthFirst,
						testProvider.Meta().(*provider.ProviderMeta).GetClient()),
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
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.token_type", "batch"),
				),
			},
			{
				Config: testGCPAuthBackendConfig_update_partial(path, gcpJSONCredentials),
				Check: resource.ComposeAggregateTestCheckFunc(
					testutil.TestAccCheckAuthMountExists("vault_gcp_auth_backend.test",
						&resAuthFirst,
						testProvider.Meta().(*provider.ProviderMeta).GetClient()),
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
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.default_lease_ttl", "50m"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.max_lease_ttl", "1h10m"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.audit_non_hmac_response_keys.#", "0"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.passthrough_request_headers.#", "3"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.passthrough_request_headers.2", "X-Mas"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.allowed_response_headers.#", "3"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.allowed_response_headers.2", "X-Mas-Response"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend.test", "tune.0.token_type", "default-batch"),
				),
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
					"disable_remount",
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
	default_lease_ttl = "10m"
	max_lease_ttl = "20m"
	listing_visibility = "hidden"
	audit_non_hmac_request_keys = ["key1", "key2"]
	audit_non_hmac_response_keys = ["key3", "key4"]
	passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
	allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	token_type = "batch"
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
    default_lease_ttl = "50m"
    max_lease_ttl = "1h10m"
    audit_non_hmac_request_keys = ["key1"]
    listing_visibility = "unauth"
    passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To", "X-Mas"]
    allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To", "X-Mas-Response"]
    token_type = "default-batch"
  }
}
`, credentials, path)
}
