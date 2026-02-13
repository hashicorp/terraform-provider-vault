// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
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
	acctestutil.SkipTestAcc(t)

	var resAuthFirst api.AuthMount
	path := resource.PrefixedUniqueId("gcp-basic-")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"
	description := "GCP Auth Mount"
	updatedDescription := "GCP Auth Mount updated"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials, description),
				Check:  testGCPAuthBackendCheck_attrs(resourceName),
			},
			{
				Config: testGCPAuthBackendConfig_update(path, gcpJSONCredentials, updatedDescription),
				Check: resource.ComposeAggregateTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuthFirst,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					testGCPAuthBackendCheck_attrs(resourceName),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.#", "1"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.%", "4"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.api", "www.googleapis.com"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.iam", "iam.googleapis.com"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.crm", "cloudresourcemanager.googleapis.com"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.compute", "compute.googleapis.com"),
					resource.TestCheckResourceAttr(resourceName, "description", updatedDescription),
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "batch"),
				),
			},
			{
				Config: testGCPAuthBackendConfig_update_partial(path, gcpJSONCredentials),
				Check: resource.ComposeAggregateTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuthFirst,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					testGCPAuthBackendCheck_attrs(resourceName),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.#", "1"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.%", "4"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.api", ""),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.iam", ""),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.crm", "example.com:9200"),
					resource.TestCheckResourceAttr(resourceName,
						"custom_endpoint.0.compute", "compute.example.com"),
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "50m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "1h10m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.2", "X-Mas"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.2", "X-Mas-Response"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "default-batch"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"credentials",
					"disable_remount",
				},
			},
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials, description),
				Check: resource.ComposeAggregateTestCheckFunc(
					testGCPAuthBackendCheck_attrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "custom_endpoint.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "description", description),
				),
			},
			{
				ResourceName:      resourceName,
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

func TestGCPAuthBackend_WIF(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-gcp-auth")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackend_WIFConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountEmail, "test"),
				),
			},
			{
				Config: testGCPAuthBackend_WIFConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudience, "test-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenKey, "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountEmail, "test-updated"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldCredentials,
				consts.FieldDisableRemount,
				consts.FieldIdentityTokenKey,
			),
		},
	})
}

// TestGCPAuthBackend_credentials_wo ensures write-only attribute
// `credentials_wo` works as expected
//
// Since we cannot read the credentials value back from Vault
// there is no way of actually confirming that it is updated.
// Hence, we ensure that the `credentials_wo_version` parameter
// gets updated appropriately.
func TestGCPAuthBackend_credentials_wo(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp-wo")

	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_credentialsWO(path, gcpJSONCredentials, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "1"),
				),
			},
			{
				Config: testGCPAuthBackendConfig_credentialsWO(path, gcpJSONCredentials, 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCredentialsWOVersion, "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldDisableRemount,
				consts.FieldCredentialsWO,
				consts.FieldCredentialsWOVersion,
			),
		},
	})
}

func TestGCPAuthBackend_credentialsConflict(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp-conflict")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testGCPAuthBackendConfig_credentialsConflict(path, gcpJSONCredentials),
				ExpectError: regexp.MustCompile("Conflicting configuration arguments"),
				Destroy:     false,
			},
		},
	})
}

func TestGCPAuthBackend_import(t *testing.T) {
	path := resource.PrefixedUniqueId("gcp-import-")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"
	description := "GCP Auth Mount"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials, description),
				Check:  testGCPAuthBackendCheck_attrs(resourceName),
			},
			{
				ResourceName:      resourceName,
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
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"
	description := "GCP Auth Mount"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials, description),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendCheck_attrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "path", path),
				),
			},
			{
				Config: testGCPAuthBackendConfig_basic(updatedPath, gcpJSONCredentials, description),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendCheck_attrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "credentials", "disable_remount"),
		},
	})
}
func TestAccGCPAuthBackend_tuning(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("gcp-tune-")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"
	description := "GCP Auth Mount Tune"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_tune_partial(path, gcpJSONCredentials, description),
				Check: resource.ComposeAggregateTestCheckFunc(
					testGCPAuthBackendCheck_attrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", ""),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
				),
			},
			{
				Config: testGCPAuthBackendConfig_tune_full(path, gcpJSONCredentials, description),
				Check: resource.ComposeAggregateTestCheckFunc(
					testGCPAuthBackendCheck_attrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "batch"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
				),
			},
		},
	})
}

func TestAccGCPAuthBackend_importTune(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("gcp-import-tune-")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"
	description := "GCP Auth Mount Import Tune"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_tune_full(path, gcpJSONCredentials, description),
				Check: resource.ComposeAggregateTestCheckFunc(
					testGCPAuthBackendCheck_attrs(resourceName),
					testutil.TestAccCheckAuthMountExists(resourceName, &resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDescription, consts.FieldCredentials, consts.FieldDisableRemount),
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

func testGCPAuthBackendCheck_attrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[resourceName]
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

// TestAccGCPAuthBackend_automatedRotation tests that Automated
// Root Rotation parameters are compatible with the GCP Auth Backend
// resource
func TestAccGCPAuthBackendClient_automatedRotation(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeGCP, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGCPAuthBackendConfigAutomatedRootRotation(path, "", 10, 0, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// zero-out rotation_period
			{
				Config: testAccGCPAuthBackendConfigAutomatedRootRotation(path, "*/20 * * * *", 0, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			{
				Config:      testAccGCPAuthBackendConfigAutomatedRootRotation(path, "", 30, 120, true),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			// zero-out rotation_schedule and rotation_window
			{
				Config: testAccGCPAuthBackendConfigAutomatedRootRotation(path, "", 30, 0, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldSecretKey, consts.FieldDisableRemount),
		},
	})
}

func testGCPAuthBackendConfig_basic(path, credentials, description string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = %q
}
`, credentials, path, description)
}

func testGCPAuthBackendConfig_update(path, credentials, description string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = %q
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
`, credentials, path, description)
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

func testGCPAuthBackend_WIFConfig_basic(path string) string {
	return fmt.Sprintf(
		`
resource "vault_gcp_auth_backend" "test" {
 path                    = "%s"
 service_account_email   = "test"
 identity_token_audience = "test"
 identity_token_ttl      = 30
}
`, path)
}

func testGCPAuthBackend_WIFConfig_updated(path string) string {
	return fmt.Sprintf(
		`
resource "vault_identity_oidc_key" "test" {
 name               = "test"
 allowed_client_ids = ["*"]
}

resource "vault_gcp_auth_backend" "test" {
 path                    = "%s"
 service_account_email   = "test-updated"
 identity_token_audience = "test-updated"
 identity_token_ttl      = 1800
 identity_token_key      = vault_identity_oidc_key.test.name
}
`, path)
}

func testAccGCPAuthBackendConfigAutomatedRootRotation(path, schedule string, period, window int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_gcp_auth_backend" "test" {
  path = "%s"
  rotation_period = "%d"
  rotation_schedule = "%s"
  rotation_window = "%d"
  disable_automated_rotation = %t
}`, path, period, schedule, window, disable)
}

func testGCPAuthBackendConfig_credentialsWO(path, credentials string, version int) string {
	return fmt.Sprintf(`
variable "json_credentials" {
	type    = string
	default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path                   = %q
  credentials_wo         = var.json_credentials
  credentials_wo_version = %d
}`, credentials, path, version)
}

func testGCPAuthBackendConfig_tune_partial(path, credentials, description string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
	type    = string
	default = %q
}

resource "vault_gcp_auth_backend" "test" {
	path        = %q
	credentials = var.json_credentials
	description = %q
	tune {
		audit_non_hmac_request_keys = ["key1"]
		audit_non_hmac_response_keys = ["key3"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	}
}
`, credentials, path, description)
}

func testGCPAuthBackendConfig_tune_full(path, credentials, description string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
	type    = string
	default = %q
}

resource "vault_gcp_auth_backend" "test" {
	path        = %q
	credentials = var.json_credentials
	description = %q
	tune {
		default_lease_ttl = "10m"
		max_lease_ttl = "20m"
		listing_visibility = "hidden"
		token_type = "batch"
		audit_non_hmac_request_keys = ["key1", "key2"]
		audit_non_hmac_response_keys = ["key3", "key4"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	}
}
`, credentials, path, description)
}

// TestGCPAuthBackend_AliasAndMetadata tests the IAM alias, IAM metadata, GCE alias, and GCE metadata fields
func TestGCPAuthBackend_AliasAndMetadata(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-gcp-alias")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				// Test with default values (not explicitly setting the fields)
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials, "GCP Auth Backend"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMAlias, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceAlias, ""),
					// Check that default metadata fields are present
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".#", "4"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceMetadata+".#", "9"),
				),
			},
			{
				// Test with custom values
				Config: testGCPAuthBackendConfig_aliasAndMetadata(path, gcpJSONCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMAlias, "unique_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceAlias, "instance_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceMetadata+".#", "3"),
				),
			},
			{
				// Test import
				ResourceName:      resourceName,
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

func testGCPAuthBackendConfig_aliasAndMetadata(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = "GCP Auth Backend with Alias and Metadata"
  
  iam_alias = "unique_id"
  iam_metadata = [
    "project_id",
    "role"
  ]
  
  gce_alias = "instance_id"
  gce_metadata = [
    "instance_id",
    "instance_name",
    "project_id"
  ]
}
`, credentials, path)
}

// TestGCPAuthBackend_AliasAndMetadataUpdate tests updating the IAM alias, IAM metadata, GCE alias, and GCE metadata fields
func TestGCPAuthBackend_AliasAndMetadataUpdate(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-gcp-alias-update")
	resourceType := "vault_gcp_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				// Start with custom values
				Config: testGCPAuthBackendConfig_aliasAndMetadata(path, gcpJSONCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMAlias, "unique_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceAlias, "instance_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceMetadata+".#", "3"),
				),
			},
			{
				// Update to different values
				Config: testGCPAuthBackendConfig_aliasAndMetadataUpdated(path, gcpJSONCredentials),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMAlias, "role_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceAlias, "role_id"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIAMMetadata+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGceMetadata+".#", "2"),
				),
			},
		},
	})
}

func testGCPAuthBackendConfig_aliasAndMetadataUpdated(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = "GCP Auth Backend with Updated Alias and Metadata"
  
  iam_alias = "role_id"
  iam_metadata = [
    "project_id"
  ]
  
  gce_alias = "role_id"
  gce_metadata = [
    "instance_name",
    "project_id"
  ]
}
`, credentials, path)
}

// TestGCPAuthBackend_InvalidAlias tests that invalid values for iam_alias and gce_alias are rejected
func TestGCPAuthBackend_InvalidAlias(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-gcp-invalid-alias")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				// Test invalid iam_alias value
				Config:      testGCPAuthBackendConfig_invalidIAMAlias(path, gcpJSONCredentials),
				ExpectError: regexp.MustCompile(`expected iam_alias to be one of \["role_id" "unique_id"\], got invalid_value`),
			},
			{
				// Test invalid gce_alias value
				Config:      testGCPAuthBackendConfig_invalidGCEAlias(path, gcpJSONCredentials),
				ExpectError: regexp.MustCompile(`expected gce_alias to be one of \["role_id" "instance_id"\], got invalid_value`),
			},
		},
	})
}

func testGCPAuthBackendConfig_invalidIAMAlias(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = "GCP Auth Backend with Invalid IAM Alias"
  
  iam_alias = "invalid_value"
}
`, credentials, path)
}

func testGCPAuthBackendConfig_invalidGCEAlias(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = "GCP Auth Backend with Invalid GCE Alias"
  
  gce_alias = "invalid_value"
}
`, credentials, path)
}

// TestGCPAuthBackend_InvalidMetadata tests that invalid metadata fields are handled properly
func TestGCPAuthBackend_InvalidMetadata(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	iamPath := acctest.RandomWithPrefix("tf-test-gcp-invalid-iam-metadata")
	gcePath := acctest.RandomWithPrefix("tf-test-gcp-invalid-gce-metadata")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				// Test with non-existent IAM metadata fields
				Config:      testGCPAuthBackendConfig_invalidIAMMetadata(iamPath, gcpJSONCredentials),
				ExpectError: regexp.MustCompile(`failed to parse iam metadata: .* contains an unavailable field, please select from "project_id, role, service_account_id, service_account_email"`),
			},
			{
				// Test with non-existent GCE metadata fields
				Config:      testGCPAuthBackendConfig_invalidGCEMetadata(gcePath, gcpJSONCredentials),
				ExpectError: regexp.MustCompile(`failed to parse gce metadata: .* contains an unavailable field, please select from "instance_creation_timestamp, instance_id, instance_name, project_id, project_number, role, service_account_id, service_account_email, zone"`),
			},
		},
	})
}

func testGCPAuthBackendConfig_invalidIAMMetadata(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = "GCP Auth Backend with Invalid IAM Metadata"
  
  iam_metadata = [
    "non_existent_field_1",
    "non_existent_field_2"
  ]
}
`, credentials, path)
}

func testGCPAuthBackendConfig_invalidGCEMetadata(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path        = %q
  credentials = var.json_credentials
  description = "GCP Auth Backend with Invalid GCE Metadata"
  
  gce_metadata = [
    "non_existent_field_1",
    "non_existent_field_2"
  ]
}
`, credentials, path)
}

func testGCPAuthBackendConfig_credentialsConflict(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type    = string
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path                   = %q
  credentials            = var.json_credentials
  credentials_wo         = var.json_credentials
  credentials_wo_version = 1
}
`, credentials, path)
}
