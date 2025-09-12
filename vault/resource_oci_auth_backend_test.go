// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccOCIAuthBackendConfig_import(t *testing.T) {
	path := acctest.RandomWithPrefix("oci")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckOCIAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOCIAuthBackendConfig_basic(path),
				Check:  testAccOCIAuthBackendConfigCheck_attrs(path),
			},
			{
				ResourceName:      "vault_oci_auth_backend.config",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"disable_remount",
				},
			},
		},
	})
}

func TestAccOCIAuthBackendConfig_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("oci")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccCheckOCIAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOCIAuthBackendConfig_basic(path),
				Check:  testAccOCIAuthBackendConfigCheck_attrs(path),
			},
			{
				Config: testAccOCIAuthBackendConfig_updated(path),
				Check:  testAccOCIAuthBackendConfigCheck_attrs(path),
			},
		},
	})
}

func TestAccOCIAuthBackendConfig_tuning(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("oci-tune")
	resourceName := "vault_oci_auth_backend.oci"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckOCIAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOCIAuthBackendConfig_tune_partial(path),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
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
				Config: testAccOCIAuthBackendConfig_tune_full(path),
				Check: resource.ComposeAggregateTestCheckFunc(
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

func TestAccOCIAuthBackendConfig_importTune(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("oci-import-tune")
	resourceName := "vault_oci_auth_backend.oci"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckOCIAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOCIAuthBackendConfig_tune_full(path),
				Check: testutil.TestAccCheckAuthMountExists(resourceName,
					&resAuth,
					testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDisableRemount),
		},
	})
}

func testAccCheckOCIAuthBackendConfigDestroy(s *terraform.State) error {
	config := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_oci_auth_backend" {
			continue
		}
		secret, err := config.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for OCI auth backend %q config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("OCI auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccOCIAuthBackendConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "config" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
}
`, path)
}

func testAccOCIAuthBackendConfigCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_oci_auth_backend.config"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := "auth/" + backend + "/config"

		if backend != instanceState.ID {
			return fmt.Errorf("expected ID to be %q, got %q", backend, instanceState.ID)
		}

		config := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
		resp, err := config.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back oci auth config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("OCI auth not configured at %q", endpoint)
		}
		attrs := map[string]string{
			"home_tenancy_id": "home_tenancy_id",
		}

		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			if resp.Data[apiAttr] != instanceState.Attributes[stateAttr] {
				return fmt.Errorf("expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccOCIAuthBackendConfig_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "config" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
}`, backend)
}

func testAccOCIAuthBackendConfig_tune_partial(path string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "oci" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
  tune {
    audit_non_hmac_request_keys = ["key1"]
	audit_non_hmac_response_keys = ["key3"]
	passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
	allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
  }
}
`, path)
}

func testAccOCIAuthBackendConfig_tune_full(path string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "oci" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
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
`, path)
}
