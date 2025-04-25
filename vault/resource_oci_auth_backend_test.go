// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccOCIAuthBackendConfig_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("oci")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckOCIAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOCIAuthBackendConfig_basic(backend),
				Check:  testAccOCIAuthBackendConfigCheck_attrs(backend),
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
	backend := acctest.RandomWithPrefix("oci")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccCheckOCIAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOCIAuthBackendConfig_basic(backend),
				Check:  testAccOCIAuthBackendConfigCheck_attrs(backend),
			},
			{
				Config: testAccOCIAuthBackendConfig_updated(backend),
				Check:  testAccOCIAuthBackendConfigCheck_attrs(backend),
			},
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

func testAccOCIAuthBackendConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "config" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
}
`, backend)
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
