// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"testing"
)

func TestScepAuthBackendRolesResource_static_challenge(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-scep-auth")
	name := acctest.RandomWithPrefix("tf-test-scep-name")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion120)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testScepAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_auth_backend" "scep" {
    path = "%s"
    type = "scep"
}
resource "vault_scep_auth_backend_role" "test" {
    backend = vault_auth_backend.scep.id
    name = "%s"
    auth_type = "static-challenge"
    challenge = "super secret"
}
`, backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "display_name", name),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "auth_type", "static-challenge"),
					// Note that the challenge is returned since the resource was just created
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "challenge", "super secret"),
				),
			},
			{
				Config: fmt.Sprintf(`
resource "vault_auth_backend" "scep" {
    path = "%s"
    type = "scep"
}
resource "vault_scep_auth_backend_role" "test" {
    backend = vault_auth_backend.scep.id
    name = "%s"
    display_name = "Almondiga"
    auth_type = "static-challenge"
}
			`, backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "display_name", "Almondiga"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "auth_type", "static-challenge"),
					// Note that the challenge is not returned, since the resource was updated and no new challenge was specified
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "challenge", ""),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if !meta.IsAPISupported(provider.VaultVersion121) {
						return true, nil
					}

					return !meta.IsEnterpriseSupported(), nil
				},
				Config: fmt.Sprintf(`
resource "vault_auth_backend" "scep" {
    path = "%s"
    type = "scep"
}
resource "vault_scep_auth_backend_role" "test" {
    backend = vault_auth_backend.scep.id
    name = "%s"
    display_name = "Almondiga"
    auth_type = "static-challenge"
    %s
}
			`, backend, name, tokenAuthMetadataConfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "display_name", "Almondiga"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "auth_type", "static-challenge"),
					// Note that the challenge is not returned, since the resource was updated and no new challenge was specified
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "challenge", ""),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "token_auth_metadata.%", "1"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.test", "token_auth_metadata.foo", "bar"),
				),
			},
		},
	})
}

func TestScepAuthBackendRolesResource_intune(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-scep-auth")
	name := acctest.RandomWithPrefix("tf-test-scep-name")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion120)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testScepAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_auth_backend" "scep" {
    path = "%s"
    type = "scep"
}
resource "vault_scep_auth_backend_role" "intune" {
    backend        = vault_auth_backend.scep.id
    name           = "%s"
    display_name   = "Intune"
    auth_type      = "intune"
    token_type     = "batch"
    token_ttl      = 300
    token_max_ttl  = 600
    token_policies = ["test_policy_1", "test_policy_2"]
}
`, backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "backend", backend),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "name", name),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "display_name", "Intune"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "auth_type", "intune"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "token_type", "batch"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "token_ttl", "300"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "token_max_ttl", "600"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "token_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "token_policies.0", "test_policy_1"),
					resource.TestCheckResourceAttr("vault_scep_auth_backend_role.intune", "token_policies.1", "test_policy_2"),
				),
			},
		},
	})
}

func testScepAuthBackendDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_scep_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for SCEP auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("SCEP auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}
