// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure-backend")
	name := acctest.RandomWithPrefix("tf-test-azure-role")

	resourceName := "vault_azure_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAzureAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureAuthBackendRoleConfig_basic(backend, name),
				Check:  testAzureAuthBackendRoleCheck_attrs(resourceName, backend, name),
			},
		},
	})
}

func TestAzureAuthBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure-backend")
	name := acctest.RandomWithPrefix("tf-test-azure-role")

	resourceName := "vault_azure_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAzureAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureAuthBackendRoleConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					testAzureAuthBackendRoleCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "300"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "600"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
				),
			},
			{
				Config: testAzureAuthBackendRoleUnset(backend, name),
				Check: resource.ComposeTestCheckFunc(
					testAzureAuthBackendRoleCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "0"),
				),
			},
		},
	})
}

func testAzureAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_azure_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for Azure auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Azure auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAzureAuthBackendRoleCheck_attrs(resourceName, backend, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := rs.Primary.ID

		endpoint := "auth/" + strings.Trim(backend, "/") + "/role/" + name
		if endpoint != path {
			return fmt.Errorf("expected ID to be %q, got %q instead", endpoint, path)
		}

		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}
		authMount := authMounts[strings.Trim(backend, "/")+"/"]

		if authMount == nil {
			return fmt.Errorf("auth mount %s not present", backend)
		}

		if "azure" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}
		attrs := map[string]string{
			"bound_service_principal_ids": "bound_service_principal_ids",
			"bound_group_ids":             "bound_group_ids",
			"bound_locations":             "bound_locations",
			"bound_subscription_ids":      "bound_subscription_ids",
			"bound_resource_groups":       "bound_resource_groups",
			"bound_scale_sets":            "bound_scale_sets",
		}

		for _, v := range commonTokenFields {
			attrs[v] = v
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}
			switch k {
			case TokenFieldPolicies:
				ta.AsSet = true
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAzureAuthBackendRoleConfig_basic(backend, name string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "azure" {
    path = "%s"
    type = "azure"
}

resource "vault_azure_auth_backend_role" "test" {
    backend                     = vault_auth_backend.azure.path
    role                        = "%s"
    bound_service_principal_ids = ["foo"]
    bound_resource_groups       = ["bar"]
    token_ttl                   = 300
    token_max_ttl               = 600
    token_policies              = ["policy_a", "policy_b"]
}
`, backend, name)
}

func testAzureAuthBackendRoleConfig(backend, name string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "azure" {
    path = "%s"
    type = "azure"
}

resource "vault_azure_auth_backend_role" "test" {
    backend                    = vault_auth_backend.azure.path
    role                       = "%s"
    token_ttl                  = 300
    token_max_ttl              = 600
    token_policies             = ["policy_a", "policy_b"]
    bound_locations	           = ["west us"]
    bound_resource_groups      = ["test"]
}
`, backend, name)
}

func testAzureAuthBackendRoleUnset(backend, name string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "azure" {
    path = "%s"
    type = "azure"
}

resource "vault_azure_auth_backend_role" "test" {
    backend                    = vault_auth_backend.azure.path
    role                       = "%s"
    bound_locations	           = ["west us"]
    bound_resource_groups      = ["test"]
}
`, backend, name)
}
