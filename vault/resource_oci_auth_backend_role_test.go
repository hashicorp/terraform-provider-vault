// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestOCIAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-oci-backend")
	name := acctest.RandomWithPrefix("tf-test-oci-role")

	resourceName := "vault_oci_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testOCIAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testOCIAuthBackendRoleConfig_basic(backend, name),
				Check:  testOCIAuthBackendRoleCheck_attrs(resourceName, backend, name),
			},
		},
	})
}

func TestOCIAuthBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-oci-backend")
	name := acctest.RandomWithPrefix("tf-test-oci-role")

	resourceName := "vault_oci_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testOCIAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testOCIAuthBackendRoleConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					testOCIAuthBackendRoleCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "300"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "600"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
				),
			},
			{
				Config: testOCIAuthBackendRoleUnset(backend, name),
				Check: resource.ComposeTestCheckFunc(
					testOCIAuthBackendRoleCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "0"),
				),
			},
		},
	})
}

func testOCIAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_oci_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for OCI auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("OCI auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testOCIAuthBackendRoleCheck_attrs(resourceName, backend, name string) resource.TestCheckFunc {
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

		if "oci" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}
		attrs := map[string]string{
			"ocid_list": "ocid_list",
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

func testOCIAuthBackendRoleConfig_basic(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "config" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
}

resource "vault_oci_auth_backend_role" "test" {
    backend        = vault_oci_auth_backend.config.path
    name           = "%s"
    ocid_list      = ["ocid1.group.oc1..aaaaaaaabmyiinfq32y5aha3r2yo4exampleo4yg3fjk2sbne4567tropaa", "ocid1.dynamicgroup.oc1..aaaaaaaabvfwct33xri5examplegov4zyjp3rd5d7sk9jjdggxijhco56hrq"]
    token_ttl      = 300
    token_max_ttl  = 600
    token_policies = ["policy_a", "policy_b"]
}
`, backend, name)
}

func testOCIAuthBackendRoleConfig(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "config" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
}

resource "vault_oci_auth_backend_role" "test" {
    backend        = vault_oci_auth_backend.config.path
    name           = "%s"
    token_ttl      = 300
    token_max_ttl  = 600
    token_policies = ["policy_a", "policy_b"]
    ocid_list      = ["ocid1.dynamicgroup.oc1..aaaaaaaabvfwc45fh7dkexampleov4zyjp3rd5d7sk95jjdggdijhco5793f"]
}
`, backend, name)
}

func testOCIAuthBackendRoleUnset(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_oci_auth_backend" "config" {
  path = "%s"
  home_tenancy_id = "ocid1.tenancy.oc1..aaaaaaaah7zkvaffv26pzyauoe2zbnionqvhvsexamplee557wakiofi4ysgqq"
}

resource "vault_oci_auth_backend_role" "test" {
    backend   = vault_oci_auth_backend.config.path
    name      = "%s"
    ocid_list = ["ocid1.dynamicgroup.oc1..aaaaaaaabvfwc45fh7dkexampleov4zyjp3rd5d7sk95jjdggdijhco5793f"]
}
`, backend, name)
}
