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
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestLDAPAuthBackendGroup_import(t *testing.T) {
	t.Parallel()
	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	groupname := acctest.RandomWithPrefix("tf-test-ldap-group")

	policies := []string{
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
	}

	resourceName := "vault_ldap_auth_backend_group.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPAuthBackendGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendGroupConfig_basic(backend, groupname, policies),
				Check:  testLDAPAuthBackendGroupCheck_attrs(resourceName, backend, groupname),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestLDAPAuthBackendGroup_basic(t *testing.T) {
	t.Parallel()
	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	groupname := acctest.RandomWithPrefix("tf-test-ldap-group")

	policies := []string{
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
	}

	resourceName := "vault_ldap_auth_backend_group.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPAuthBackendGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendGroupConfig_basic(backend, groupname, policies),
				Check:  testLDAPAuthBackendGroupCheck_attrs(resourceName, backend, groupname),
			},
		},
	})
}

func testLDAPAuthBackendGroupDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_auth_backend_group" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for ldap auth backend group %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("ldap auth backend group %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testLDAPAuthBackendGroupCheck_attrs(resourceName, backend, groupname string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		path := rs.Primary.ID
		endpoint := "auth/" + strings.Trim(backend, "/") + "/groups/" + groupname
		if endpoint != path {
			return fmt.Errorf("expected id to be %q, got %q instead", endpoint, path)
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}
		authMount := authMounts[strings.Trim(backend, "/")+"/"]

		if authMount == nil {
			return fmt.Errorf("auth mount %s not present", backend)
		}

		if "ldap" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		attrs := map[string]string{
			"policies": "policies",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testLDAPAuthBackendGroupConfig_basic(backend, groupname string, policies []string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "ldap" {
    path = "%s"
    type = "ldap"
}

resource "vault_ldap_auth_backend_group" "test" {
    backend   = vault_auth_backend.ldap.path
    groupname = "%s"
    policies  = %s
}
`, backend, groupname, util.ArrayToTerraformList(policies))
}
