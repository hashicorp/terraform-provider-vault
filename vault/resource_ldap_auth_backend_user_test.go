// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
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

func TestLDAPAuthBackendUser_basic(t *testing.T) {
	t.Parallel()
	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	username := acctest.RandomWithPrefix("tf-test-ldap-user")

	policies := []string{
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
	}

	groups := []string{
		acctest.RandomWithPrefix("group"),
		acctest.RandomWithPrefix("group"),
	}

	resourceName := "vault_ldap_auth_backend_user.test"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendUserConfig_basic(backend, username, policies, groups),
				Check: resource.ComposeTestCheckFunc(
					testLDAPAuthBackendUserCheck_attrs(resourceName, backend, username),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestLDAPAuthBackendUser_noGroups(t *testing.T) {
	t.Parallel()
	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	username := acctest.RandomWithPrefix("tf-test-ldap-user")

	var policies []string
	var groups []string

	resourceName := "vault_ldap_auth_backend_user.test"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendUserConfig_basic(backend, username, policies, groups),
				Check: resource.ComposeTestCheckFunc(
					testLDAPAuthBackendUserCheck_attrs(resourceName, backend, username),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestLDAPAuthBackendUser_oneGroup(t *testing.T) {
	t.Parallel()
	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	username := acctest.RandomWithPrefix("tf-test-ldap-user")

	var policies []string
	groups := []string{
		acctest.RandomWithPrefix("group"),
	}

	resourceName := "vault_ldap_auth_backend_user.test"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendUserDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendUserConfig_basic(backend, username, policies, groups),
				Check: resource.ComposeTestCheckFunc(
					testLDAPAuthBackendUserCheck_attrs(resourceName, backend, username),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testLDAPAuthBackendUserDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_auth_backend_user" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for ldap auth backend user %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("ldap auth backend user %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testLDAPAuthBackendUserCheck_attrs(resourceName, backend, username string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		path := rs.Primary.ID
		endpoint := "auth/" + strings.Trim(backend, "/") + "/users/" + username
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
			"groups":   "groups",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}

			if k == "groups" {
				ta.TransformVaultValue = testutil.SplitVaultValueString
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testLDAPAuthBackendUserConfig_basic(backend, username string, policies, groups []string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "ldap" {
    path = "%s"
    type = "ldap"
}

resource "vault_ldap_auth_backend_user" "test" {
    backend  = vault_auth_backend.ldap.path
    username = "%s"
    policies = %s
    groups   = %s
}
`, backend, username, util.ArrayToTerraformList(policies), util.ArrayToTerraformList(groups))
}
