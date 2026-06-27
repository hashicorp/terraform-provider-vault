package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestLDAPGroupPolicyAttachment_basic(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	groupname := acctest.RandomWithPrefix("tf-test-ldap-group")

	policies := []string{
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
	}

	resourceName := "vault_ldap_group_policy_attachment.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPGroupPolicyAttachmentDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPGroupPolicyAttachmentConfig_basic(backend, groupname, policies),
				Check:  testLDAPGroupPolicyAttachmentCheckAttrs(resourceName, backend, groupname, policies),
			},
		},
	})
}

func TestLDAPGroupPolicyAttachment_nonexistentGroup(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	nonexistentGroup := acctest.RandomWithPrefix("tf-test-nonexistent-group")
	policies := []string{acctest.RandomWithPrefix("policy")}

	config := fmt.Sprintf(`
resource "vault_auth_backend" "ldap" {
  path = "%s"
  type = "ldap"
}

resource "vault_ldap_group_policy_attachment" "test" {
  backend    = vault_auth_backend.ldap.path
  groupname  = "%s"
  policies   = %s
}
`, backend, nonexistentGroup, util.ArrayToTerraformList(policies))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`error: ldap group not found .*`),
			},
		},
	})
}

func TestLDAPGroupPolicyAttachment_missingPolicies(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	groupname := acctest.RandomWithPrefix("tf-test-ldap-group")

	config := fmt.Sprintf(`
resource "vault_auth_backend" "ldap" {
  path = "%s"
  type = "ldap"
}

resource "vault_ldap_auth_backend_group" "test" {
  backend    = vault_auth_backend.ldap.path
  groupname = "%s"
}

resource "vault_ldap_group_policy_attachment" "test" {
  backend    = vault_auth_backend.ldap.path
  groupname  = vault_ldap_auth_backend_group.test.groupname
}
`, backend, groupname)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`The argument "policies" is required`),
			},
		},
	})
}

func TestLDAPGroupPolicyAttachment_multiplePolicies(t *testing.T) {
	t.Parallel()

	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	groupname := acctest.RandomWithPrefix("tf-test-ldap-group")
	policies := []string{
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
	}

	resourceName := "vault_ldap_group_policy_attachment.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testLDAPGroupPolicyAttachmentDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPGroupPolicyAttachmentConfig_basic(backend, groupname, policies),
				Check:  testLDAPGroupPolicyAttachmentCheckAttrs(resourceName, backend, groupname, policies),
			},
		},
	})
}

func testLDAPGroupPolicyAttachmentDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_group_policy_attachment" {
			continue
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for ldap group %q: %s", rs.Primary.ID, err)
		}

		if secret != nil {
			if policies, ok := secret.Data["policies"]; ok && len(policies.([]interface{})) > 0 {
				return fmt.Errorf("policies still attached to group %q", rs.Primary.ID)
			}
		}
	}
	return nil
}

func testLDAPGroupPolicyAttachmentCheckAttrs(resourceName, backend, groupname string, expectedPolicies []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		expectedID := fmt.Sprintf("auth/%s/groups/%s", strings.Trim(backend, "/"), groupname)
		if rs.Primary.ID != expectedID {
			return fmt.Errorf("expected ID %q, got %q", expectedID, rs.Primary.ID)
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		group, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if group == nil || group.Data == nil {
			return fmt.Errorf("group %q not found", rs.Primary.ID)
		}

		actualPolicies := group.Data["policies"].([]interface{})
		for _, expected := range expectedPolicies {
			found := false
			for _, actual := range actualPolicies {
				if actual.(string) == expected {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("expected policy %q not found in attached policies", expected)
			}
		}

		return nil
	}
}

func testLDAPGroupPolicyAttachmentConfig_basic(backend, groupname string, policies []string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "ldap" {
  path = "%s"
  type = "ldap"
}

resource "vault_ldap_auth_backend_group" "test" {
  backend   = vault_auth_backend.ldap.path
  groupname = "%s"
}

resource "vault_ldap_group_policy_attachment" "test" {
  backend    = vault_auth_backend.ldap.path
  groupname  = vault_ldap_auth_backend_group.test.groupname
  policies   = %s
}
`, backend, groupname, util.ArrayToTerraformList(policies))
}
