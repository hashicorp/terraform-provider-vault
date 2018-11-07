package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccIdentityGroupAlias(t *testing.T) {
	group := acctest.RandomWithPrefix("my-group")

	nameGroup := "vault_identity_group.group"
	nameGroupAlias := "vault_identity_group_alias.group-alias"
	nameGithubA := "vault_auth_backend.githubA"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityGroupAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupAliasConfig(group),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(nameGroupAlias, "name", group),
					resource.TestCheckResourceAttrPair(nameGroupAlias, "canonical_id", nameGroup, "id"),
					resource.TestCheckResourceAttrPair(nameGroupAlias, "mount_accessor", nameGithubA, "accessor"),
				),
			},
		},
	})
}

func TestAccIdentityGroupAliasUpdate(t *testing.T) {
	group := acctest.RandomWithPrefix("my-group")

	nameGroup := "vault_identity_group.group"
	nameGroupAlias := "vault_identity_group_alias.group-alias"
	nameGithubA := "vault_auth_backend.githubA"
	nameGithubB := "vault_auth_backend.githubB"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityGroupAliasDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupAliasConfig(group),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(nameGroupAlias, "name", group),
					resource.TestCheckResourceAttrPair(nameGroupAlias, "canonical_id", nameGroup, "id"),
					resource.TestCheckResourceAttrPair(nameGroupAlias, "mount_accessor", nameGithubA, "accessor"),
				),
			},
			{
				Config: testAccIdentityGroupAliasConfigUpdate(group),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(nameGroupAlias, "name", group),
					resource.TestCheckResourceAttrPair(nameGroupAlias, "canonical_id", nameGroup, "id"),
					resource.TestCheckResourceAttrPair(nameGroupAlias, "mount_accessor", nameGithubB, "accessor"),
				),
			},
		},
	})
}

func testAccCheckIdentityGroupAliasDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_group_alias" {
			continue
		}
		secret, err := client.Logical().Read(identityGroupAliasIDPath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity group %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity group role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityGroupAliasConfig(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
}

resource "vault_auth_backend" "githubA" {
  type = "github"
  path = "githubA-%s"
}

resource "vault_auth_backend" "githubB" {
  type = "github"
  path = "githubB-%s"
}

resource "vault_identity_group_alias" "group-alias" {
  name = "%s"
  mount_accessor = "${vault_auth_backend.githubA.accessor}"
  canonical_id = "${vault_identity_group.group.id}"
}`, groupName, groupName, groupName, groupName)
}

func testAccIdentityGroupAliasConfigUpdate(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
}

resource "vault_auth_backend" "githubA" {
  type = "github"
  path = "githubA-%s"
}

resource "vault_auth_backend" "githubB" {
  type = "github"
  path = "githubB-%s"
}

resource "vault_identity_group_alias" "group-alias" {
  name = "%s"
  mount_accessor = "${vault_auth_backend.githubB.accessor}"
  canonical_id = "${vault_identity_group.group.id}"
}`, groupName, groupName, groupName, groupName)
}
