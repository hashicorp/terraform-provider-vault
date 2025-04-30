// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const testAccIdentityOidcRoleTemplate = `{
  "name": {{identity.entity.name}}
}`

func TestAccIdentityOidcRole(t *testing.T) {
	var p *schema.Provider
	name := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_identity_oidc_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckIdentityOidcRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcRoleConfig(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "key", name),
					resource.TestCheckResourceAttr(resourceName, "template", ""),
					resource.TestCheckResourceAttr(resourceName, "ttl", "86400"),
					testAccIdentityOidcRoleCheckAttrs(resourceName),
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

func TestAccIdentityOidcRoleWithClientId(t *testing.T) {
	var p *schema.Provider
	name := acctest.RandomWithPrefix("test-role")
	clientId := acctest.RandomWithPrefix("test-client-id")

	resourceName := "vault_identity_oidc_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckIdentityOidcRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcRoleWithClientIdConfig(name, clientId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "key", name),
					resource.TestCheckResourceAttr(resourceName, "template", ""),
					resource.TestCheckResourceAttr(resourceName, "client_id", clientId),
					resource.TestCheckResourceAttr(resourceName, "ttl", "86400"),
					testAccIdentityOidcRoleCheckAttrs(resourceName),
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

func TestAccIdentityOidcRoleUpdate(t *testing.T) {
	var p *schema.Provider
	name := acctest.RandomWithPrefix("test-role")
	clientId := acctest.RandomWithPrefix("test-client-id")
	updateClientId := acctest.RandomWithPrefix("test-update-client-id")

	resourceName := "vault_identity_oidc_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckIdentityOidcRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcRoleWithClientIdConfig(name, clientId),
				Check:  testAccIdentityOidcRoleCheckAttrs(resourceName),
			},
			{
				Config: testAccIdentityOidcRoleConfigUpdate(name, updateClientId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "key", name),
					resource.TestCheckResourceAttr(resourceName, "template", fmt.Sprintf("%s\n", testAccIdentityOidcRoleTemplate)),
					resource.TestCheckResourceAttr(resourceName, "client_id", updateClientId),
					resource.TestCheckResourceAttr(resourceName, "ttl", "3600"),
					testAccIdentityOidcRoleCheckAttrs(resourceName),
				),
			},
			{
				Config: testAccIdentityOidcRoleWithClientIdConfig(name, clientId),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "key", name),
					resource.TestCheckResourceAttr(resourceName, "template", ""),
					resource.TestCheckResourceAttr(resourceName, "client_id", clientId),
					resource.TestCheckResourceAttr(resourceName, "ttl", "86400"),
					testAccIdentityOidcRoleCheckAttrs(resourceName),
				),
			},
		},
	})
}

func testAccCheckIdentityOidcRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(identityOidcRolePath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity oidc role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity oidc role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityOidcRoleCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := identityOidcRolePath(rs.Primary.ID)

		attrs := map[string]string{
			"key":       "key",
			"template":  "template",
			"ttl":       "ttl",
			"client_id": "client_id",
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

func testAccIdentityOidcRoleConfig(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
	name = "%s"
	key = vault_identity_oidc_key.key.name
}
`, entityName, entityName)
}

func testAccIdentityOidcRoleWithClientIdConfig(entityName string, clientId string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
	name = "%s"
	key = vault_identity_oidc_key.key.name
  client_id = "%s"
}
`, entityName, entityName, clientId)
}

func testAccIdentityOidcRoleConfigUpdate(entityName string, clientId string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
	name = "%s"
	key = vault_identity_oidc_key.key.name
  client_id = "%s"

	template = <<EOF
%s
EOF
	ttl = 3600
}`, entityName, entityName, clientId, testAccIdentityOidcRoleTemplate)
}
