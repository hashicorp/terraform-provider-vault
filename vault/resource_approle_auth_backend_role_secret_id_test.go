// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	helper "github.com/hashicorp/vault/sdk/helper/consts"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const secretIDResource = "vault_approle_auth_backend_role_secret_id.secret_id"

func TestAccAppRoleAuthBackendRoleSecretID_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAppRoleAuthBackendRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(secretIDResource, "backend", backend),
					resource.TestCheckResourceAttr(secretIDResource, "role_name", role),
					resource.TestCheckResourceAttrSet(secretIDResource, "accessor"),
				),
			},
			{
				PreConfig: func() {
					// delete approle out-of-band
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					path := fmt.Sprintf("auth/%s/role/%s", backend, role)
					_, err := client.Logical().Delete(path)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_basic(backend, role),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRoleSecretID_wrapped(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	withWrappedAccessor := false

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAppRoleAuthBackendRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_wrapped(backend, role, withWrappedAccessor),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(secretIDResource, "backend", backend),
					resource.TestCheckResourceAttr(secretIDResource, "role_name", role),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_accessor"),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_token"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRoleSecretID_wrapped_withWrappedAccessor(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	withWrappedAccessor := true

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAppRoleAuthBackendRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_wrapped(backend, role, withWrappedAccessor),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(secretIDResource, "backend", backend),
					resource.TestCheckResourceAttr(secretIDResource, "role_name", role),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_accessor"),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_token"),
					resource.TestCheckResourceAttrSet(secretIDResource, "accessor"),
					resource.TestMatchResourceAttr(secretIDResource, "accessor", regexp.MustCompile("^[[:xdigit:]]{8}-([[:xdigit:]]{4}-){3}[[:xdigit:]]{12}$")),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRoleSecretID_wrapped_namespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	withWrappedAccessor := false

	namespacePath := acctest.RandomWithPrefix("test-namespace")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy: func(s *terraform.State) error {
			if err := testAccCheckAppRoleAuthBackendRoleSecretIDDestroy(s); err != nil {
				return err
			}
			return testNamespaceDestroy(namespacePath)(s)
		},
		Steps: []resource.TestStep{
			{
				Config: testNamespaceConfig(namespacePath),
				Check:  testNamespaceCheckAttrs(),
			},
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_wrapped_namespace(namespacePath, backend, role, withWrappedAccessor),
				Check: resource.ComposeTestCheckFunc(
					testAssertClientNamespace(namespacePath),
					resource.TestCheckResourceAttr(secretIDResource, "backend", backend),
					resource.TestCheckResourceAttr(secretIDResource, "role_name", role),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_accessor"),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_token"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRoleSecretID_wrapped_namespace_withWrappedAccessor(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	withWrappedAccessor := true

	namespacePath := acctest.RandomWithPrefix("test-namespace")
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy: func(s *terraform.State) error {
			if err := testAccCheckAppRoleAuthBackendRoleSecretIDDestroy(s); err != nil {
				return err
			}
			return testNamespaceDestroy(namespacePath)(s)
		},
		Steps: []resource.TestStep{
			{
				Config: testNamespaceConfig(namespacePath),
				Check:  testNamespaceCheckAttrs(),
			},
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_wrapped_namespace(namespacePath, backend, role, withWrappedAccessor),
				Check: resource.ComposeTestCheckFunc(
					testAssertClientNamespace(namespacePath),
					resource.TestCheckResourceAttr(secretIDResource, "backend", backend),
					resource.TestCheckResourceAttr(secretIDResource, "role_name", role),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_accessor"),
					resource.TestCheckResourceAttrSet(secretIDResource, "wrapping_token"),
					resource.TestCheckResourceAttrSet(secretIDResource, "accessor"),
					resource.TestMatchResourceAttr(secretIDResource, "accessor", regexp.MustCompile("^[[:xdigit:]]{8}-([[:xdigit:]]{4}-){3}[[:xdigit:]]{12}$")),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRoleSecretID_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	secretID := acctest.RandomWithPrefix("test-role-id")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckAppRoleAuthBackendRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_full(backend, role, secretID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(secretIDResource, "backend", backend),
					resource.TestCheckResourceAttr(secretIDResource, "role_name", role),
					resource.TestCheckResourceAttr(secretIDResource, "secret_id", secretID),
					resource.TestCheckResourceAttrSet(secretIDResource, "accessor"),
					resource.TestCheckResourceAttr(secretIDResource, "cidr_list.#", "2"),
					resource.TestCheckResourceAttr(secretIDResource, consts.FieldMetadata, `{"hello":"world"}`),
					//fadia
					resource.TestCheckResourceAttr(secretIDResource, "ttl", "700"),
					resource.TestCheckResourceAttr(secretIDResource, "num_uses", ""),
				),
			},
		},
	})
}

func testAccCheckAppRoleAuthBackendRoleSecretIDDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_approle_auth_backend_role_secret_id" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AppRole auth backend role SecretID %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AppRole auth backend role SecretID %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAppRoleAuthBackendRoleSecretIDConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret_id" {
  role_name = vault_approle_auth_backend_role.role.role_name
  backend = vault_auth_backend.approle.path
}`, backend, role)
}

func testAccAppRoleAuthBackendRoleSecretIDConfig_full(backend, role, secretID string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret_id" {
  role_name = vault_approle_auth_backend_role.role.role_name
  backend = vault_auth_backend.approle.path
  cidr_list = ["10.148.0.0/20", "10.150.0.0/20"]
  ttl = 700
  num_uses = 2
  metadata = <<EOF
{
  "hello": "world"
}
EOF

  secret_id = "%s"
}`, backend, role, secretID)
}

func testAccAppRoleAuthBackendRoleSecretIDConfig_wrapped(backend, role string, withWrappedAccessor bool) string {
	config := fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret_id" {
  role_name = vault_approle_auth_backend_role.role.role_name
  backend = vault_auth_backend.approle.path
  wrapping_ttl = "60s"
`, backend, role)
	if withWrappedAccessor {
		config += fmt.Sprintf(`
	with_wrapped_accessor = %t
`, withWrappedAccessor)
	}
	return config + "}"
}

func testAccAppRoleAuthBackendRoleSecretIDConfig_wrapped_namespace(namespacePath, backend, role string, withWrappedAccessor bool) string {
	return fmt.Sprintf(`
provider "vault" {
	namespace = %q
}

%s
`, namespacePath, testAccAppRoleAuthBackendRoleSecretIDConfig_wrapped(backend, role, withWrappedAccessor))
}

func testAssertClientNamespace(expectedNS string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
		actualNS := client.Headers().Get(helper.NamespaceHeaderName)
		if actualNS != expectedNS {
			return fmt.Errorf("expected namespace %v, actual %v", expectedNS, actualNS)
		}
		return nil
	}
}
