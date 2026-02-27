// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKubernetesAuthBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600
	maxTTL := 3600
	audience := "vault"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, "", ttl, maxTTL, audience),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenMaxTTL, strconv.Itoa(maxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPeriod, "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAudience, audience),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
			{
				ResourceName:      "vault_kubernetes_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basic(backend, role, "", ttl),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_update(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	oldTTL := 3600
	newTTL := oldTTL * 2

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basic(backend, role, "serviceaccount_uid", oldTTL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(oldTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basic(backend, role, "serviceaccount_name", newTTL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_name"),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600
	maxTTL := 3600
	audience := "vault"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, "", ttl, maxTTL, audience),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespace_selector", "{\"matchLabels\":{\"env\":\"dev\"}}"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(ttl)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenMaxTTL, strconv.Itoa(maxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPeriod, "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAudience, audience),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_fullUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	oldTTL := 3600
	newTTL := oldTTL * 2
	oldMaxTTL := 3600
	newMaxTTL := oldMaxTTL * 2
	oldAudience := "vault"
	newAudience := "new-vault"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, "", oldTTL, oldMaxTTL, oldAudience),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespace_selector", "{\"matchLabels\":{\"env\":\"dev\"}}"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(oldTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenMaxTTL, strconv.Itoa(oldMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPeriod, "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAudience, oldAudience),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, "", newTTL, newMaxTTL, newAudience),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespace_selector", "{\"matchLabels\":{\"env\":\"dev\"}}"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenMaxTTL, strconv.Itoa(newMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPeriod, "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAudience, newAudience),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
			{
				Config: testAccKubernetesAuthBackendRoleConfig_full(backend, role, "", newTTL, newMaxTTL, newAudience),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						"bound_service_account_namespace_selector", "{\"matchLabels\":{\"env\":\"dev\"}}"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenMaxTTL, strconv.Itoa(newMaxTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPeriod, "900"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAudience, newAudience),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
			// Unset `token_max_ttl`
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basicWithAudience(backend, role, newTTL, newAudience),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAudience, newAudience),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
			// Unset `audience`
			{
				Config: testAccKubernetesAuthBackendRoleConfig_basicWithAudience(backend, role, newTTL, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNames+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".0", "example"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldBoundServiceAccountNamespaces+".#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".0", "default"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".1", "dev"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".2", "prod"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenTTL, strconv.Itoa(newTTL)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAudience, ""),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_role.role",
						consts.FieldAliasNameSource, "serviceaccount_uid"),
				),
			},
		},
	})
}

func testAccCheckKubernetesAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kubernetes_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for Kubernetes auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Kubernetes auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccKubernetesAuthBackendRoleConfig_basic(backend, role, aliasSource string, ttl int) string {
	config := fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = vault_auth_backend.kubernetes.path
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  token_ttl = %d
  token_policies = ["default", "dev", "prod"]
`, backend, role, ttl)
	if aliasSource != "" {
		config += fmt.Sprintf(`
  alias_name_source = %q
`, aliasSource)
	}
	return config + "}"
}

func testAccKubernetesAuthBackendRoleConfig_basicWithAudience(backend, role string, ttl int, audience string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = vault_auth_backend.kubernetes.path
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  token_ttl = %d
  token_policies = ["default", "dev", "prod"]
  audience = %q
}`, backend, role, ttl, audience)
}

func testAccKubernetesAuthBackendRoleConfig_full(backend, role, aliasSource string, ttl, maxTTL int, audience string) string {
	config := fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = vault_auth_backend.kubernetes.path
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = ["example"]
  bound_service_account_namespace_selector = "{\"matchLabels\":{\"env\":\"dev\"}}"
  token_ttl = %d
  token_max_ttl = %d
  token_period = 900
  token_policies = ["default", "dev", "prod"]
  audience = %q
`, backend, role, ttl, maxTTL, audience)
	if aliasSource != "" {
		config += fmt.Sprintf(`
  alias_name_source = %q
`, aliasSource)
	}
	return config + "}"
}

func TestAccKubernetesAuthBackendRole_failure_missing_namespace_and_selector(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_missingNamespaceAndSelector(backend, role, ttl),
				ExpectError: regexp.MustCompile(
					"\"bound_service_account_namespaces\" can not be empty if \"bound_service_account_namespace_selector\" is not set"),
			},
		},
	})
}

func TestAccKubernetesAuthBackendRole_failure_explicit_empty_namespace_and_selector(t *testing.T) {
	backend := acctest.RandomWithPrefix("kubernetes")
	role := acctest.RandomWithPrefix("test-role")
	ttl := 3600

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckKubernetesAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendRoleConfig_explicitlyEmptyNamespaceAndSelector(backend, role, ttl),
				ExpectError: regexp.MustCompile(
					"\"bound_service_account_namespaces\" can not be empty if \"bound_service_account_namespace_selector\" is not set"),
			},
		},
	})
}

func testAccKubernetesAuthBackendRoleConfig_missingNamespaceAndSelector(backend, role string, ttl int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = vault_auth_backend.kubernetes.path
  role_name = %q
  bound_service_account_names = ["example"]
  token_ttl = %d
  token_policies = ["default", "dev", "prod"]
}`, backend, role, ttl)
}

func testAccKubernetesAuthBackendRoleConfig_explicitlyEmptyNamespaceAndSelector(backend, role string, ttl int) string {
	// explicit empty list and empty string to exercise the emptiness checks
	return fmt.Sprintf(`
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = %q
}

resource "vault_kubernetes_auth_backend_role" "role" {
  backend = vault_auth_backend.kubernetes.path
  role_name = %q
  bound_service_account_names = ["example"]
  bound_service_account_namespaces = []
  bound_service_account_namespace_selector = ""
  token_ttl = %d
  token_policies = ["default", "dev", "prod"]
}`, backend, role, ttl)
}
