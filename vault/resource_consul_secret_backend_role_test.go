// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestConsulSecretBackendRole(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-consul")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resourceName := "vault_consul_secret_backend_role.test"

	createTestCheckBase := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "0"),
		resource.TestCheckResourceAttr(resourceName, "consul_namespace", "consul-ns-0"),
		resource.TestCheckResourceAttr(resourceName, "partition", "partition-0"),
	}
	updateTestCheckBase := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "120"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "true"),
		resource.TestCheckResourceAttr(resourceName, "max_ttl", "240"),
		resource.TestCheckResourceAttr(resourceName, "consul_namespace", "consul-ns-1"),
		resource.TestCheckResourceAttr(resourceName, "partition", "partition-1"),
	}

	// This first test covers the "base case" with all Consul ACL policy types
	// that are supported by the provider.
	createTestCheckFuncs := append(createTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "1"),
		resource.TestCheckTypeSetElemAttr(resourceName, "consul_policies.*", "foo"),
		resource.TestCheckResourceAttr(resourceName, "consul_roles.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "consul_roles.0", "role-0"),
		resource.TestCheckResourceAttr(resourceName, "service_identities.#", "1"),
		resource.TestCheckTypeSetElemAttr(resourceName, "service_identities.*", "service-0:dc1"),
		resource.TestCheckResourceAttr(resourceName, "node_identities.#", "1"),
		resource.TestCheckTypeSetElemAttr(resourceName, "node_identities.*", "server-0:dc1"))

	updateTestCheckFuncs := append(updateTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "2"),
		resource.TestCheckTypeSetElemAttr(resourceName, "consul_policies.*", "foo"),
		resource.TestCheckTypeSetElemAttr(resourceName, "consul_policies.*", "bar"),
		resource.TestCheckResourceAttr(resourceName, "consul_roles.#", "3"),
		resource.TestCheckResourceAttr(resourceName, "consul_roles.0", "role-0"),
		resource.TestCheckResourceAttr(resourceName, "consul_roles.1", "role-1"),
		resource.TestCheckResourceAttr(resourceName, "consul_roles.2", "role-2"),
		resource.TestCheckResourceAttr(resourceName, "service_identities.#", "2"),
		resource.TestCheckTypeSetElemAttr(resourceName, "service_identities.*", "service-0:dc1"),
		resource.TestCheckTypeSetElemAttr(resourceName, "service_identities.*", "service-1"),
		resource.TestCheckResourceAttr(resourceName, "node_identities.#", "2"),
		resource.TestCheckTypeSetElemAttr(resourceName, "node_identities.*", "server-0:dc1"),
		resource.TestCheckTypeSetElemAttr(resourceName, "node_identities.*", "client-0:dc1"))

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testAccConsulSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testConsulSecretBackendRole_initialConfig(path, name, token, false, false),
				ExpectError: regexp.MustCompile("Use either a policy document, a list of policies or roles, or a set of service or node identities, depending on your Consul version"),
			},
			{
				Config:      testConsulSecretBackendRole_initialConfig(path, name, token, true, true),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
			{
				Config: testConsulSecretBackendRole_initialConfig(path, name, token, false, true),
				Check:  resource.ComposeTestCheckFunc(createTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			{
				Config:      testConsulSecretBackendRole_updateConfig(path, name, token, false, false),
				ExpectError: regexp.MustCompile("Use either a policy document, a list of policies or roles, or a set of service or node identities, depending on your Consul version"),
			},
			{
				Config:      testConsulSecretBackendRole_updateConfig(path, name, token, true, true),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
			{
				Config: testConsulSecretBackendRole_updateConfig(path, name, token, false, true),
				Check:  resource.ComposeTestCheckFunc(updateTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})

	// This separate test is used to check the functionality when using the legacy policies
	// field in the provider with newer versions of Vault (versions 1.11 and above).
	// Imported policies will always be in the new field consul_policies, so the import test ignores
	// both fields but has a custom ImportStateCheck function for those values.
	createImportTestCheckFuncs := append(createTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "policies.0", "boo"),
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "0"))

	updateImportTestCheckFuncs := append(updateTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "policies.#", "2"),
		resource.TestCheckResourceAttr(resourceName, "policies.0", "boo"),
		resource.TestCheckResourceAttr(resourceName, "policies.1", "far"),
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "0"))

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccConsulSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackendRole_initialConfig(path, name, token, true, false),
				Check:  resource.ComposeTestCheckFunc(createImportTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, importStateCheckLegacyPolicies("boo"), "policies", "consul_policies"),
			{
				Config: testConsulSecretBackendRole_updateConfig(path, name, token, true, false),
				Check:  resource.ComposeTestCheckFunc(updateImportTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, importStateCheckLegacyPolicies("boo", "far"), "policies", "consul_policies"),
		},
	})
}

func TestConsulSecretBackendRole_Legacy(t *testing.T) {
	var p *schema.Provider
	path := acctest.RandomWithPrefix("tf-test-consul")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resourceName := "vault_consul_secret_backend_role.test"

	createTestCheckBase := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "0"),
		resource.TestCheckResourceAttr(resourceName, "consul_namespace", "consul-ns-0"),
		resource.TestCheckResourceAttr(resourceName, "partition", "partition-0"),
	}
	updateTestCheckBase := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, path),
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "120"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "true"),
		resource.TestCheckResourceAttr(resourceName, "max_ttl", "240"),
		resource.TestCheckResourceAttr(resourceName, "consul_namespace", "consul-ns-1"),
		resource.TestCheckResourceAttr(resourceName, "partition", "partition-1"),
	}

	// This test covers the "base case" with all Consul ACL policy types supported by Vault 1.10.
	// Imported policies will always be in the new field consul_policies, so the import test ignores
	// both fields but has a custom ImportStateCheck function for those values.
	createTestCheckFuncs := append(createTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "0"),
		resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "policies.0", "boo"))

	updateTestCheckFuncs := append(updateTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "0"),
		resource.TestCheckResourceAttr(resourceName, "policies.#", "2"),
		resource.TestCheckResourceAttr(resourceName, "policies.0", "boo"),
		resource.TestCheckResourceAttr(resourceName, "policies.1", "far"))

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionGTE(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testAccConsulSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testConsulSecretBackendRole_initialConfig(path, name, token, false, false),
				ExpectError: regexp.MustCompile("Use either a policy document, a list of policies, or a list of roles, depending on your Consul version"),
			},
			{
				Config:      testConsulSecretBackendRole_initialConfig(path, name, token, true, true),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
			{
				Config: testConsulSecretBackendRole_initialConfig(path, name, token, true, false),
				Check:  resource.ComposeTestCheckFunc(createTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, importStateCheckLegacyPolicies("boo"), "policies", "consul_policies"),
			{
				Config:      testConsulSecretBackendRole_updateConfig(path, name, token, false, false),
				ExpectError: regexp.MustCompile("Use either a policy document, a list of policies, or a list of roles, depending on your Consul version"),
			},
			{
				Config:      testConsulSecretBackendRole_updateConfig(path, name, token, true, true),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
			{
				Config: testConsulSecretBackendRole_updateConfig(path, name, token, true, false),
				Check:  resource.ComposeTestCheckFunc(updateTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, importStateCheckLegacyPolicies("boo", "far"), "policies", "consul_policies"),
		},
	})

	// This separate test is used to check the functionality when using the new consul_policies
	// field in the provider with an older version of Vault (versions 1.10 and below).
	createImportTestCheckFuncs := append(createTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "1"),
		resource.TestCheckTypeSetElemAttr(resourceName, "consul_policies.*", "foo"))

	updateImportTestCheckFuncs := append(updateTestCheckBase,
		resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
		resource.TestCheckResourceAttr(resourceName, "consul_policies.#", "2"),
		resource.TestCheckTypeSetElemAttr(resourceName, "consul_policies.*", "foo"),
		resource.TestCheckTypeSetElemAttr(resourceName, "consul_policies.*", "bar"))

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccConsulSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackendRole_initialConfig(path, name, token, false, true),
				Check:  resource.ComposeTestCheckFunc(createImportTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "consul_roles", "node_identities", "service_identities"),
			{
				Config: testConsulSecretBackendRole_updateConfig(path, name, token, false, true),
				Check:  resource.ComposeTestCheckFunc(updateImportTestCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "consul_roles", "node_identities", "service_identities"),
		},
	})
}

func testAccConsulSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_consul_secret_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testConsulSecretBackendRole_initialConfig(path, name, token string, useLegacyPolicies, useNewFields bool) string {
	config := fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
}

resource "vault_consul_secret_backend_role" "test" {
  backend = vault_consul_secret_backend.test.path
  name = "%s"
  consul_namespace = "consul-ns-0"
  partition = "partition-0"
`, path, token, name)

	if useLegacyPolicies {
		config += `
policies = [
    "boo",
]
`
	}

	if useNewFields {
		config += `
consul_policies = [
	"foo",
]

consul_roles = [
	"role-0",
	# canary to ensure roles is a Set
	"role-0",
]

service_identities = [
	"service-0:dc1",
	# canary to ensure service identities is a Set
	"service-0:dc1",
]

node_identities = [
	"server-0:dc1",
	# canary to ensure node identities is a Set
	"server-0:dc1",
]
`
	}

	return config + "}"
}

func testConsulSecretBackendRole_updateConfig(path, name, token string, useLegacyPolicies, useNewFields bool) string {
	config := fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
}

resource "vault_consul_secret_backend_role" "test" {
  backend = vault_consul_secret_backend.test.path
  name = "%s"
  consul_namespace = "consul-ns-1"
  partition = "partition-1"
  ttl = 120
  max_ttl = 240
  local = true
`, path, token, name)

	if useLegacyPolicies {
		config += `
policies = [
    "boo",
	 "far",
]
`
	}

	if useNewFields {
		config += `
consul_policies = [
	"foo",
	"bar",
]

consul_roles = [
	"role-0",
	"role-1",
	"role-2",
	# canary to ensure roles is a Set
	"role-2",
]

service_identities = [
	"service-0:dc1",
	"service-1",
	# canary to ensure service identities is a Set
	"service-1",
]

node_identities = [
	"server-0:dc1",
	"client-0:dc1",
	# canary to ensure node identities is a Set
	"client-0:dc1",
]
`
	}

	return config + "}"
}

func TestConsulSecretBackendRoleNameFromPath(t *testing.T) {
	{
		name, err := consulSecretBackendRoleNameFromPath("foo/roles/bar")
		if err != nil {
			t.Fatalf("error getting name: %v", err)
		}
		if name != "bar" {
			t.Fatalf("expected name 'bar', but got %s", name)
		}
	}

	{
		name, err := consulSecretBackendRoleNameFromPath("no match")
		if err == nil {
			t.Fatal("Expected error getting name but got nil")
		}
		if name != "" {
			t.Fatalf("expected empty name, but got %s", name)
		}
	}
}

func TestConsulSecretBackendRoleBackendFromPath(t *testing.T) {
	{
		backend, err := consulSecretBackendRoleBackendFromPath("foo/roles/bar")
		if err != nil {
			t.Fatalf("error getting backend: %v", err)
		}
		if backend != "foo" {
			t.Fatalf("expected backend 'foo', but got %s", backend)
		}
	}

	{
		backend, err := consulSecretBackendRoleBackendFromPath("no match")
		if err == nil {
			t.Fatal("Expected error getting backend but got nil")
		}
		if backend != "" {
			t.Fatalf("expected empty backend, but got %s", backend)
		}
	}
}

// This custom ImportStateCheck function is used for import tests where the legacy policies field is
// defined, but ensures the returned value always matches under the new field name consul_policies.
func importStateCheckLegacyPolicies(policies ...string) resource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		for _, s := range states {
			for i, p := range policies {
				attr := fmt.Sprintf("consul_policies.%d", i)
				if consulPolicies := s.Attributes[attr]; consulPolicies != p {
					return fmt.Errorf("expected %q for %s, actual %q",
						policies, "consul_policies", consulPolicies)
				}
			}
		}
		return nil
	}
}
