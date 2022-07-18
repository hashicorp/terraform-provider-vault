package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestConsulSecretBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-backend")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resourcePath := "vault_consul_secret_backend_role.test"
	missingParametersError := "Use either a policy document, a list of policies, or a list of roles, depending on your Consul version"

	createTestCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourcePath, "backend", backend),
		resource.TestCheckResourceAttr(resourcePath, "name", name),
		resource.TestCheckResourceAttr(resourcePath, "ttl", "0"),
		resource.TestCheckResourceAttr(resourcePath, "consul_namespace", "consul-ns-0"),
		resource.TestCheckResourceAttr(resourcePath, "partition", "partition-0"),
	}

	updateTestCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourcePath, "backend", backend),
		resource.TestCheckResourceAttr(resourcePath, "name", name),
		resource.TestCheckResourceAttr(resourcePath, "ttl", "120"),
		resource.TestCheckResourceAttr(resourcePath, "max_ttl", "240"),
		resource.TestCheckResourceAttr(resourcePath, "local", "true"),
		resource.TestCheckResourceAttr(resourcePath, "consul_namespace", "consul-ns-1"),
		resource.TestCheckResourceAttr(resourcePath, "partition", "partition-1"),
	}

	testNewParameters := testutil.CheckTestVaultVersion(t)
	if testNewParameters {
		missingParametersError = "Use either a policy document, a list of policies or roles, or a set of service or node identities, depending on your Consul version"

		createTestCheckFuncs = append(createTestCheckFuncs,
			resource.TestCheckResourceAttr(resourcePath, "policies.#", "0"),
			resource.TestCheckResourceAttr(resourcePath, "consul_policies.#", "1"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "consul_policies.*", "foo"),
			resource.TestCheckResourceAttr(resourcePath, "consul_roles.#", "1"),
			resource.TestCheckResourceAttr(resourcePath, "consul_roles.0", "role-0"),
			resource.TestCheckResourceAttr(resourcePath, "service_identities.#", "1"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "service_identities.*", "service-0:dc1"),
			resource.TestCheckResourceAttr(resourcePath, "node_identities.#", "1"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "node_identities.*", "server-0:dc1"))

		updateTestCheckFuncs = append(updateTestCheckFuncs,
			resource.TestCheckResourceAttr(resourcePath, "policies.#", "0"),
			resource.TestCheckResourceAttr(resourcePath, "consul_policies.#", "2"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "consul_policies.*", "foo"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "consul_policies.*", "bar"),
			resource.TestCheckResourceAttr(resourcePath, "consul_roles.#", "3"),
			resource.TestCheckResourceAttr(resourcePath, "consul_roles.0", "role-0"),
			resource.TestCheckResourceAttr(resourcePath, "consul_roles.1", "role-1"),
			resource.TestCheckResourceAttr(resourcePath, "consul_roles.2", "role-2"),
			resource.TestCheckResourceAttr(resourcePath, "service_identities.#", "2"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "service_identities.*", "service-0:dc1"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "service_identities.*", "service-1"),
			resource.TestCheckResourceAttr(resourcePath, "node_identities.#", "2"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "node_identities.*", "server-0:dc1"),
			resource.TestCheckTypeSetElemAttr(resourcePath, "node_identities.*", "client-0:dc1"))
	} else {
		createTestCheckFuncs = append(createTestCheckFuncs,
			resource.TestCheckResourceAttr(resourcePath, "consul_policies.#", "0"),
			resource.TestCheckResourceAttr(resourcePath, "policies.#", "1"),
			resource.TestCheckResourceAttr(resourcePath, "policies.0", "boo"))

		updateTestCheckFuncs = append(updateTestCheckFuncs,
			resource.TestCheckResourceAttr(resourcePath, "consul_policies.#", "0"),
			resource.TestCheckResourceAttr(resourcePath, "policies.#", "2"),
			resource.TestCheckResourceAttr(resourcePath, "policies.0", "boo"),
			resource.TestCheckResourceAttr(resourcePath, "policies.1", "far"))
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config:      testConsulSecretBackendRole_initialConfig(backend, name, token, false, false),
				ExpectError: regexp.MustCompile(missingParametersError),
			},
			{
				Config:      testConsulSecretBackendRole_initialConfig(backend, name, token, true, true),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
			{
				Config: testConsulSecretBackendRole_initialConfig(backend, name, token, !testNewParameters, testNewParameters),
				Check:  resource.ComposeTestCheckFunc(createTestCheckFuncs...),
			},
			{
				Config:      testConsulSecretBackendRole_updateConfig(backend, name, token, false, false),
				ExpectError: regexp.MustCompile(missingParametersError),
			},
			{
				Config:      testConsulSecretBackendRole_updateConfig(backend, name, token, true, true),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
			{
				Config: testConsulSecretBackendRole_updateConfig(backend, name, token, !testNewParameters, testNewParameters),
				Check:  resource.ComposeTestCheckFunc(updateTestCheckFuncs...),
			},
			{
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
			},
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

func testConsulSecretBackendRole_initialConfig(backend, name, token string, withPolicies, isAboveVersionThreshold bool) string {
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
`, backend, token, name)

	if withPolicies {
		config += `
  policies = [
    "boo",
  ]
`
	}

	if isAboveVersionThreshold {
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

func testConsulSecretBackendRole_updateConfig(backend, name, token string, withPolicies, isAboveVersionThreshold bool) string {
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
  token_type = "client"
`, backend, token, name)

	if withPolicies {
		config += `
  policies = [
    "boo",
	 "far",
  ]
`
	}

	if isAboveVersionThreshold {
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
