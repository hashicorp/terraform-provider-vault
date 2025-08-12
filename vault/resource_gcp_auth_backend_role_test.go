// Copyright (c) HashiCorp, Inc.
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
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestGCPAuthBackend_pathRegex(t *testing.T) {
	tests := map[string]struct {
		path      string
		wantMount string
		wantRole  string
	}{
		"no nesting": {
			path:      "auth/gcp/role/carrot",
			wantMount: "gcp",
			wantRole:  "carrot",
		},
		"nested": {
			path:      "auth/test/usc1/gpc/role/usc1-test-master",
			wantMount: "test/usc1/gpc",
			wantRole:  "usc1-test-master",
		},
		"nested with double 'role'": {
			path:      "auth/gcp/role/role/foo",
			wantMount: "gcp/role",
			wantRole:  "foo",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mount, err := gcpAuthResourceBackendFromPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if mount != tc.wantMount {
				t.Fatalf("expected mount %q, got %q", tc.wantMount, mount)
			}

			role, err := gcpAuthResourceRoleFromPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if role != tc.wantRole {
				t.Fatalf("expected role %q, got %q", tc.wantRole, role)
			}
		})
	}
}

func TestGCPAuthBackendRole_basic(t *testing.T) {
	t.Run("simple backend path", func(t *testing.T) {
		backend := acctest.RandomWithPrefix("tf-test-gcp-backend")
		testGCPAuthBackendRole_basic(t, backend)
	})
	t.Run("nested backend path", func(t *testing.T) {
		backend := acctest.RandomWithPrefix("tf-test-gcp-backend") + "/nested"
		testGCPAuthBackendRole_basic(t, backend)
	})
}

func testGCPAuthBackendRole_basic(t *testing.T, backend string) {
	name := acctest.RandomWithPrefix("tf-test-gcp-role")
	serviceAccount := acctest.RandomWithPrefix("tf-test-gcp-service-account")
	projectId := acctest.RandomWithPrefix("tf-test-gcp-project-id")

	resourceName := "vault_gcp_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendRoleConfig_basic(backend, name, serviceAccount, projectId),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendRoleCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "300"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "600"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
				),
			},
			{
				Config: testGCPAuthBackendRoleConfig_unset(backend, name, serviceAccount, projectId),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendRoleCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "0"),
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

func TestGCPAuthBackendRole_gce(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp-backend")
	name := acctest.RandomWithPrefix("tf-test-gcp-role")
	projectId := acctest.RandomWithPrefix("tf-test-gcp-project-id")

	resourceName := "vault_gcp_auth_backend_role.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testGCPAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendRoleConfig_gce(backend, name, projectId),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendRoleCheck_attrs(resourceName, backend, name),
					resource.TestCheckResourceAttr(resourceName, "bound_labels.#", "2"),
				),
			},
		},
	})
}

func testGCPAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for GCP auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("GCP auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPAuthBackendRoleCheck_attrs(resourceName, backend, name string) resource.TestCheckFunc {
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
		if "gcp" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		attrs := map[string]string{
			"type":                   "type",
			"bound_projects":         "bound_projects",
			"bound_service_accounts": "bound_service_accounts",
			"bound_regions":          "bound_regions",
			"bound_zones":            "bound_zones",
			"bound_labels":           "bound_labels",
			"add_group_aliases":      "add_group_aliases",
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
			case "bound_labels":
				ta.AsSet = true
				ta.TransformVaultValue = func(st *testutil.VaultStateTest, resp *api.Secret) (interface{}, error) {
					// converts a map[string]interface{} to a slice of 'k:v' delimited strings.
					result := []interface{}{}
					v, ok := resp.Data[st.VaultAttr]
					if !ok {
						return nil, fmt.Errorf("no value for %s", st)
					}

					for k, v := range v.(map[string]interface{}) {
						result = append(result, fmt.Sprintf("%s:%s", k, v))
					}

					return result, nil
				}
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testGCPAuthBackendRoleConfig_basic(backend, name, serviceAccount, projectId string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "gcp" {
    path = "%s"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "test" {
    backend                = vault_auth_backend.gcp.path
    role                   = "%s"
    type                   = "iam"
    bound_service_accounts = ["%s"]
    bound_projects         = ["%s"]
    token_ttl              = 300
    token_max_ttl          = 600
    token_policies         = ["policy_a", "policy_b"]
    add_group_aliases      = true
}
`, backend, name, serviceAccount, projectId)
}

func testGCPAuthBackendRoleConfig_unset(backend, name, serviceAccount, projectId string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "gcp" {
    path = "%s"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "test" {
    backend                = vault_auth_backend.gcp.path
    role                   = "%s"
    type                   = "iam"
    bound_service_accounts = ["%s"]
    bound_projects         = ["%s"]
    add_group_aliases      = true
}
`, backend, name, serviceAccount, projectId)
}

func testGCPAuthBackendRoleConfig_gce(backend, name, projectId string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "gcp" {
    path = "%s"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "test" {
    backend                = vault_auth_backend.gcp.path
    role                   = "%s"
    type                   = "gce"
    bound_projects         = ["%s"]
    token_ttl              = 300
    token_max_ttl          = 600
    token_policies         = ["policy_a", "policy_b"]
    bound_regions          = ["eu-west2"]
    bound_zones            = ["europe-west2-c"]
    bound_labels           = ["foo:bar", "key:value"]
}
`, backend, name, projectId)
}
