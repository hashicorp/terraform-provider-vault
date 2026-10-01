// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// skipIfSCIMClientUnsupported skips the test unless the server is Vault 2.2.0
// or newer, ignoring any prerelease suffix. A plain SkipIfAPIVersionLT would
// skip on "2.2.0-beta1" or "2.2.0-rc1" because semver sorts prereleases below
// the final release, even though those builds already ship SCIM clients.
//
// # Running these tests against a local Vault server
//
// SCIM clients are a Vault Enterprise feature, so a local Enterprise dev server
// is needed. Build it with the "enterprise" build tag (without it the SCIM
// routes are missing and every create fails with "unsupported path"), and point
// it at your own license file through VAULT_LICENSE_PATH:
//
//	go build -tags "enterprise testonly" -o /tmp/vault-ent .
//	VAULT_LICENSE_PATH=/path/to/your/vault.hclic /tmp/vault-ent server -dev \
//	    -dev-root-token-id=<dev-token> -dev-listen-address=127.0.0.1:8200
//
// Then, from another shell, run the tests with the dev server's address and
// token:
//
//	TF_ACC=1 TF_ACC_ENTERPRISE=1 \
//	VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<dev-token> \
//	go test -v -run TestAccIdentityVaultSCIMClient ./vault
//
// Keep this safe:
//   - Use a throwaway dev server only. Dev mode is in-memory, unsealed and
//     unauthenticated by design, so never use it for real data.
//   - Bind it to 127.0.0.1 so it is not reachable from the network.
//   - The tests create and destroy real resources on whichever server
//     VAULT_ADDR points at. Never point them at a shared or production cluster.
//   - Never commit the license file or a real token. Pass them through the
//     environment or a file outside the repository, and use a dev-only token
//     instead of a real one.
//   - Stop the server when finished.
func skipIfSCIMClientUnsupported(t *testing.T) {
	t.Helper()
	SkipOnAPIVersion(t, testProvider.Meta(), func(cur *version.Version) bool {
		return cur.Core().LessThan(provider.VaultVersion220)
	}, "Vault version < %q", provider.VaultVersion220)
}

// TestAccIdentityVaultSCIMClient_requiredFieldsOnly creates a client with only
// the required fields and checks that client_id is computed, deleting is false,
// and Vault's defaults are applied.
func TestAccIdentityVaultSCIMClient_requiredFieldsOnly(t *testing.T) {
	clientName := acctest.RandomWithPrefix("tf-scim-client")
	resourceName := "vault_scim_client.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityVaultSCIMClientConfig(clientName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSCIMClientName, clientName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeleting, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultSchemaVersion, "2.2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxActiveTokens, "2"),
				),
			},
		},
	})
}

// TestAccIdentityVaultSCIMClient_allOptionalFields creates a client with every
// optional field set and checks that each value is stored in state.
func TestAccIdentityVaultSCIMClient_allOptionalFields(t *testing.T) {
	clientName := acctest.RandomWithPrefix("tf-scim-client")
	resourceName := "vault_scim_client.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityVaultSCIMClientConfig_allFields(clientName, "2.0", 5, 3600, true, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSCIMClientName, clientName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldClientID),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldAliasMountAccessor),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultSchemaVersion, "2.0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowUserAdoption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowGroupAdoption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxActiveTokens, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeleting, "false"),
				),
			},
		},
	})
}

// TestAccIdentityVaultSCIMClient_changeAliasMountAccessorForceNew points the
// client at a different auth mount and checks that the client is replaced
// (new client_id), since alias_mount_accessor is ForceNew.
func TestAccIdentityVaultSCIMClient_changeAliasMountAccessorForceNew(t *testing.T) {
	clientName := acctest.RandomWithPrefix("tf-scim-client")
	resourceName := "vault_scim_client.test"
	var firstClientID string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityVaultSCIMClientConfig_withAuthAccessor(clientName, "a"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSCIMClientName, clientName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("not found: %s", resourceName)
						}
						firstClientID = rs.Primary.Attributes[consts.FieldClientID]
						return nil
					},
				),
			},
			{
				Config: testAccIdentityVaultSCIMClientConfig_withAuthAccessor(clientName, "b"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSCIMClientName, clientName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("not found: %s", resourceName)
						}
						if rs.Primary.Attributes[consts.FieldClientID] == firstClientID {
							return fmt.Errorf("expected new client_id after replacement, got same ID: %s", firstClientID)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestAccIdentityVaultSCIMClient_updateAccessGrantPrincipalInPlace changes the
// principal entity's config and checks that the client is updated in place,
// keeping the same client_id.
func TestAccIdentityVaultSCIMClient_updateAccessGrantPrincipalInPlace(t *testing.T) {
	clientName := acctest.RandomWithPrefix("tf-scim-client")
	resourceName := "vault_scim_client.test"
	var clientID string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityVaultSCIMClientConfig_principal(clientName, "principal-1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSCIMClientName, clientName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("not found: %s", resourceName)
						}
						clientID = rs.Primary.Attributes[consts.FieldClientID]
						return nil
					},
				),
			},
			{
				Config: testAccIdentityVaultSCIMClientConfig_principal(clientName, "principal-2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSCIMClientName, clientName),
					// client_id must remain the same (in-place update, not replaced)
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("not found: %s", resourceName)
						}
						if rs.Primary.Attributes[consts.FieldClientID] != clientID {
							return fmt.Errorf("expected client_id %s to remain unchanged, got %s",
								clientID, rs.Primary.Attributes[consts.FieldClientID])
						}
						return nil
					},
				),
			},
		},
	})
}

// TestAccIdentityVaultSCIMClient_updateOptionalFieldsInPlace changes
// max_active_tokens, max_token_ttl, allow_user_adoption and allow_group_adoption
// and checks that the new values are read back after the update.
func TestAccIdentityVaultSCIMClient_updateOptionalFieldsInPlace(t *testing.T) {
	clientName := acctest.RandomWithPrefix("tf-scim-client")
	resourceName := "vault_scim_client.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityVaultSCIMClientConfig_allFields(clientName, "2.2", 2, 0, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxActiveTokens, "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowUserAdoption, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowGroupAdoption, "false"),
				),
			},
			{
				Config: testAccIdentityVaultSCIMClientConfig_allFields(clientName, "2.2", 10, 1800, true, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxActiveTokens, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTokenTTL, "1800"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowUserAdoption, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowGroupAdoption, "true"),
				),
			},
		},
	})
}

// TestAccIdentityVaultSCIMClient_import imports a client by client_name and
// checks that the imported state matches the created state, ignoring
// deletion_policy because Vault never returns it.
func TestAccIdentityVaultSCIMClient_import(t *testing.T) {
	clientName := acctest.RandomWithPrefix("tf-scim-client")
	resourceName := "vault_scim_client.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityVaultSCIMClientConfig(clientName),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDeletionPolicy),
		},
	})
}

// TestAccIdentityVaultSCIMClient_destroyDefaultWithLinkedResourcesFails links a
// group to the client, then destroys it with deletion_policy unset. Vault must
// refuse, and its "SCIM client has linked resources" error must reach the user.
func TestAccIdentityVaultSCIMClient_destroyDefaultWithLinkedResourcesFails(t *testing.T) {
	clientName := acctest.RandomWithPrefix("tf-scim-client")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
		Steps: []resource.TestStep{
			{
				// Create the client, then link a group to it out-of-band through
				// Vault's link-group endpoint so the client owns a resource.
				Config: testAccIdentityVaultSCIMClientConfig(clientName),
				Check: func(s *terraform.State) error {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					grp, err := client.Logical().Write("identity/group", map[string]interface{}{
						"name": "linked-" + clientName,
					})
					if err != nil {
						return fmt.Errorf("creating group: %w", err)
					}
					_, err = client.Logical().Write(
						fmt.Sprintf("identity/scim/client/%s/link-group", clientName),
						map[string]interface{}{"group_id": grp.Data["id"]},
					)
					return err
				},
			},
			{
				// With deletion_policy unset, Vault refuses to delete a client that
				// still owns resources, and that error must reach the operator.
				Config:      testAccIdentityVaultSCIMClientConfig(clientName),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`SCIM client has linked resources`),
			},
			{
				// Set a policy so the framework's final destroy can clean up.
				Config: testAccIdentityVaultSCIMClientConfig(clientName, fmt.Sprintf(`deletion_policy = %q`, consts.DeletionPolicyDeleteChildResources)),
			},
		},
	})
}

// TestAccIdentityVaultSCIMClient_duplicateAccessGrantPrincipal creates two
// clients that share one access_grant_principal and expects the second create
// to fail, since Vault allows each principal on only one client.
func TestAccIdentityVaultSCIMClient_duplicateAccessGrantPrincipal(t *testing.T) {
	name1 := acctest.RandomWithPrefix("tf-scim-client-1")
	name2 := acctest.RandomWithPrefix("tf-scim-client-2")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			skipIfSCIMClientUnsupported(t)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      testAccIdentityVaultSCIMClientConfig_duplicatePrincipal(name1, name2),
				ExpectError: regexp.MustCompile(`(error creating SCIM client|access_grant_principal)`),
			},
		},
	})
}

// TestAccIdentityVaultSCIMClient_destroyPolicies destroys a client under each
// deletion_policy value with nothing linked to it.
// Each case creates a client and lets the framework destroy it, then
// CheckDestroy confirms Vault no longer has the client. An empty policy sends a
// plain DELETE; the other two send the matching Vault query flag.
func TestAccIdentityVaultSCIMClient_destroyPolicies(t *testing.T) {
	tests := map[string]struct {
		attr string // extra attribute for the client block; empty means no policy
	}{
		"policy unset":           {attr: ""},
		"delete_child_resources": {attr: fmt.Sprintf(`deletion_policy = %q`, consts.DeletionPolicyDeleteChildResources)},
		"orphan_child_resources": {attr: fmt.Sprintf(`deletion_policy = %q`, consts.DeletionPolicyOrphanChildResources)},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clientName := acctest.RandomWithPrefix("tf-scim-client")

			var attrs []string
			if tc.attr != "" {
				attrs = append(attrs, tc.attr)
			}

			resource.Test(t, resource.TestCase{
				PreCheck: func() {
					acctestutil.TestEntPreCheck(t)
					skipIfSCIMClientUnsupported(t)
				},
				ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
				CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
				Steps: []resource.TestStep{
					{Config: testAccIdentityVaultSCIMClientConfig(clientName, attrs...)},
				},
			})
		})
	}
}

// TestAccIdentityVaultSCIMClient_invalidInputs checks that bad values are
// rejected before any Vault call. Every case is a single PlanOnly step that must fail
// with the schema validator's message, so nothing is created.
func TestAccIdentityVaultSCIMClient_invalidInputs(t *testing.T) {
	tests := map[string]struct {
		attr    string // the invalid attribute line added to the client block
		wantErr *regexp.Regexp
	}{
		"invalid deletion_policy": {
			attr:    `deletion_policy = "invalid_policy"`,
			wantErr: regexp.MustCompile(`expected deletion_policy to be one of`),
		},
		"invalid default_schema_version": {
			attr:    `default_schema_version = "3.0"`,
			wantErr: regexp.MustCompile(`expected default_schema_version to be one of`),
		},
		"max_active_tokens zero": {
			attr:    `max_active_tokens = 0`,
			wantErr: regexp.MustCompile(`expected max_active_tokens to be at least \(1\)`),
		},
		"max_token_ttl negative": {
			attr:    `max_token_ttl = -10`,
			wantErr: regexp.MustCompile(`expected max_token_ttl to be at least \(0\)`),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clientName := acctest.RandomWithPrefix("tf-scim-client")

			// No Enterprise or version gate: these fail at plan time, so they
			// run against any Vault server.
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
				ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
				Steps: []resource.TestStep{
					{
						Config:      testAccIdentityVaultSCIMClientConfig(clientName, tc.attr),
						PlanOnly:    true,
						ExpectError: tc.wantErr,
					},
				},
			})
		})
	}
}

// testAccCheckIdentityVaultSCIMClientDestroy verifies that every vault_scim_client
// in state was actually deleted from Vault.
func testAccCheckIdentityVaultSCIMClientDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_scim_client" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		path := fmt.Sprintf("identity/scim/client/%s", rs.Primary.ID)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return err
		}
		if resp != nil {
			return fmt.Errorf("SCIM client %q still exists in Vault", rs.Primary.ID)
		}
	}

	return nil
}

// Configuration helper functions

// testAccIdentityVaultSCIMClientConfig returns a config with one entity and one
// vault_scim_client that uses it as its access_grant_principal. Each extraAttrs
// entry is written as an extra attribute line inside the client block, for
// example `max_active_tokens = 5` or `deletion_policy = "orphan_child_resources"`.
// Pass none for a client with only the required fields.
func testAccIdentityVaultSCIMClientConfig(name string, extraAttrs ...string) string {
	extra := ""
	for _, attr := range extraAttrs {
		extra += "  " + attr + "\n"
	}

	return fmt.Sprintf(`
resource "vault_identity_entity" "principal" {
  name = "principal-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
%s}
`, name, name, extra)
}

func testAccIdentityVaultSCIMClientConfig_allFields(name, schemaVersion string, maxTokens, ttl int, allowUser, allowGroup bool) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass-%s"
}

resource "vault_identity_entity" "principal" {
  name = "principal-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
  alias_mount_accessor   = vault_auth_backend.userpass.accessor
  default_schema_version = %q
  allow_user_adoption    = %t
  allow_group_adoption   = %t
  max_active_tokens      = %d
  max_token_ttl          = %d
}
`, name, name, name, schemaVersion, allowUser, allowGroup, maxTokens, ttl)
}

// withAuthAccessor creates two distinct userpass mounts ("a" and "b") and points
// the SCIM client at the one named by `which`. Changing `which` changes the
// client's alias_mount_accessor (the mounts have different accessors), which
// must force replacement. Changing a single mount's path instead would not:
// the provider remounts in place and the accessor stays the same.
func testAccIdentityVaultSCIMClientConfig_withAuthAccessor(name, which string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "a" {
  type = "userpass"
  path = "userpass-a-%[1]s"
}

resource "vault_auth_backend" "b" {
  type = "userpass"
  path = "userpass-b-%[1]s"
}

resource "vault_identity_entity" "principal" {
  name = "principal-%[1]s"
}

resource "vault_scim_client" "test" {
  client_name            = %[1]q
  access_grant_principal = vault_identity_entity.principal.id
  alias_mount_accessor   = vault_auth_backend.%[2]s.accessor
}
`, name, which)
}

func testAccIdentityVaultSCIMClientConfig_principal(clientName, entitySuffix string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "principal" {
  name = "%s-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
}
`, entitySuffix, clientName, clientName)
}

func testAccIdentityVaultSCIMClientConfig_duplicatePrincipal(name1, name2 string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "shared_principal" {
  name = "shared-%s"
}

resource "vault_scim_client" "c1" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.shared_principal.id
}

resource "vault_scim_client" "c2" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.shared_principal.id
  depends_on             = [vault_scim_client.c1]
}
`, name1, name1, name2)
}
