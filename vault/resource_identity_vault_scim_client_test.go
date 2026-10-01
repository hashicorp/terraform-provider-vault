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
func skipIfSCIMClientUnsupported(t *testing.T) {
	t.Helper()
	SkipOnAPIVersion(t, testProvider.Meta(), func(cur *version.Version) bool {
		return cur.Core().LessThan(provider.VaultVersion220)
	}, "Vault version < %q", provider.VaultVersion220)
}

// Test 1: Create with required fields only (client_id is computed; deleting is false)
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
				Config: testAccIdentityVaultSCIMClientConfig_requiredOnly(clientName),
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

// Test 2: Create with all optional fields (All fields stored in state correctly)
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

// Test 3: Change alias_mount_accessor (Plan shows ForceNew)
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

// Test 4: Update access_grant_principal in-place (No replacement; Read reflects new value)
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

// Test 5: Update max_active_tokens, allow_user_adoption, allow_group_adoption (In-place update)
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

// Test 6: ImportStateVerify (client_name as import ID round-trips cleanly)
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
				Config: testAccIdentityVaultSCIMClientConfig_requiredOnly(clientName),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDeletionPolicy),
		},
	})
}

// Test 8: Destroy with deletion_policy unset, client has linked resources
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
				Config: testAccIdentityVaultSCIMClientConfig_requiredOnly(clientName),
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
				Config:      testAccIdentityVaultSCIMClientConfig_requiredOnly(clientName),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`SCIM client has linked resources`),
			},
			{
				// Set a policy so the framework's final destroy can clean up.
				Config: testAccIdentityVaultSCIMClientConfig_deletionPolicy(clientName, consts.DeletionPolicyDeleteChildResources),
			},
		},
	})
}

// Test 12: Two vault_scim_client resources with the same access_grant_principal (Apply-time error)
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

// Destroy: client with each deletion_policy and nothing linked to it (tests 7, 9, 10).
// Each case creates a client and lets the framework destroy it, then
// CheckDestroy confirms Vault no longer has the client. An empty policy sends a
// plain DELETE; the other two send the matching Vault query flag.
func TestAccIdentityVaultSCIMClient_destroyPolicies(t *testing.T) {
	tests := map[string]struct {
		config func(name string) string
	}{
		"policy unset": {
			config: testAccIdentityVaultSCIMClientConfig_requiredOnly,
		},
		"delete_child_resources": {
			config: func(name string) string {
				return testAccIdentityVaultSCIMClientConfig_deletionPolicy(name, consts.DeletionPolicyDeleteChildResources)
			},
		},
		"orphan_child_resources": {
			config: func(name string) string {
				return testAccIdentityVaultSCIMClientConfig_deletionPolicy(name, consts.DeletionPolicyOrphanChildResources)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clientName := acctest.RandomWithPrefix("tf-scim-client")

			resource.Test(t, resource.TestCase{
				PreCheck: func() {
					acctestutil.TestEntPreCheck(t)
					skipIfSCIMClientUnsupported(t)
				},
				ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
				CheckDestroy:             testAccCheckIdentityVaultSCIMClientDestroy,
				Steps: []resource.TestStep{
					{Config: tc.config(clientName)},
				},
			})
		})
	}
}

// Plan-time validation: bad values are rejected before any Vault call
// (tests 11, 13, 14, 15). Every case is a single PlanOnly step that must fail
// with the schema validator's message, so nothing is created.
func TestAccIdentityVaultSCIMClient_invalidInputs(t *testing.T) {
	tests := map[string]struct {
		config  func(name string) string
		wantErr *regexp.Regexp
	}{
		"invalid deletion_policy": {
			config: func(name string) string {
				return testAccIdentityVaultSCIMClientConfig_deletionPolicy(name, "invalid_policy")
			},
			wantErr: regexp.MustCompile(`expected deletion_policy to be one of`),
		},
		"invalid default_schema_version": {
			config: func(name string) string {
				return testAccIdentityVaultSCIMClientConfig_schemaVersion(name, "3.0")
			},
			wantErr: regexp.MustCompile(`expected default_schema_version to be one of`),
		},
		"max_active_tokens zero": {
			config: func(name string) string {
				return testAccIdentityVaultSCIMClientConfig_maxActiveTokens(name, 0)
			},
			wantErr: regexp.MustCompile(`expected max_active_tokens to be at least \(1\)`),
		},
		"max_token_ttl negative": {
			config: func(name string) string {
				return testAccIdentityVaultSCIMClientConfig_maxTokenTTL(name, -10)
			},
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
						Config:      tc.config(clientName),
						PlanOnly:    true,
						ExpectError: tc.wantErr,
					},
				},
			})
		})
	}
}

// CheckDestroy verifies the resource was actually deleted from Vault
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
func testAccIdentityVaultSCIMClientConfig_requiredOnly(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "principal" {
  name = "principal-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
}
`, name, name)
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

func testAccIdentityVaultSCIMClientConfig_deletionPolicy(name, policy string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "principal" {
  name = "principal-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
  deletion_policy        = %q
}
`, name, name, policy)
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

func testAccIdentityVaultSCIMClientConfig_schemaVersion(name, version string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "principal" {
  name = "principal-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
  default_schema_version = %q
}
`, name, name, version)
}

func testAccIdentityVaultSCIMClientConfig_maxActiveTokens(name string, tokens int) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "principal" {
  name = "principal-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
  max_active_tokens      = %d
}
`, name, name, tokens)
}

func testAccIdentityVaultSCIMClientConfig_maxTokenTTL(name string, ttl int) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "principal" {
  name = "principal-%s"
}

resource "vault_scim_client" "test" {
  client_name            = %q
  access_grant_principal = vault_identity_entity.principal.id
  max_token_ttl          = %d
}
`, name, name, ttl)
}
