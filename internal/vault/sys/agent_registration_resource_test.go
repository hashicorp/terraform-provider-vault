// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccAgentRegistration_basic tests the basic CRUD lifecycle of an agent registration
func TestAccAgentRegistration_basic(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_basic(displayName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldEntityID),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldCreationTime),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLastUpdatedTime),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNoDefaultCeilingPolicy, "false"),
					// ceiling_policies should be empty list (default policies filtered out)
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".#", "0"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldDisplayName,
			},
		},
	})
}

// testAccAgentRegistrationImportStateIdFunc returns the display_name for import
func testAccAgentRegistrationImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes[consts.FieldDisplayName], nil
	}
}

// testAccAgentRegistrationImportStateIDByIDFunc returns the id (UUID) for import
func testAccAgentRegistrationImportStateIDByIDFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes[consts.FieldID], nil
	}
}

// TestAccAgentRegistration_importByID tests importing a record using its id
// (UUID) rather than its display_name. When the import ID parses as a UUID, the
// provider reads the record by id.
func TestAccAgentRegistration_importByID(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_basic(displayName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIDByIDFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldID,
			},
		},
	})
}

// TestAccAgentRegistration_importByIDSlashDisplayName tests that a record whose
// display_name contains a "/" can be imported by its id (UUID). Importing by id
// is the reliable path for such records, since a "/" in the display_name would
// otherwise be interpreted as a path separator by the read-by-display_name
// endpoint.
func TestAccAgentRegistration_importByIDSlashDisplayName(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent") + "/with/slashes"
	entityName := acctest.RandomWithPrefix("test-entity")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_customEntityName(displayName, entityName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldID),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIDByIDFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldID,
			},
		},
	})
}

// TestAccAgentRegistration_withPolicies tests agent registration with ceiling policies
func TestAccAgentRegistration_withPolicies(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	policyName := acctest.RandomWithPrefix("test-policy")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_withPolicies(displayName, policyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldEntityID),
					// Default policies are filtered out, so we only see user-specified policies
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".0", policyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNoDefaultCeilingPolicy, "false"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldDisplayName,
			},
		},
	})
}

// TestAccAgentRegistration_noDefaultPolicy tests opting out of default ceiling policy
func TestAccAgentRegistration_noDefaultPolicy(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_noDefaultPolicy(displayName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldEntityID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNoDefaultCeilingPolicy, "true"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldDisplayName,
			},
		},
	})
}

// TestAccAgentRegistration_withDescription tests agent registration with description
func TestAccAgentRegistration_withDescription(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	description := "Test agent for automated testing"
	updatedDescription := "Updated test agent description"
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_withDescription(displayName, description),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldEntityID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, description),
				),
			},
			{
				Config: testAccAgentRegistrationConfig_withDescription(displayName, updatedDescription),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldEntityID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, updatedDescription),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldDisplayName,
				ImportStateVerifyIgnore:              []string{consts.FieldDescription, consts.FieldLastUpdatedTime},
			},
		},
	})
}

// TestAccAgentRegistration_updatePolicies tests updating ceiling policies
func TestAccAgentRegistration_updatePolicies(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	policy1 := acctest.RandomWithPrefix("policy1")
	policy2 := acctest.RandomWithPrefix("policy2")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_withPolicies(displayName, policy1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					// Default policies are filtered out, so we only see user-specified policies
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".0", policy1),
				),
			},
			{
				Config: testAccAgentRegistrationConfig_withPolicies(displayName, policy2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					// Default policies are filtered out, so we only see user-specified policies
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".0", policy2),
				),
			},
		},
	})
}

// TestAccAgentRegistration_requiresReplace tests that changing display_name requires replacement
func TestAccAgentRegistration_requiresReplace(t *testing.T) {
	displayName1 := acctest.RandomWithPrefix("test-agent-1")
	displayName2 := acctest.RandomWithPrefix("test-agent-2")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_basic(displayName1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName1),
				),
			},
			{
				Config: testAccAgentRegistrationConfig_basic(displayName2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName2),
				),
			},
		},
	})
}

// TestAccAgentRegistration_namespace tests agent registration in a namespace
func TestAccAgentRegistration_namespace(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	displayName := acctest.RandomWithPrefix("test-agent")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_namespace(ns, displayName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldEntityID),
				),
			},
			{
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, ns)
				},
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldDisplayName,
			},
		},
	})
}

// TestAccAgentRegistration_multiplePolicies tests agent registration with multiple ceiling policies
func TestAccAgentRegistration_multiplePolicies(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	policy1 := acctest.RandomWithPrefix("policy1")
	policy2 := acctest.RandomWithPrefix("policy2")
	resourceName := "vault_agent_registration.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAgentRegistrationConfig_multiplePolicies(displayName, policy1, policy2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldEntityID),
					// Default policies are filtered out, so we only see user-specified policies
					resource.TestCheckResourceAttr(resourceName, consts.FieldCeilingPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldCeilingPolicies+".*", policy1),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldCeilingPolicies+".*", policy2),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAgentRegistrationImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldDisplayName,
			},
		},
	})
}

// TestAccAgentRegistration_duplicateDisplayNameAcrossNamespaces tests that the same
// display_name can be used in different namespaces (namespace-scoped uniqueness).
// This test creates two separate registrations with the same display_name in different
// namespaces to prove that display_name uniqueness is scoped to the namespace.
func TestAccAgentRegistration_duplicateDisplayNameAcrossNamespaces(t *testing.T) {
	displayName := acctest.RandomWithPrefix("test-agent")
	ns1 := acctest.RandomWithPrefix("ns1")
	ns2 := acctest.RandomWithPrefix("ns2")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create two registrations with the same display_name in different namespaces
				// This should succeed, proving namespace-scoped uniqueness
				Config: testAccAgentRegistrationConfig_twoNamespaces(ns1, ns2, displayName),
				Check: resource.ComposeTestCheckFunc(
					// Verify first registration exists in ns1
					resource.TestCheckResourceAttr("vault_agent_registration.test1", consts.FieldNamespace, ns1),
					resource.TestCheckResourceAttr("vault_agent_registration.test1", consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet("vault_agent_registration.test1", consts.FieldID),
					// Verify second registration exists in ns2 with same display_name
					resource.TestCheckResourceAttr("vault_agent_registration.test2", consts.FieldNamespace, ns2),
					resource.TestCheckResourceAttr("vault_agent_registration.test2", consts.FieldDisplayName, displayName),
					resource.TestCheckResourceAttrSet("vault_agent_registration.test2", consts.FieldID),
				),
			},
		},
	})
}

// Config helper functions

func testAccAgentRegistrationConfig_basic(displayName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "test" {
  name     = "%s-entity"
  policies = ["default"]
}

resource "vault_agent_registration" "test" {
  display_name = "%s"
  entity_id    = vault_identity_entity.test.id
}
`, displayName, displayName)
}

// testAccAgentRegistrationConfig_customEntityName decouples the entity name from
// the display_name, so the display_name can contain characters (such as "/")
// that are not valid in an identity entity name.
func testAccAgentRegistrationConfig_customEntityName(displayName, entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "test" {
  name     = "%s"
  policies = ["default"]
}

resource "vault_agent_registration" "test" {
  display_name = "%s"
  entity_id    = vault_identity_entity.test.id
}
`, entityName, displayName)
}

func testAccAgentRegistrationConfig_withPolicies(displayName, policyName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "%s"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_identity_entity" "test" {
  name     = "%s-entity"
  policies = ["default"]
}

resource "vault_agent_registration" "test" {
  display_name              = "%s"
  entity_id                 = vault_identity_entity.test.id
  ceiling_policies = [vault_policy.test.name]
}
`, policyName, displayName, displayName)
}

func testAccAgentRegistrationConfig_noDefaultPolicy(displayName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "test" {
  name     = "%s-entity"
}

resource "vault_agent_registration" "test" {
  display_name            = "%s"
  entity_id               = vault_identity_entity.test.id
  no_default_ceiling_policy = true
}
`, displayName, displayName)
}

func testAccAgentRegistrationConfig_withDescription(displayName, description string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "test" {
  name     = "%s-entity"
  policies = ["default"]
}

resource "vault_agent_registration" "test" {
  display_name = "%s"
  entity_id    = vault_identity_entity.test.id
  description  = "%s"
}
`, displayName, displayName, description)
}

func testAccAgentRegistrationConfig_namespace(ns, displayName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_identity_entity" "test" {
  namespace = vault_namespace.test.path
  name      = "%s-entity"
  policies  = ["default"]
}

resource "vault_agent_registration" "test" {
  namespace    = vault_namespace.test.path
  display_name = "%s"
  entity_id    = vault_identity_entity.test.id
}
`, ns, displayName, displayName)
}

func testAccAgentRegistrationConfig_twoNamespaces(ns1, ns2, displayName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test1" {
  path = "%s"
}

resource "vault_namespace" "test2" {
  path = "%s"
}

resource "vault_identity_entity" "test1" {
  namespace = vault_namespace.test1.path
  name      = "%s-entity-1"
  policies  = ["default"]
}

resource "vault_identity_entity" "test2" {
  namespace = vault_namespace.test2.path
  name      = "%s-entity-2"
  policies  = ["default"]
}

# First registration with display_name in namespace 1
resource "vault_agent_registration" "test1" {
  namespace    = vault_namespace.test1.path
  display_name = "%s"
  entity_id    = vault_identity_entity.test1.id
}

# Second registration with same display_name in namespace 2
# This should succeed because display_name uniqueness is namespace-scoped
resource "vault_agent_registration" "test2" {
  namespace    = vault_namespace.test2.path
  display_name = "%s"
  entity_id    = vault_identity_entity.test2.id
}
`, ns1, ns2, displayName, displayName, displayName, displayName)
}

func testAccAgentRegistrationConfig_multiplePolicies(displayName, policy1, policy2 string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test1" {
  name = "%s"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "test2" {
  name = "%s"
  policy = <<EOT
path "auth/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_identity_entity" "test" {
  name     = "%s-entity"
  policies = ["default"]
}

resource "vault_agent_registration" "test" {
  display_name              = "%s"
  entity_id                 = vault_identity_entity.test.id
  ceiling_policies = [
    vault_policy.test1.name,
    vault_policy.test2.name,
  ]
}
`, policy1, policy2, displayName, displayName)
}
