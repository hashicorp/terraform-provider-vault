// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package keymgmt_test

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccKeymgmtKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_initialConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
				),
			},
			{
				Config: testKeymgmtKey_updatedConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
				),
			},
			{
				Config: testKeymgmtKey_withMinEnabledVersion(mount, keyName, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMinEnabledVersion, "1"),
				),
			},
			{
				Config: testKeymgmtKey_withReplicaRegions(mount, keyName, []string{"us-west-1", "us-east-1"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
				),
			},
			{
				Config: testKeymgmtKey_withReplicaRegions(mount, keyName, []string{"eu-west-1"}),
				Check:  resource.ComposeTestCheckFunc(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionReplace),
					},
				},
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldReplicaRegions,
				},
			},
		},
	})
}

func testAccKeymgmtKeyImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		mount := rs.Primary.Attributes[consts.FieldMount]
		name := rs.Primary.Attributes[consts.FieldName]
		return fmt.Sprintf("%s/key/%s", mount, name), nil
	}
}

func testKeymgmtKey_initialConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}
`, mount, keyName)
}

func testKeymgmtKey_updatedConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}
`, mount, keyName)
}

func testKeymgmtKey_withReplicaRegions(mount, keyName string, regions []string) string {
	regionsList := make([]string, len(regions))
	for i, region := range regions {
		regionsList[i] = fmt.Sprintf("%q", region)
	}
	regionsStr := strings.Join(regionsList, ", ")

	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
  replica_regions  = [%s]
}
`, mount, keyName, regionsStr)
}

func TestAccKeymgmtKey_defaultType(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_noTypeConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					// type should default to rsa-2048
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "rsa-2048"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLatestVersion),
				),
			},
		},
	})
}

func TestAccKeymgmtKey_multiple(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	key1Name := acctest.RandomWithPrefix("key1")
	key2Name := acctest.RandomWithPrefix("key2")
	resourceType := "vault_keymgmt_key"
	resourceName1 := resourceType + ".test1"
	resourceName2 := resourceType + ".test2"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_multipleConfig(mount, key1Name, key2Name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName1, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldName, key1Name),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName1, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldName, key2Name),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldType, "rsa-2048"),
					resource.TestCheckResourceAttr(resourceName2, consts.FieldDeletionAllowed, "true"),
				),
			},
		},
	})
}

func TestAccKeymgmtKey_namespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	namespace := acctest.RandomWithPrefix("test-namespace")
	resourceType := "vault_keymgmt_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_namespaceConfig(namespace, mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespace),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore: []string{
					consts.FieldReplicaRegions,
				},
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
			},
			{
				// Cleanup step: unset the env var and verify no drift
				Config:   testKeymgmtKey_namespaceConfig(namespace, mount, keyName),
				PlanOnly: true,
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
			},
		},
	})
}

func TestAccKeymgmtKey_validation(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtKey_invalidTypeConfig(mount, keyName),
				ExpectError: regexp.MustCompile("unsupported key type"),
			},
		},
	})
}

func TestAccKeymgmtKey_deletionNotAllowed(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceType := "vault_keymgmt_key"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_deletionNotAllowedConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, keyName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "false"),
				),
			},
			{
				// Enable deletion so cleanup can succeed
				Config: testKeymgmtKey_updatedConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
				),
			},
		},
	})
}

func TestAccKeymgmtKey_invalidMount(t *testing.T) {
	keyName := acctest.RandomWithPrefix("key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config:      testKeymgmtKey_invalidMountConfig(keyName),
				ExpectError: regexp.MustCompile("no handler for route"),
			},
		},
	})
}

// TestAccKeymgmtKey_metadataDrift verifies that metadata is detected as drifted
// when the key is recreated outside Terraform, which leaves Vault with no
// metadata record. Vault omits metadata on read in that case, and the provider
// must not keep the stale value in state.
func TestAccKeymgmtKey_metadataDrift(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceName := "vault_keymgmt_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_metadataConfig(mount, keyName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.owner", "payments"),
				),
			},
			{
				PreConfig: func() {
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}
					keyPath := fmt.Sprintf("%s/key/%s", mount, keyName)
					if _, err := client.Logical().Delete(keyPath); err != nil {
						t.Fatalf("failed to delete key %s: %v", keyPath, err)
					}
					if _, err := client.Logical().Write(keyPath, map[string]interface{}{"type": "aes256-gcm96"}); err != nil {
						t.Fatalf("failed to recreate key %s: %v", keyPath, err)
					}
					// Keep deletion_allowed in sync so metadata is the only drift.
					if _, err := client.Logical().Write(keyPath, map[string]interface{}{consts.FieldDeletionAllowed: true}); err != nil {
						t.Fatalf("failed to update key %s: %v", keyPath, err)
					}
				},
				Config: testKeymgmtKey_metadataConfig(mount, keyName),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.TestCheckResourceAttr(resourceName, "metadata.owner", "payments"),
			},
		},
	})
}

// TestAccKeymgmtKey_metadataClear verifies how metadata maps to what Vault
// stores for a Plugin Framework resource: a map is written, {} clears it, and
// removing the attribute also clears it, with no diff left over because Vault
// returns an empty map after a clear. It also verifies that an import reads the
// stored map back.
func TestAccKeymgmtKey_metadataClear(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-keymgmt")
	keyName := acctest.RandomWithPrefix("key")
	resourceName := "vault_keymgmt_key.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: testKeymgmtKey_metadataConfigWith(mount, keyName, `metadata = { owner = "payments", team = "eco" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					testKeymgmtKeyVaultMetadata(resourceName, map[string]interface{}{"owner": "payments", "team": "eco"}),
				),
			},
			{
				Config: testKeymgmtKey_metadataConfigWith(mount, keyName, `metadata = {}`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "0"),
					testKeymgmtKeyVaultMetadata(resourceName, nil),
				),
			},
			{
				Config: testKeymgmtKey_metadataConfigWith(mount, keyName, `metadata = { owner = "payments" }`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "1"),
					testKeymgmtKeyVaultMetadata(resourceName, map[string]interface{}{"owner": "payments"}),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccKeymgmtKeyImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldReplicaRegions},
			},
			{
				Config: testKeymgmtKey_metadataConfigWith(mount, keyName, ``),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "metadata.%"),
					testKeymgmtKeyVaultMetadata(resourceName, nil),
				),
			},
		},
	})
}

func testKeymgmtKey_metadataConfigWith(mount, keyName, metadata string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
  %s
}
`, mount, keyName, metadata)
}

// testKeymgmtKeyVaultMetadata checks the metadata Vault itself returns for the
// key. A nil want means Vault holds no metadata, either as an omitted field or
// as an empty map.
func testKeymgmtKeyVaultMetadata(resourceName string, want map[string]interface{}) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}
		client, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			return err
		}
		keyPath := fmt.Sprintf("%s/key/%s", rs.Primary.Attributes[consts.FieldMount], rs.Primary.Attributes[consts.FieldName])
		resp, err := client.Logical().Read(keyPath)
		if err != nil {
			return err
		}
		if resp == nil {
			return fmt.Errorf("key %q not found in Vault", keyPath)
		}
		got, _ := resp.Data[consts.FieldMetadata].(map[string]interface{})
		if len(got) != len(want) {
			return fmt.Errorf("Vault metadata for %q: got %v, want %v", keyPath, got, want)
		}
		for k, v := range want {
			if got[k] != v {
				return fmt.Errorf("Vault metadata for %q: got %v, want %v", keyPath, got, want)
			}
		}
		return nil
	}
}

func testKeymgmtKey_metadataConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
  metadata         = { owner = "payments" }
}
`, mount, keyName)
}

func testKeymgmtKey_multipleConfig(mount, key1Name, key2Name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test1" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}

resource "vault_keymgmt_key" "test2" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "rsa-2048"
  deletion_allowed = true
}
`, mount, key1Name, key2Name)
}

func testKeymgmtKey_namespaceConfig(namespace, mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_mount" "keymgmt" {
  namespace = vault_namespace.test.path
  path      = %q
  type      = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  namespace        = vault_namespace.test.path
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}
`, namespace, mount, keyName)
}

func testKeymgmtKey_noTypeConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  deletion_allowed = true
}
`, mount, keyName)
}

func testKeymgmtKey_withMinEnabledVersion(mount, keyName string, minEnabledVersion int) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount               = vault_mount.keymgmt.path
  name                = %q
  type                = "aes256-gcm96"
  deletion_allowed    = true
  min_enabled_version = %d
}
`, mount, keyName, minEnabledVersion)
}

func testKeymgmtKey_invalidTypeConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "invalid-key-type"
  deletion_allowed = true
}
`, mount, keyName)
}

func testKeymgmtKey_deletionNotAllowedConfig(mount, keyName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "keymgmt" {
  path = %q
  type = "keymgmt"
}

resource "vault_keymgmt_key" "test" {
  mount            = vault_mount.keymgmt.path
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = false
}
`, mount, keyName)
}

func testKeymgmtKey_invalidMountConfig(keyName string) string {
	return fmt.Sprintf(`
resource "vault_keymgmt_key" "test" {
  mount            = "nonexistent-mount"
  name             = %q
  type             = "aes256-gcm96"
  deletion_allowed = true
}
`, keyName)
}
