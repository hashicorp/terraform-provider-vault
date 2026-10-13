// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func TestAccTransformTransformation(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("transform")

	resourceName := "vault_transform_transformation.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTransformationDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTransformation_basicConfig(path, "ccn-fpe", "fpe", "ccn", "internal", "payments", "*"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "ccn-fpe"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "fpe"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTemplate, "ccn"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTweakSource, "internal"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "payments"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaskingCharacter, "*"),
				),
			},
			{
				ResourceName: resourceName,
				ImportState:  true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected 1 state but received %+v", states)
					}
					state := states[0]
					if state.Attributes["templates.#"] != "1" {
						t.Fatalf("expected %q, received %q", "1", state.Attributes["templates.#"])
					}
					if state.Attributes[consts.FieldType] != "fpe" {
						t.Fatalf("expected %q, received %q", "fpe", state.Attributes[consts.FieldType])
					}
					if state.Attributes["id"] == "" {
						t.Fatal("expected value for id, received nothing")
					}
					if state.Attributes[consts.FieldAllowedRoles+".#"] != "1" {
						t.Fatalf("expected %q, received %q", "1", state.Attributes[consts.FieldAllowedRoles+".#"])
					}
					if state.Attributes["templates.0"] != "ccn" {
						t.Fatalf("expected %q, received %q", "ccn", state.Attributes["templates.0"])
					}
					if state.Attributes[consts.FieldTweakSource] != "internal" {
						t.Fatalf("expected %q, received %q", "internal", state.Attributes[consts.FieldTweakSource])
					}
					if state.Attributes[consts.FieldPath] == "" {
						t.Fatal("expected a value for path, received nothing")
					}
					if state.Attributes[consts.FieldAllowedRoles+".0"] != "payments" {
						t.Fatalf("expected %q, received %q", "payments", state.Attributes[consts.FieldAllowedRoles+".0"])
					}
					if state.Attributes[consts.FieldName] != "ccn-fpe" {
						t.Fatalf("expected %q, received %q", "ccn-fpw", state.Attributes[consts.FieldName])
					}
					var expectDeletionAllowed string

					meta := testProvider.Meta().(*provider.ProviderMeta)
					if provider.IsAPISupported(meta, provider.VaultVersion112) {
						expectDeletionAllowed = "true"
					}
					if state.Attributes[consts.FieldDeletionAllowed] != expectDeletionAllowed {
						t.Fatalf("expected %q, received %q", expectDeletionAllowed, state.Attributes[consts.FieldDeletionAllowed])
					}
					if provider.IsAPISupported(meta, provider.VaultVersion220) {
						if state.Attributes[consts.FieldMaxTweakLen] != "0" {
							t.Fatalf("expected %q, received %q", "0", state.Attributes[consts.FieldMaxTweakLen])
						}
						if state.Attributes[consts.FieldFpeAlgorithm] != "ff1" {
							t.Fatalf("expected %q, received %q", "ff1", state.Attributes[consts.FieldFpeAlgorithm])
						}
					}
					return nil
				},
			},
			{
				Config: transformTransformation_basicConfig(path, "ccn-fpe", "fpe", "ccn-1", "generated", "payments-1", "-"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "ccn-fpe"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "fpe"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTemplate, "ccn-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTweakSource, "generated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "payments-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaskingCharacter, "-"),
				),
			},
			{
				Config:   transformTransformation_basicConfig(path, "ccn-fpe", "fpe", "ccn-1", "generated", "payments-1", "-"),
				PlanOnly: true,
			},
		},
	})
}

// TestAccTransformTransformation_FF1 tests the vault_transform_transformation
// resource with a FPE transformation on Vault versions 2.2.0 onwards. It is the
// same test as TestAccTransformTransformation, with the addition of fields
// max_tweak_len and fpe_algorithm.
func TestAccTransformTransformation_FF1(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("transform")

	resourceName := "vault_transform_transformation.test"
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTransformationDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTransformation_fpeWithMaxTweakLenConfig(path, "fpe8", "ccn", "supplied", "payments", 8),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "fpe8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "fpe"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTemplate, "ccn"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTweakSource, "supplied"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "payments"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTweakLen, "8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldFpeAlgorithm, "ff1"),
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

func TestAccTransformTransformation_TokenizationWithStores(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("transform")
	storeName := acctest.RandomWithPrefix("test-store")

	resourceName := "vault_transform_transformation.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTransformationDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTransformation_tokenizationConfig(path, "test-tokenization", storeName, "default"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "test-tokenization"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "tokenization"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMappingMode, "default"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStores+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStores+".0", storeName),
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

func TestAccTransformTransformation_TokenizationWithConvergent(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("transform")
	storeName := acctest.RandomWithPrefix("test-store")

	resourceName := "vault_transform_transformation.test"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTransformationDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTransformation_tokenizationConvergentConfig(path, "ccn-convergent", storeName, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "ccn-convergent"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "tokenization"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStores+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldStores+".0", storeName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergent, "true"),
				),
			},
			{
				Config: transformTransformation_tokenizationConvergentConfig(path, "ccn-convergent", storeName, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "ccn-convergent"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "tokenization"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergent, "false"),
				),
			},
		},
	})
}

func transformTransformationDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_transformation" {
			continue
		}
		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func transformTransformation_basicConfig(path, name, tp, template, tweakSource, allowedRoles, maskingChar string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation" "test" {
  path              = vault_mount.mount_transform.path
  name              = "%s"
  type              = "%s"
  template          = "%s"
  tweak_source      = "%s"
  allowed_roles     = ["%s"]
  masking_character = "%s"
  deletion_allowed  = true
}
`, path, name, tp, template, tweakSource, allowedRoles, maskingChar)
}

func transformTransformation_tokenizationConfig(path, name, storeName, mappingMode string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_role" "test" {
  path            = vault_mount.mount_transform.path
  name            = "test-role"
  transformations = [vault_transform_transformation.test.name]
}

resource "vault_transform_transformation" "test" {
  path           = vault_mount.mount_transform.path
  name           = "%s"
  type           = "tokenization"
  mapping_mode   = "%s"
  stores         = ["%s"]
  allowed_roles  = ["test-role"]
  deletion_allowed = true
}
`, path, name, mappingMode, storeName)
}

func transformTransformation_fpeWithMaxTweakLenConfig(path, name, template, tweakSource, allowedRoles string, maxTweakLen int) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation" "test" {
  path           = vault_mount.mount_transform.path
  name           = "%s"
  type           = "fpe"
  template       = "%s"
  tweak_source   = "%s"
  allowed_roles  = ["%s"]
  max_tweak_len  = %d
  deletion_allowed = true
}
`, path, name, template, tweakSource, allowedRoles, maxTweakLen)
}

func transformTransformation_tokenizationConvergentConfig(path, name, storeName string, convergent bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation" "test" {
	path             = vault_mount.mount_transform.path
	name             = "%s"
	type             = "tokenization"
	mapping_mode     = "default"
	stores           = ["%s"]
	allowed_roles    = ["payments"]
	convergent       = %t
	deletion_allowed = true
}
`, path, name, storeName, convergent)
}
