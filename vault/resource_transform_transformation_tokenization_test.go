package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func TestAccTransformTransformationTokenization(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resourceName := "vault_transform_transformation_tokenization.default_transform"
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTransformationTokenizationDestroy,
		Steps: []resource.TestStep{
			{
				Config: defaultTransformTokenizationConfig(path, "tkn_transform"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "tkn_transform"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldConvergent},
			},
		},
	})
}

func TestAccTransformTransformationTokenization_WithFields(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resourceName := "vault_transform_transformation_tokenization.test"
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTransformationTokenizationDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTokenizationWithFieldsConfig(path, "tkn_transform", "default", "payments", 86400),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "tkn_transform"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMappingMode, "default"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "payments"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeletionAllowed, "true"),
				),
			},
			{
				Config: transformTokenizationWithFieldsConfig(path, "tkn_transform", "default", "payments-updated", 172800),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "payments-updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "172800"),
				),
			},
			{
				Config: transformTokenizationWithFieldsConfig(path, "tkn_transform", "default", "payments-updated", 172800),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldConvergent},
			},
		},
	})
}

func TestAccTransformTransformationTokenization_Convergent(t *testing.T) {
	path := acctest.RandomWithPrefix("transform")
	resourceName := "vault_transform_transformation_tokenization.test"
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             transformTransformationTokenizationDestroy,
		Steps: []resource.TestStep{
			{
				Config: transformTokenizationConvergentConfig(path, "tkn_convergent", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, "tkn_convergent"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldConvergent, "true"),
				),
			},
			{
				Config: transformTokenizationConvergentConfig(path, "tkn_convergent", false),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroyBeforeCreate),
						plancheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.FieldConvergent), knownvalue.Bool(false)),
					},
				},
			},
		},
	})
}

func transformTransformationTokenizationDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transform_transformation_tokenization" {
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

func defaultTransformTokenizationConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation_tokenization" "default_transform" {
  path             = vault_mount.mount_transform.path
  name             = "%s"
  deletion_allowed = true
}`, path, name)
}

func transformTokenizationWithFieldsConfig(path, name, mappingMode, allowedRole string, maxTTL int) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation_tokenization" "test" {
  path             = vault_mount.mount_transform.path
  name             = "%s"
  mapping_mode     = "%s"
  allowed_roles    = ["%s"]
  max_ttl          = %d
  deletion_allowed = true
}`, path, name, mappingMode, allowedRole, maxTTL)
}

func transformTokenizationConvergentConfig(path, name string, convergent bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "mount_transform" {
  path = "%s"
  type = "transform"
}

resource "vault_transform_transformation_tokenization" "test" {
  path             = vault_mount.mount_transform.path
  name             = "%s"
  convergent       = %t
  deletion_allowed = true
}`, path, name, convergent)
}
