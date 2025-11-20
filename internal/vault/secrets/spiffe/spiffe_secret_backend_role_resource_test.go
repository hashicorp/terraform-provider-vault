package spiffe_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	// The fwresource import alias is so there is no collision
	// with the more typical acceptance testing import:
	// "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/spiffe"
)

func TestSpiffeSecretRoleResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := fwresource.SchemaRequest{}
	schemaResponse := &fwresource.SchemaResponse{}

	// Instantiate the resource.Resource and call its Schema method
	spiffe.NewSpiffeSecretBackendRoleResource().Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	// Validate the schema
	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)
	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}
}

func TestAccSpiffeSecretRoleResource(t *testing.T) {
	mount := acctest.RandomWithPrefix("spiffe-mount")
	resourceAddress := "vault_spiffe_secret_backend_role.test"

	checkPresent := func(res string, attrs ...string) resource.TestCheckFunc {
		var fs []resource.TestCheckFunc
		for _, attr := range attrs {
			fs = append(fs, resource.TestCheckResourceAttrSet(res, attr))
		}
		return resource.ComposeTestCheckFunc(fs...)
	}

	checkResourceAttr := func(res string, attrValuePairs ...string) resource.TestCheckFunc {
		var fs []resource.TestCheckFunc
		for i := 0; i < len(attrValuePairs); i += 2 {
			fs = append(fs, resource.TestCheckResourceAttr(res, attrValuePairs[i], attrValuePairs[i+1]))
		}
		return resource.ComposeTestCheckFunc(fs...)
	}

	formatTemplate := func(template string) string {
		return strings.ReplaceAll(template, `"`, `\"`)
	}
	subTemplate := `{"sub":"spiffe://dadgarcorp.com/workload"}`

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion122)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,

		Steps: []resource.TestStep{
			// Test the simplest form of config
			{
				Config: fmt.Sprintf(`
					resource "vault_mount" "the_backend" {
						path			= "%s"
						type			= "spiffe"
					}
					resource "vault_spiffe_secret_backend_config" "config" {
						mount			= vault_mount.the_backend.path
						trust_domain	= "dadgarcorp.com"
					}
					resource "vault_spiffe_secret_backend_role" "test" {
						mount			= vault_mount.the_backend.path
						name			= "the-role-name"
						template		= "%s"
					}
					`, mount, formatTemplate(subTemplate)),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"name", "the-role-name",
						"template", subTemplate),
					checkPresent(resourceAddress, "ttl", "use_jti_claim"),
				),
			},
			// Test that we can set TTL
			{
				Config: fmt.Sprintf(`
					resource "vault_mount" "the_backend" {
						path			= "%s"
						type			= "spiffe"
					}
					resource "vault_spiffe_secret_backend_config" "config" {
						mount			= vault_mount.the_backend.path
						trust_domain	= "dadgarcorp.com"
					}
					resource "vault_spiffe_secret_backend_role" "test" {
						mount			= vault_mount.the_backend.path
						name			= "the-role-name"
						template		= "%s"
                        ttl				= "24h"
					}
					`, mount, formatTemplate(subTemplate)),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"name", "the-role-name",
						"template", subTemplate,
						"ttl", "24h"),
					checkPresent(resourceAddress, "use_jti_claim"),
				),
			},
			// Fully specified role
			{
				Config: fmt.Sprintf(`
					resource "vault_mount" "the_backend" {
						path			= "%s"
						type			= "spiffe"
					}
					resource "vault_spiffe_secret_backend_config" "config" {
						mount			= vault_mount.the_backend.path
						trust_domain	= "dadgarcorp.com"
					}
					resource "vault_spiffe_secret_backend_role" "test" {
						mount			= vault_mount.the_backend.path
						name			= "the-role-name"
						template		= "%s"
                        ttl				= "25h"
                        use_jti_claim	= true
					}
					`, mount, formatTemplate(subTemplate)),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"name", "the-role-name",
						"template", subTemplate,
						"ttl", "25h",
						"use_jti_claim", "true"),
				),
			},
			// Test importing
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccSpiffeSecretsConfigRoleStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
		},
	})
}

func testAccSpiffeSecretsConfigRoleStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/role/%s", rs.Primary.Attributes["mount"], rs.Primary.Attributes["name"]), nil
	}
}
