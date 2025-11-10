package spiffe_test

import (
	"context"
	"fmt"
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

func TestSpiffeSecretBackendResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := fwresource.SchemaRequest{}
	schemaResponse := &fwresource.SchemaResponse{}

	// Instantiate the resource.Resource and call its Schema method
	spiffe.NewSpiffeSecretBackendConfigResource().Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	// Validate the schema
	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)
	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}
}

func TestAccSpiffeSecretsConfigResource(t *testing.T) {
	mount := acctest.RandomWithPrefix("spiffe-mount")
	resourceAddress := "vault_spiffe_backend_config.test"

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

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
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
			resource "vault_spiffe_backend_config" "test" {
			    mount			= vault_mount.the_backend.path
			    trust_domain	= "dadgarcorp.com"
			}
			`, mount),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress, "trust_domain", "dadgarcorp.com"),
					checkPresent(resourceAddress, "bundle_refresh_hint", "jwt_oidc_compatibility_mode",
						"jwt_signing_algorithm", "key_lifetime"),
					resource.TestCheckNoResourceAttr(resourceAddress, "jwt_issuer_url"),
				),
			},
			// Test that we can change the trust domain
			{
				Config: fmt.Sprintf(`
				resource "vault_mount" "the_backend" {
				    path			= "%s"
				    type			= "spiffe"
				}
				resource "vault_spiffe_backend_config" "test" {
				    mount			= vault_mount.the_backend.path
				    trust_domain	= "changed.dadgarcorp.com"
				}
				`, mount),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress, "trust_domain", "changed.dadgarcorp.com"),
					checkPresent(resourceAddress, "bundle_refresh_hint", "jwt_oidc_compatibility_mode",
						"jwt_signing_algorithm", "key_lifetime"),
					resource.TestCheckNoResourceAttr(resourceAddress, "jwt_issuer_url"),
				),
			},
			// Test that we can set bundle_refresh_hint
			{
				Config: fmt.Sprintf(`
				resource "vault_mount" "the_backend" {
				    path				= "%s"
				    type				= "spiffe"
				}
				resource "vault_spiffe_backend_config" "test" {
				    mount				= vault_mount.the_backend.path
				    trust_domain		= "changed.dadgarcorp.com"
				    bundle_refresh_hint = "123"
				}
				`, mount),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"trust_domain", "changed.dadgarcorp.com",
						"bundle_refresh_hint", "123"),
					checkPresent(resourceAddress, "jwt_oidc_compatibility_mode", "jwt_signing_algorithm",
						"key_lifetime"),
					resource.TestCheckNoResourceAttr(resourceAddress, "jwt_issuer_url"),
				),
			},
			// Test that we can set key_lifetime
			{
				Config: fmt.Sprintf(`
				resource "vault_mount" "the_backend" {
				    path			= "%s"
				    type			= "spiffe"
				}
				resource "vault_spiffe_backend_config" "test" {
				    mount			= vault_mount.the_backend.path
				    trust_domain	= "changed.dadgarcorp.com"
				    key_lifetime	= "6666"
				}
				`, mount),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"trust_domain", "changed.dadgarcorp.com",
						"bundle_refresh_hint", "123",
						"key_lifetime", "6666"),
					checkPresent(resourceAddress, "jwt_oidc_compatibility_mode", "jwt_signing_algorithm"),
					resource.TestCheckNoResourceAttr(resourceAddress, "jwt_issuer_url"),
				),
			},
			// Test that we can set jwt_issuer_url
			{
				Config: fmt.Sprintf(`
				resource "vault_mount" "the_backend" {
				    path			= "%s"
				    type			= "spiffe"
				}
				resource "vault_spiffe_backend_config" "test" {
				    mount			= vault_mount.the_backend.path
				    trust_domain	= "changed.dadgarcorp.com"
				    jwt_issuer_url	= "https://spiffe.com"
				}
				`, mount),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"trust_domain", "changed.dadgarcorp.com",
						"bundle_refresh_hint", "123",
						"key_lifetime", "6666",
						"jwt_issuer_url", "https://spiffe.com"),
					checkPresent(resourceAddress, "jwt_oidc_compatibility_mode", "jwt_signing_algorithm"),
				),
			},
			// Test that we can set jwt_signing_algorithm
			{
				Config: fmt.Sprintf(`
				resource "vault_mount" "the_backend" {
				    path					= "%s"
				    type					= "spiffe"
				}
				resource "vault_spiffe_backend_config" "test" {
				    mount					= vault_mount.the_backend.path
				    trust_domain			= "changed.dadgarcorp.com"
				    jwt_signing_algorithm	= "ES384"
				}
				`, mount),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"trust_domain", "changed.dadgarcorp.com",
						"bundle_refresh_hint", "123",
						"key_lifetime", "6666",
						"jwt_issuer_url", "https://spiffe.com",
						"jwt_signing_algorithm", "ES384",
					),
					checkPresent(resourceAddress, "jwt_oidc_compatibility_mode"),
				),
			},
			// Fully specified config
			{
				Config: fmt.Sprintf(`
				resource "vault_mount" "the_backend" {
				    path						= "%s"
				    type						= "spiffe"
				}
				resource "vault_spiffe_backend_config" "test" {
				    mount						= vault_mount.the_backend.path
				    trust_domain				= "complete.dadgarcorp.com"
				    bundle_refresh_hint			= "7200" # FIXME(victorr): how can we make it so that "2h" works?
				    key_lifetime				= "172800" # "48h"
				    jwt_issuer_url				= "https://issuer.complete.dadgarcorp.com"
				    jwt_signing_algorithm		= "ES512"
				    jwt_oidc_compatibility_mode = true
				}
				`, mount),
				Check: resource.ComposeTestCheckFunc(
					checkResourceAttr(resourceAddress,
						"trust_domain", "complete.dadgarcorp.com",
						"bundle_refresh_hint", "7200",
						"key_lifetime", "172800",
						"jwt_issuer_url", "https://issuer.complete.dadgarcorp.com",
						"jwt_signing_algorithm", "ES512",
						"jwt_oidc_compatibility_mode", "true",
					),
				),
			},
			// Test importing
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccSpiffeSecretsConfigImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
		},
	})
}

func testAccSpiffeSecretsConfigImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/config", rs.Primary.Attributes["mount"]), nil
	}
}
