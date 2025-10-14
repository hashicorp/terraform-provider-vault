package spiffe_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccSpiffeAuthConfig tests the spiffe auth config resource
func TestAccSpiffeAuthConfig(t *testing.T) {
	testutil.SkipTestAccEnt(t)
	mount := acctest.RandomWithPrefix("spiffe-mount")
	caBytes, _, _ := testutil.GenerateCA()
	ca := strings.Trim(string(caBytes), "\n")
	resourceAddress := "vault_spiffe_auth_backend_config.spiffe_config"

	spiffeBundle := `
	{
	   "keys": [
	       {
	           "use": "jwt-svid",
	           "kty": "EC",
	           "kid": "ZxKvdYWv1ZcSAUOQ0zxNmyvgm8eKKgIb",
	           "crv": "P-256",
	           "x": "UU_Z5vjB272LtPsRxemPskh8fVhEvfy7xzg3tsIyas0",
	           "y": "0B8DIXslvTqYTVSxzuGyGzVVKTUOHcJMzjOfmmR3kaE"
	       }
	   ],
	   "spiffe_sequence": 1
	}
	`

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			// FIXME: Limit tests to Vault 1.21.x or higher
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,

		Steps: []resource.TestStep{
			// Test the simplest form of config
			{
				Config: staticBundleSpiffeConfig(mount, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "trust_domain", "example.org"),
					resource.TestCheckResourceAttr(resourceAddress, "profile", "static"),
					resource.TestCheckResourceAttr(resourceAddress, "bundle", ca+"\n"),
				),
			},
			// Test we can set the audience list
			{
				Config: staticBundleSpiffeConfigWithAudience(mount, ca, []string{"vault", "vault-core"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "trust_domain", "example.org"),
					resource.TestCheckResourceAttr(resourceAddress, "profile", "static"),
					resource.TestCheckResourceAttr(resourceAddress, "bundle", ca+"\n"),
					resource.TestCheckResourceAttr(resourceAddress, "audience"+".#", "2"),
					resource.TestCheckResourceAttr(resourceAddress, "audience"+".0", "vault"),
					resource.TestCheckResourceAttr(resourceAddress, "audience"+".1", "vault-core"),
				),
			},
			// Test we can clear the audience list
			{
				Config: staticBundleSpiffeConfigWithAudience(mount, ca, []string{}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "trust_domain", "example.org"),
					resource.TestCheckResourceAttr(resourceAddress, "profile", "static"),
					resource.TestCheckResourceAttr(resourceAddress, "bundle", ca+"\n"),
					resource.TestCheckResourceAttr(resourceAddress, "audience"+".#", "0"),
				),
			},
			{
				Config: httpsWebPemSpiffeConfig(mount, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "trust_domain", "example.org"),
					resource.TestCheckResourceAttr(resourceAddress, "profile", "https_web_pem"),
					resource.TestCheckResourceAttr(resourceAddress, "endpoint_url", "https://dadgarcorp.com/spiffe-ca"),
					resource.TestCheckResourceAttr(resourceAddress, "endpoint_root_ca_truststore_pem", ca+"\n"),
					resource.TestCheckNoResourceAttr(resourceAddress, "bundle"),
				),
			},
			{
				Config: webBundleSpiffeConfig(mount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "trust_domain", "example.org"),
					resource.TestCheckResourceAttr(resourceAddress, "profile", "https_web_bundle"),
					resource.TestCheckResourceAttr(resourceAddress, "endpoint_url", "https://dadgarcorp.com/spiffe-ca"),
					resource.TestCheckNoResourceAttr(resourceAddress, "bundle"),
				),
			},
			{
				Config: spiffeBundleSpiffeConfig(mount, spiffeBundle),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "trust_domain", "example.org"),
					resource.TestCheckResourceAttr(resourceAddress, "profile", "https_spiffe_bundle"),
					resource.TestCheckResourceAttr(resourceAddress, "endpoint_url", "https://dadgarcorp.com/spiffe-ca"),
					resource.TestCheckResourceAttr(resourceAddress, "endpoint_spiffe_id", "spiffe://dadgarcorp.com/spire"),
					resource.TestCheckResourceAttr(resourceAddress, "bundle", spiffeBundle+"\n"),
				),
			},
			// Test importing
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccSpiffeAuthConfigImportStateIdFunc(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
		},
	})
}

func testAccSpiffeAuthConfigImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("auth/%s/config", rs.Primary.Attributes["mount"]), nil
	}
}

func staticBundleSpiffeConfig(mount string, ca string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "spiffe_mount" {
  type = "spiffe"
  path = "%s"

  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_spiffe_auth_backend_config" "spiffe_config" {
  mount        = vault_auth_backend.spiffe_mount.path
  trust_domain = "example.org"
  profile      = "static"
  bundle       = <<EOC
%s
EOC
}
`, mount, ca)
}

func staticBundleSpiffeConfigWithAudience(mount string, ca string, audiences []string) string {
	var formattedAudiences string
	if len(audiences) > 0 {
		formattedAudiences = "\"" + strings.Join(audiences, "\", \"") + "\""
	}
	return fmt.Sprintf(`
resource "vault_auth_backend" "spiffe_mount" {
  type = "spiffe"
  path = "%s"

  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_spiffe_auth_backend_config" "spiffe_config" {
  mount        = vault_auth_backend.spiffe_mount.path
  trust_domain = "example.org"
  profile      = "static"
  bundle       = <<EOC
%s
EOC
  audience    = [%s]
}
`, mount, ca, formattedAudiences)
}

func httpsWebPemSpiffeConfig(mount string, trustCa string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "spiffe_mount" {
  type = "spiffe"
  path = "%s"

  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_spiffe_auth_backend_config" "spiffe_config" {
  mount        = vault_auth_backend.spiffe_mount.path
  trust_domain = "example.org"
  profile      = "https_web_pem"
  endpoint_url = "https://dadgarcorp.com/spiffe-ca"
  defer_bundle_fetch = true
  endpoint_root_ca_truststore_pem  = <<EOC
%s
EOC
}
`, mount, trustCa)
}

func webBundleSpiffeConfig(mount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "spiffe_mount" {
  type = "spiffe"
  path = "%s"

  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_spiffe_auth_backend_config" "spiffe_config" {
  mount        = vault_auth_backend.spiffe_mount.path
  trust_domain = "example.org"
  profile      = "https_web_bundle"
  endpoint_url = "https://dadgarcorp.com/spiffe-ca"
  defer_bundle_fetch = true
}
`, mount)
}

func spiffeBundleSpiffeConfig(mount string, bundle string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "spiffe_mount" {
  type = "spiffe"
  path = "%s"

  tune {
    passthrough_request_headers = ["Authorization"]
  }
}

resource "vault_spiffe_auth_backend_config" "spiffe_config" {
  mount        = vault_auth_backend.spiffe_mount.path
  trust_domain = "example.org"
  profile      = "https_spiffe_bundle"
  endpoint_url = "https://dadgarcorp.com/spiffe-ca"
  endpoint_spiffe_id = "spiffe://dadgarcorp.com/spire"
  defer_bundle_fetch = true
  bundle = <<EOB
%s
EOB
}
`, mount, bundle)
}
