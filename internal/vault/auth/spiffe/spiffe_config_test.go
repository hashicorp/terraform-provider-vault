package spiffe_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccSpiffeConfig(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	mount := acctest.RandomWithPrefix("spiffe-mount")
	caBytes, _, _ := testutil.GenerateCA()
	ca := strings.Trim(string(caBytes), "\n")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test the simplest form of config
			{
				Config: staticBundleSpiffeConfig(mount, ca),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("trust_domain"), knownvalue.StringExact("example.org")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("profile"), knownvalue.StringExact("static")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("bundle"), knownvalue.StringExact(ca+"\n")),
				},
			},
			// Test we can set the audience list
			{
				Config: staticBundleSpiffeConfigWithAudience(mount, ca, []string{"vault", "vault-core"}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("trust_domain"), knownvalue.StringExact("example.org")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("profile"), knownvalue.StringExact("static")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("bundle"), knownvalue.StringExact(ca+"\n")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("audience"),
						knownvalue.SetExact([]knownvalue.Check{
							knownvalue.StringExact("vault"),
							knownvalue.StringExact("vault-core"),
						})),
				},
			},
			// Test we can clear the audience list
			{
				Config: staticBundleSpiffeConfigWithAudience(mount, ca, []string{}),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("vault_spiffe_auth_config.spiffe_config", plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("audience"), knownvalue.ListSizeExact(0)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("trust_domain"), knownvalue.StringExact("example.org")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("profile"), knownvalue.StringExact("static")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("bundle"), knownvalue.StringExact(ca+"\n")),
					statecheck.ExpectKnownValue("vault_spiffe_auth_config.spiffe_config", tfjsonpath.New("audience"), knownvalue.ListSizeExact(0)),
				},
			},
		},
	})
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

resource "vault_spiffe_auth_config" "spiffe_config" {
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

resource "vault_spiffe_auth_config" "spiffe_config" {
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
