package spiffe_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

func TestAccSpiffeSecretMintJwtResource(t *testing.T) {
	mount := acctest.RandomWithPrefix("spiffe-mount")

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},

		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					resource "vault_mount" "the_backend" {
						path            = "%s"
						type            = "spiffe"
					}
					resource "vault_spiffe_backend_config" "config" {
						mount			= vault_mount.the_backend.path
						trust_domain	= "dadgarcorp.com"
					}
					resource "vault_spiffe_role" "role" {
                      	mount		    = vault_mount.the_backend.path
                      	name		    = "the-role-name"
                      	template	    = jsonencode(
                            {
                                sub = "spiffe://dadgarcorp.com/workload"
                            }
                        )
					}
					ephemeral "vault_spiffe_mintjwt" "test" {
						mount		    = vault_mount.the_backend.path
                        mount_id	    = vault_mount.the_backend.id
						name		    = vault_spiffe_role.role.name

						audience	    = "test audience"
					}
		            provider "echo" {
		            	data            = ephemeral.vault_spiffe_mintjwt.test
		            }

                    resource "echo" "jwtsvid" {}

					`, mount),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.jwtsvid",
						tfjsonpath.New("data").AtMapKey("token"),
						jwtsvidCheck{
							audience: "test audience",
							svid:     "spiffe://dadgarcorp.com/workload",
						}),
				},
			},
		},
	})
}

var _ knownvalue.Check = jwtsvidCheck{}

type jwtsvidCheck struct {
	audience string
	svid     string
}

func (f jwtsvidCheck) CheckValue(value any) error {
	token, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string got %T", value)
	}
	svid, err := jwtsvid.ParseInsecure(token, []string{f.audience})
	if err != nil {
		return err
	}
	if svid.ID.String() != f.svid {
		return fmt.Errorf("svid ID (%s) does not match expected ID (%s)", svid.ID.String(), svid)
	}
	return nil
}

func (f jwtsvidCheck) String() string {
	return fmt.Sprintf("audience: %q, svid: %q", f.audience, f.svid)
}
