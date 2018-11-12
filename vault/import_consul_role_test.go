package vault

import (
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccConsulSecretBackendRole_importBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("test")
	toIgnore := []string{"path", "name"}
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceConsulSecretBackendRole_initialConfig(path),
				Check:  testResourceConsulSecretBackendRole_initialCheck(path),
			},
			{
				ResourceName:            "vault_consul_secret_backend_role.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: toIgnore,
			},
		},
	})
}
