package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccGenericSecret_importBasic(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	mount := "secretsv1"
	name := acctest.RandomWithPrefix("test")
	path := fmt.Sprintf("%s/%s", mount, name)
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(ns, mount, path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				ResourceName:            "vault_generic_secret.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"delete_all_versions"},
			},
		},
	})
}
