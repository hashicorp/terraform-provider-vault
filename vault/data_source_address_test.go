package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceAddress(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceAddressBasic_config,
				Check:  resource.TestCheckResourceAttrSet("data.vault_address.test", "address"),
			},
		},
	})
}

var testDataSourceAddressBasic_config = `

data "vault_address" "test" {}

`
