package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceAddress(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []r.TestStep{
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
