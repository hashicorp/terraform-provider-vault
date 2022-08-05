package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func addressDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(addressDataSourceRead),
		Schema: map[string]*schema.Schema{
			"address": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "URL of the root of the target Vault server.",
			},
		},
	}
}

func addressDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	address := client.Address()

	d.SetId(address)
	d.Set("address", address)

	return nil
}
