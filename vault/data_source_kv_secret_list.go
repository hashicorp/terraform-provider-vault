package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"
)

func kvSecretListDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: kvSecretListDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Full KV-V1 path where secrets will be listed.",
				ValidateFunc: validateNoTrailingSlash,
			},

			"names": {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of all secret names.",
				Sensitive:   true,
			},
		},
	}
}

func kvSecretListDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	names, err := kvListRequest(client, path)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("names", names); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(path)

	return nil
}
