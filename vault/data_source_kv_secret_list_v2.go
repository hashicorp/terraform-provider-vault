package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func kvSecretListDataSourceV2() *schema.Resource {
	return &schema.Resource{
		ReadContext: kvSecretV2ListDataSourceRead,

		Schema: map[string]*schema.Schema{
			"mount": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where KV-V2 engine is mounted",
			},

			"name": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Full named path of the secret. For a nested secret, " +
					"the name is the nested path excluding the mount and data " +
					"prefix. For example, for a secret at 'kvv2/data/foo/bar/baz', " +
					"the name is 'foo/bar/baz'",
			},

			"path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path where the generic secret will be written.",
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

func kvSecretV2ListDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)

	mount := d.Get("mount").(string)
	name := d.Get("name").(string)

	path := getKVV2Path(mount, name, "metadata")

	if err := d.Set("path", path); err != nil {
		return diag.FromErr(err)
	}

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
