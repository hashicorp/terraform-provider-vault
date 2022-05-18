package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"
)

func genericSecretListDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: genericSecretListDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where secret will be read.",
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

func genericSecretListDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return diag.Errorf("error checking kv path %s, err=%s", path, err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	log.Printf("[DEBUG] Listing secrets at %s from Vault", path)

	resp, err := client.Logical().List(path)
	if err != nil {
		return diag.Errorf("error listing from Vault at path %s, err=%s", path, err)
	}
	if resp == nil {
		return diag.Errorf("no secrets found at %q", path)
	}

	d.SetId(path)

	// Set keys to state if there are keys in response
	if keyList, ok := resp.Data["keys"]; ok && keyList != nil {
		if keys, ok := keyList.([]interface{}); ok {
			if err := d.Set("names", keys); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}
