package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/vault/api"
)

func kvSecretV2DataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: kvSecretV2DataSourceRead,

		Schema: map[string]*schema.Schema{
			"mount": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where KV-V2 engine is mounted",
			},

			"name": {
				Type:     schema.TypeString,
				Required: true,
				Description: "Full name of the secret. For a nested secret, " +
					"the name is the nested path excluding the mount and data " +
					"prefix. For example, for a secret at 'kvv2/data/foo/bar/baz', " +
					"the name is 'foo/bar/baz'",
			},

			"path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path where the generic secret will be written.",
			},

			"version": {
				Type:     schema.TypeInt,
				Optional: true,
			},

			"data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault",
				Sensitive:   true,
			},

			"created_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which secret was created",
			},

			"custom_metadata": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Custom metadata for the secret",
			},

			"deletion_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Deletion time for the secret",
			},

			"destroyed": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Indicates whether the secret has been destroyed",
			},
		},
	}
}

func kvSecretV2DataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)

	mount := d.Get("mount").(string)
	name := d.Get("name").(string)

	path := getKVV2Path(mount, name, "data")

	if err := d.Set("path", path); err != nil {
		return diag.FromErr(err)
	}

	if v, ok := d.GetOk("version"); ok {
		// add version to path as a query param
		path = fmt.Sprintf("%s?version=%d", path, v.(int))
	}

	log.Printf("[DEBUG] Reading secret at %s from Vault", path)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading secret %q from Vault: %s", path, err)
	}
	if secret == nil {
		return diag.Errorf("no secret found at %q", path)
	}

	d.SetId(path)

	data := secret.Data["data"]

	if err := d.Set("data", serializeDataMapToString(data.(map[string]interface{}))); err != nil {
		return diag.FromErr(err)
	}

	if v, ok := secret.Data["metadata"]; ok {
		metadata := v.(map[string]interface{})

		if v, ok := metadata["created_time"]; ok {
			if err := d.Set("created_time", v.(string)); err != nil {
				return diag.FromErr(err)
			}
		}

		if v, ok := metadata["deletion_time"]; ok {
			if err := d.Set("deletion_time", v.(string)); err != nil {
				return diag.FromErr(err)
			}
		}

		if v, ok := metadata["destroyed"]; ok {
			if err := d.Set("destroyed", v.(bool)); err != nil {
				return diag.FromErr(err)
			}
		}

		if v, ok := metadata["custom_metadata"]; ok && v != nil {
			if err := d.Set("custom_metadata", serializeDataMapToString(v.(map[string]interface{}))); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}
