package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretSubkeysV2DataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: kvSecretSubkeysDataSourceRead,

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where KV-V2 engine is mounted",
			},

			consts.FieldName: {
				Type:     schema.TypeString,
				Required: true,
				Description: "Full name of the secret. For a nested secret, " +
					"the name is the nested path excluding the mount and data " +
					"prefix. For example, for a secret at 'kvv2/data/foo/bar/baz', " +
					"the name is 'foo/bar/baz'",
			},

			consts.FieldPath: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path where the generic secret will be written.",
			},

			consts.FieldVersion: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Specifies the version to return. If not set the latest version is returned.",
			},
			"depth": {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "Specifies the deepest nesting level to provide in the output." +
					"If non-zero, keys that reside at the specified depth value will be " +
					"artificially treated as leaves and will thus be 'null' even if further " +
					"underlying sub-keys exist.",
			},
			"data_json": {
				Type:     schema.TypeString,
				Computed: true,
				// we save the subkeys as a JSON string in order to
				// cleanly support nested values
				Description: "Subkeys for the KV-V2 secret read from Vault.",
			},
		},
	}
}

func kvSecretSubkeysDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	path := getKVV2Path(mount, name, "subkeys")

	if v, ok := d.GetOk(consts.FieldVersion); ok {
		// add version to path as a query param
		path = fmt.Sprintf("%s?version=%d", path, v.(int))
	}

	if v, ok := d.GetOk("depth"); ok {
		// add depth to path as a query param
		path = fmt.Sprintf("%s?depth=%d", path, v.(int))
	}

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading subkeys at %s from Vault", path)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading subkeys from Vault, err=%s", err)
	}

	if data, ok := secret.Data["subkeys"]; ok {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return diag.Errorf("error marshaling JSON for %q: %s", path, err)
		}
		if err := d.Set("data_json", string(jsonData)); err != nil {
			return diag.FromErr(err)
		}
	}

	d.SetId(path)

	return nil
}
