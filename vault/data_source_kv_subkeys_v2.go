// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

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
		ReadContext: provider.ReadContextWrapper(kvSecretSubkeysDataSourceRead),

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
			consts.FieldDepth: {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "Specifies the deepest nesting level to provide in the output." +
					"If non-zero, keys that reside at the specified depth value will be " +
					"artificially treated as leaves and will thus be 'null' even if further " +
					"underlying sub-keys exist.",
			},
			consts.FieldDataJSON: {
				Type:     schema.TypeString,
				Computed: true,
				// we save the subkeys as a JSON string in order to
				// cleanly support nested values
				Description: "Subkeys for the KV-V2 secret read from Vault.",
			},
			consts.FieldData: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Subkeys stored as a map of strings.",
				Sensitive:   true,
			},
		},
	}
}

func kvSecretSubkeysDataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	path := getKVV2Path(mount, name, "subkeys")

	if v, ok := d.GetOk(consts.FieldVersion); ok {
		// add version to path as a query param
		path = fmt.Sprintf("%s?version=%d", path, v.(int))
	}

	if v, ok := d.GetOk(consts.FieldDepth); ok {
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
		if err := d.Set(consts.FieldDataJSON, string(jsonData)); err != nil {
			return diag.FromErr(err)
		}

		if err := d.Set(consts.FieldData, serializeDataMapToString(data.(map[string]interface{}))); err != nil {
			return diag.FromErr(err)
		}
	}

	d.SetId(path)

	return nil
}
