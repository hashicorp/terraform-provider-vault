// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"log"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretV2DataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: ReadContextWrapper(kvSecretV2DataSourceRead),

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

			consts.FieldVersion: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version of the secret to retrieve",
			},

			consts.FieldPath: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path where the KVV2 secret is written.",
			},

			consts.FieldDataJSON: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded secret data read from Vault.",
				Sensitive:   true,
			},

			consts.FieldData: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},

			"created_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the secret was created",
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

func kvSecretV2DataSourceRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	// prefix for v2 secrets is "data"
	path := getKVV2Path(mount, name, consts.FieldData)

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	var secret *api.Secret
	var err error
	if v, ok := d.GetOk(consts.FieldVersion); ok {
		data := map[string][]string{
			"version": {strconv.Itoa(v.(int))},
		}
		secret, err = client.Logical().ReadWithData(path, data)
		log.Printf("[DEBUG] Reading secret at %q (version %d) from Vault", path, v)
	} else {
		secret, err = client.Logical().Read(path)
		log.Printf("[DEBUG] Reading secret at %q (latest version) from Vault", path)
	}

	if err != nil {
		return diag.Errorf("error reading secret %q from Vault: %s", path, err)
	}
	if secret == nil {
		return diag.Errorf("no secret found at %q", path)
	}

	data := secret.Data["data"]

	jsonData, err := json.Marshal(data)
	if err != nil {
		return diag.Errorf("error marshaling JSON for %q: %s", path, err)
	}

	if err := d.Set(consts.FieldDataJSON, string(jsonData)); err != nil {
		return diag.FromErr(err)
	}

	if v, ok := data.(map[string]interface{}); ok {
		if err := d.Set(consts.FieldData, serializeDataMapToString(v)); err != nil {
			return diag.FromErr(err)
		}
	}

	if v, ok := secret.Data["metadata"]; ok {
		metadata := v.(map[string]interface{})

		if v, ok := metadata["created_time"]; ok {
			if err := d.Set("created_time", v); err != nil {
				return diag.FromErr(err)
			}
		}

		if v, ok := metadata["deletion_time"]; ok {
			if err := d.Set("deletion_time", v); err != nil {
				return diag.FromErr(err)
			}
		}

		if v, ok := metadata["destroyed"]; ok {
			if err := d.Set("destroyed", v); err != nil {
				return diag.FromErr(err)
			}
		}

		if customMetadata, ok := metadata["custom_metadata"]; ok && customMetadata != nil {
			if v, ok := customMetadata.(map[string]interface{}); ok {
				if err := d.Set("custom_metadata", serializeDataMapToString(v)); err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}

	d.SetId(path)

	return nil
}
