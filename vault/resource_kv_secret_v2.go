// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var kvMetadataFields = map[string]string{
	consts.FieldMaxVersions:        consts.FieldMaxVersions,
	consts.FieldCASRequired:        consts.FieldCASRequired,
	consts.FieldDeleteVersionAfter: consts.FieldDeleteVersionAfter,
	consts.FieldCustomMetadata:     consts.FieldData,
}

func kvSecretV2Resource(name string) *schema.Resource {
	return &schema.Resource{
		CreateContext: kvSecretV2Write,
		UpdateContext: kvSecretV2Write,
		DeleteContext: kvSecretV2Delete,
		ReadContext:   ReadContextWrapper(kvSecretV2Read),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path where KV-V2 engine is mounted.",
			},
			consts.FieldName: {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				Description: "Full name of the secret. For a nested secret, " +
					"the name is the nested path excluding the mount and data " +
					"prefix. For example, for a secret at 'kvv2/data/foo/bar/baz', " +
					"the name is 'foo/bar/baz'",
			},
			consts.FieldPath: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path where the KV-V2 secret will be written.",
			},
			"cas": {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "This flag is required if cas_required is set to true " +
					"on either the secret or the engine's config. In order for a " +
					"write to be successful, cas must be set to the current version " +
					"of the secret.",
			},
			"options": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "An object that holds option settings.",
			},

			"disable_read": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				Description: "If set to true, disables reading secret from Vault; " +
					"note: drift won't be detected.",
			},

			// Data is passed as JSON so that an arbitrary structure is
			// possible, rather than forcing e.g. all values to be strings.
			consts.FieldDataJSON: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "JSON-encoded secret data to write.",
				// We rebuild the attached JSON string to a simple single-line
				// string. These make Terraform not want to change when an extra
				// space is included in the JSON string. It is also necessary
				// when disable_read is false for comparing values.
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
				Sensitive:    true,
			},

			consts.FieldData: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},

			consts.FieldMetadata: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Metadata associated with this secret read from Vault.",
			},

			"delete_all_versions": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, permanently deletes all versions for the specified key.",
			},

			consts.FieldCustomMetadata: {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "Custom metadata to be set for the secret.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						consts.FieldMaxVersions: {
							Type:        schema.TypeInt,
							Optional:    true,
							Description: "The number of versions to keep per key.",
						},
						consts.FieldCASRequired: {
							Type:     schema.TypeBool,
							Optional: true,
							Description: "If true, all keys will require the cas " +
								"parameter to be set on all write requests.",
						},
						consts.FieldDeleteVersionAfter: {
							Type:     schema.TypeInt,
							Optional: true,
							Description: "If set, specifies the length of time before " +
								"a version is deleted.",
						},
						consts.FieldData: {
							Type:     schema.TypeMap,
							Optional: true,
							Description: "A map of arbitrary string to string valued " +
								"user-provided metadata meant to describe the secret.",
						},
					},
				},
				MaxItems: 1,
			},
		},
	}
}

func getKVV2Path(mount, name, prefix string) string {
	return fmt.Sprintf("%s/%s/%s", mount, prefix, name)
}

func getCustomMetadata(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}

	fieldPrefix := fmt.Sprintf("%s.0", consts.FieldCustomMetadata)
	for vaultKey, stateKey := range kvMetadataFields {
		fieldKey := fmt.Sprintf("%s.%s", fieldPrefix, stateKey)

		if val, ok := d.GetOk(fieldKey); ok {
			data[vaultKey] = val
		}
	}
	return data
}

func kvSecretV2Write(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	path := getKVV2Path(mount, name, consts.FieldData)

	var secretData map[string]interface{}
	err := json.Unmarshal([]byte(d.Get(consts.FieldDataJSON).(string)), &secretData)
	if err != nil {
		return diag.Errorf("data_json %#v syntax error: %s", d.Get(consts.FieldDataJSON), err)
	}

	data := map[string]interface{}{
		"data": secretData,
	}

	kvFields := []string{"cas", "options"}
	for _, k := range kvFields {
		data[k] = d.Get(k)
	}

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing secret data to %s, err=%s", path, err)
	}

	d.SetId(path)

	// Write custom metadata for secret if provided
	if _, ok := d.GetOk(consts.FieldCustomMetadata); ok {
		cm := getCustomMetadata(d)

		metadataPath := getKVV2Path(mount, name, consts.FieldMetadata)
		log.Printf("[DEBUG] Writing custom metadata for secret at %s", path)
		if _, err := client.Logical().Write(metadataPath, cm); err != nil {
			return diag.Errorf("error writing custom metadata to %s, err=%s", metadataPath, err)
		}
	}

	return kvSecretV2Read(ctx, d, meta)
}

func kvSecretV2Read(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	shouldRead := !d.Get("disable_read").(bool)

	path := d.Id()
	if path == "" {
		return nil
	}

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	// id should be of the form "mount/data/name"
	// limit substrings to 3 in case name has '/'
	// in it or if it's a nested secret
	parsedPath := strings.SplitN(path, "/", 3)
	if len(parsedPath) != 3 {
		return diag.Errorf("invalid format for KV secret path %s", path)
	}

	mount := parsedPath[0]
	name := parsedPath[2]

	// Set mount and name fields
	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	if shouldRead {

		client, e := provider.GetClient(d, meta)
		if e != nil {
			return diag.FromErr(e)
		}

		log.Printf("[DEBUG] Reading %s from Vault", path)
		secret, err := client.Logical().Read(path)
		if err != nil {
			return diag.Errorf("error reading from Vault: %s", err)
		}
		if secret == nil {
			log.Printf("[WARN] secret (%s) not found, removing from state", path)
			d.SetId("")
			return nil
		}

		log.Printf("[DEBUG] secret: %#v", secret)

		data := secret.Data["data"]

		if v, ok := data.(map[string]interface{}); ok {
			if err := d.Set(consts.FieldData, serializeDataMapToString(v)); err != nil {
				return diag.FromErr(err)
			}
		}

		if metadata, ok := secret.Data["metadata"]; ok {
			if v, ok := metadata.(map[string]interface{}); ok {
				if err := d.Set(consts.FieldMetadata, serializeDataMapToString(v)); err != nil {
					return diag.FromErr(err)
				}

				// Read & Set custom metadata
				if _, ok := v[consts.FieldCustomMetadata]; ok {
					// construct metadata path
					parsedPath[1] = "metadata"
					metadataPath := strings.Join(parsedPath, "/")
					cm, err := readKVV2Metadata(client, metadataPath)
					if err != nil {
						return diag.FromErr(err)
					}

					if err := d.Set(consts.FieldCustomMetadata, []interface{}{cm}); err != nil {
						return diag.FromErr(err)
					}
				}
			}
		}

	}

	return nil
}

func readKVV2Metadata(client *api.Client, path string) (map[string]interface{}, error) {
	log.Printf("[DEBUG] Reading metadata for KVV2 secret at %s", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	if resp == nil {
		log.Printf("[DEBUG] no metadata found for secret")
		return nil, nil
	}

	data := map[string]interface{}{}

	for vaultKey, tfKey := range kvMetadataFields {
		if val, ok := resp.Data[vaultKey]; ok {
			// the delete_version_after field is written to
			// Vault as an integer but is returned as a string
			// of the format "3h12m10s"
			if vaultKey == consts.FieldDeleteVersionAfter {
				t, err := time.ParseDuration(val.(string))
				if err != nil {
					return nil, fmt.Errorf("error parsing duration, err=%s", err)
				}
				val = t.Seconds()
			}

			data[tfKey] = val

		}
	}

	return data, nil
}

func kvSecretV2Delete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	base := consts.FieldData
	deleteAllVersions := d.Get("delete_all_versions").(bool)
	if deleteAllVersions {
		base = consts.FieldMetadata
	}

	path := getKVV2Path(mount, name, base)

	log.Printf("[DEBUG] Deleting vault_kv_secret_v2 from %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}
