package vault

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const (
	customMetadataKeyName     = "custom_metadata"
	deleteVersionAfterKeyName = "delete_version_after"
	maxVersionsKeyName        = "max_versions"
	casRequiredKeyName        = "cas_required"
)

func genericSecretMetadataResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		CreateContext: genericSecretMetadataResourceWrite,
		UpdateContext: genericSecretMetadataResourceWrite,
		DeleteContext: genericSecretMetadataResourceDelete,
		ReadContext:   genericSecretMetadataResourceRead,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the generic secret will be written.",
			},

			casRequiredKeyName: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			customMetadataKeyName: {
				Type:     schema.TypeMap,
				Optional: true,
				Default:  nil,
			},
			deleteVersionAfterKeyName: {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "0s",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					told, err := time.ParseDuration(old)
					if err != nil {
						return false
					}
					tnew, err := time.ParseDuration(new)
					if err != nil {
						return false
					}
					return told == tnew
				},
				ValidateFunc: func(i interface{}, s string) (e []string, es []error) {
					_, err := time.ParseDuration(i.(string))
					if err != nil {
						es = append(es, fmt.Errorf("unable to parse duration %s. err=%w", i, err))
					}
					return
				},
			},
			maxVersionsKeyName: {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  0,
			},
		},
	}
}

func genericSecretMetadataResourceWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	var metadata = map[string]interface{}{}
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	originalPath := path

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error determining if it's a v2 path: %s", err))
	}
	if !v2 {
		return diag.FromErr(fmt.Errorf("secret metadata requires a kv-v2 secret"))
	}
	path = addPrefixToVKVPath(path, mountPath, "metadata")

	// process metadata
	metadata[casRequiredKeyName] = d.Get(casRequiredKeyName).(bool)
	metadata[customMetadataKeyName] = d.Get(customMetadataKeyName).(map[string]interface{})
	metadata[deleteVersionAfterKeyName] = d.Get(deleteVersionAfterKeyName).(string)
	metadata[maxVersionsKeyName] = d.Get(maxVersionsKeyName).(int)

	_, err = client.Logical().Write(path, metadata)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error writing to Vault: %s", err))
	}

	d.SetId(originalPath)

	genericSecretMetadataResourceRead(ctx, d, meta)

	return diags
}

func genericSecretMetadataResourceDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	client := meta.(*api.Client)

	path := d.Id()

	mountPath, _, err := isKVv2(path, client)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error determining if it's a v2 path: %s", err))
	}
	path = addPrefixToVKVPath(path, mountPath, "metadata")

	log.Printf("[DEBUG] Deleting vault_generic_metadata_secret from %q", path)
	_, err = client.Logical().Write(path, map[string]interface{}{
		casRequiredKeyName:        false,
		customMetadataKeyName:     nil,
		deleteVersionAfterKeyName: "0s",
		maxVersionsKeyName:        0,
	})
	if err != nil {
		return diag.FromErr(fmt.Errorf("error deleting %q from Vault: %q", path, err))
	}

	return diags
}

func genericSecretMetadataResourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	path := d.Id()
	client := meta.(*api.Client)
	secretMetadata, err := readKVMetadata(path, client)

	if err != nil {
		return diag.FromErr(err)
	}

	d.Set("path", path)
	d.Set(casRequiredKeyName, secretMetadata.Data[casRequiredKeyName].(bool))
	if val, ok := secretMetadata.Data[customMetadataKeyName]; ok {
		d.Set(customMetadataKeyName, val.(map[string]interface{}))
	}
	d.Set(deleteVersionAfterKeyName, secretMetadata.Data[deleteVersionAfterKeyName].(string))
	d.Set(maxVersionsKeyName, secretMetadata.Data[maxVersionsKeyName])

	return diags
}
