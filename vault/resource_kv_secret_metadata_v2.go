package vault

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretMetadataV2Resource(name string) *schema.Resource {
	return &schema.Resource{
		CreateContext: kvSecretMetadataV2CreateUpdate,
		UpdateContext: kvSecretMetadataV2CreateUpdate,
		DeleteContext: kvSecretMetadataV2Delete,
		ReadContext:   kvSecretMetadataV2Read,
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
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique identifier for the secret metadata.",
			},
			consts.FieldMaxVersions: {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The number of versions to keep per key.",
			},
			consts.FieldCASRequired: {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				Description: "If true, all keys will require the cas " +
					"parameter to be set on all write requests.",
			},
			consts.FieldDeleteVersionAfter: {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "If set, specifies the length of time before " +
					"a version is deleted",
			},
			consts.FieldCustomMetadataJSON: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "JSON-encoded secret metadata to write",
				StateFunc:    NormalizeDataJSONFunc(name),
				ValidateFunc: ValidateDataJSONFunc(name),
				Sensitive:    true,
			},
			consts.FieldCustomMetadata: {
				Type:     schema.TypeMap,
				Computed: true,
				Description: "A map of arbitrary string to string valued " +
					"user-provided metadata meant to describe the secret",
			},
		},
	}
}

func kvSecretMetadataV2CreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	data := map[string]interface{}{}

	if v, ok := d.GetOk(consts.FieldCustomMetadataJSON); ok {
		var secretMetadata map[string]interface{}
		err := json.Unmarshal([]byte(v.(string)), &secretMetadata)
		if err != nil {
			return diag.Errorf("data_json %#v syntax error: %s", v, err)
		}

		data[consts.FieldCustomMetadata] = secretMetadata

	}

	fields := []string{consts.FieldMaxVersions, consts.FieldCASRequired, consts.FieldDeleteVersionAfter}
	for _, k := range fields {
		data[k] = d.Get(k)
	}

	path := getKVV2Path(mount, name, consts.FieldMetadata)
	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing metadata to %s, err=%s", path, err)
	}

	d.SetId(path)

	return kvSecretMetadataV2Read(ctx, d, meta)
}

func kvSecretMetadataV2Read(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	diags := diag.Diagnostics{}

	path := d.Id()

	log.Printf("[DEBUG] Reading %s from Vault", path)
	config, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading secret metadata from Vault: %s", err)
	}
	if config == nil {
		log.Printf("[WARN] metadata (%s) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	configFields := []string{consts.FieldMaxVersions, consts.FieldCASRequired}
	for _, k := range configFields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	if metadata, ok := config.Data[consts.FieldCustomMetadata]; ok {
		if v, ok := metadata.(map[string]interface{}); ok {
			if err := d.Set(consts.FieldCustomMetadata, serializeDataMapToString(v)); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	// convert delete_version_after to seconds
	if v, ok := config.Data[consts.FieldDeleteVersionAfter]; ok && v != nil {
		durationString := config.Data[consts.FieldDeleteVersionAfter].(string)
		t, err := time.ParseDuration(durationString)
		if err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set(consts.FieldDeleteVersionAfter, t.Seconds()); err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}

func kvSecretMetadataV2Delete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting Secret Metadata at %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting secret metadata %q", path)
	}

	log.Printf("[DEBUG] Deleted Secret Metadata %q", path)

	return nil
}
