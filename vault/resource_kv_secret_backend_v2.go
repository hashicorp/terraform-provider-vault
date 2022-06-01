package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/util"
)

func kvSecretBackendV2Resource() *schema.Resource {
	return &schema.Resource{
		CreateContext: kvSecretBackendV2CreateUpdate,
		UpdateContext: kvSecretBackendV2CreateUpdate,
		DeleteContext: kvSecretBackendV2Delete,
		ReadContext:   kvSecretBackendV2Read,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"mount": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path where KV-V2 engine is mounted.",
			},
			"max_versions": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The number of versions to keep per key.",
			},
			"cas_required": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				Description: "If true, all keys will require the cas " +
					"parameter to be set on all write requests.",
			},
			"delete_version_after": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The full duration string for " +
					"`delete_version_after_input` formatted by Vault in " +
					"`00h00m00s` format",
			},
			"delete_version_after_input": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "If set, specifies the length of time before " +
					"a version is deleted. Accepts Go duration format string.",
			},
		},
	}
}

func kvSecretBackendV2CreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)
	mount := d.Get("mount").(string)

	schemaToVaultFieldMap := map[string]string{
		"max_versions":               "",
		"cas_required":               "",
		"delete_version_after_input": "delete_version_after",
	}

	data := util.GetAPIRequestData(d, schemaToVaultFieldMap)

	path := mount + "/config"
	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing config data to %s, err=%s", path, err)
	}

	d.SetId(path)

	return kvSecretBackendV2Read(ctx, d, meta)
}

func kvSecretBackendV2Read(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)
	diags := diag.Diagnostics{}

	path := d.Id()

	log.Printf("[DEBUG] Reading %s from Vault", path)
	config, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading config from Vault: %s", err)
	}
	if config == nil {
		log.Printf("[WARN] config (%s) not found, removing from state", path)
		d.SetId("")
		return nil
	}

	configFields := []string{"max_versions", "cas_required", "delete_version_after"}
	for _, k := range configFields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}

func kvSecretBackendV2Delete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}
