package vault

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
			consts.FieldMount: {
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
				Type:     schema.TypeInt,
				Optional: true,
				Description: "If set, specifies the length of time before " +
					"a version is deleted",
			},
		},
	}
}

func kvSecretBackendV2CreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()
	mount := d.Get("mount").(string)

	data := map[string]interface{}{}

	fields := []string{"max_versions", "cas_required"}

	for _, k := range fields {
		data[k] = d.Get(k)
	}

	// convert input seconds to duration string
	if deleteVersionSeconds, ok := d.GetOk("delete_version_after"); ok {
		data["delete_version_after"] = formatIntToDurationString(deleteVersionSeconds.(int))
	}

	path := mount + "/config"
	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing config data to %s, err=%s", path, err)
	}

	d.SetId(path)

	return kvSecretBackendV2Read(ctx, d, meta)
}

func kvSecretBackendV2Read(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()
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

	configFields := []string{"max_versions", "cas_required"}
	for _, k := range configFields {
		if err := d.Set(k, config.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	// convert delete_version_after to seconds
	if err := config.Data["delete_version_after"]; err != nil {
		durationString := config.Data["delete_version_after"].(string)
		t, _ := time.ParseDuration(durationString)
		if err := d.Set("delete_version_after", t.Seconds()); err != nil {
			return diag.FromErr(err)
		}
	}

	return diags
}

func formatIntToDurationString(input int) string {
	hours := input / 3600
	minutes := (input % 3600) / 60
	seconds := (input % 3600) % 60

	return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
}

func kvSecretBackendV2Delete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}
