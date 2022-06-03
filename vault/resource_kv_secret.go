package vault

import (
	"context"
	"encoding/json"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretResource(name string) *schema.Resource {
	return &schema.Resource{
		CreateContext: kvSecretWrite,
		UpdateContext: kvSecretWrite,
		DeleteContext: kvSecretDelete,
		ReadContext:   kvSecretRead,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path of the KV-V1 secret.",
			},
			"data_json": {
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
			"data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},
		},
	}
}

func kvSecretWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()
	path := d.Get("path").(string)

	var secretData map[string]interface{}
	err := json.Unmarshal([]byte(d.Get("data_json").(string)), &secretData)
	if err != nil {
		return diag.Errorf("data_json %#v syntax error: %s", d.Get("data_json"), err)
	}

	data := map[string]interface{}{
		"data": secretData,
	}

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error writing secret data to %s, err=%s", path, err)
	}

	d.SetId(path)

	return kvSecretRead(ctx, d, meta)
}

func kvSecretRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	path := d.Id()

	if err := d.Set("path", path); err != nil {
		return diag.FromErr(err)
	}

	client := meta.(*provider.ProviderMeta).GetClient()

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

	if err := d.Set("data", serializeDataMapToString(data.(map[string]interface{}))); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func kvSecretDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()
	path := d.Id()

	log.Printf("[DEBUG] Deleting vault_kv_secret from %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting %q from Vault: %q", path, err)
	}

	return nil
}
