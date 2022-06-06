package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: kvSecretDataSourceRead,

		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path of the KV-V1 secret.",
			},
			consts.FieldData: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},
			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by Vault.",
			},
			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds.",
			},
			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func kvSecretDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*provider.ProviderMeta).GetClient()

	path := d.Get("path").(string)

	if err := d.Set("path", path); err != nil {
		return diag.FromErr(err)
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

	if err := d.Set("lease_id", secret.LeaseID); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("lease_duration", secret.LeaseDuration); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("lease_renewable", secret.Renewable); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
