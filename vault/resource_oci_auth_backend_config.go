// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func ociAuthBackendConfigResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: ociAuthBackendWrite,
		ReadContext:   ReadContextWrapper(ociAuthBackendRead),
		UpdateContext: ociAuthBackendWrite,
		DeleteContext: ociAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "oci",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"home_tenancy_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: " The Tenancy OCID of your OCI account.",
				Sensitive:   true,
			},
		},
	}
}

func ociAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	// if backend comes from the config, it won't have the StateFunc
	// applied yet, so we need to apply it again.
	backend := d.Get("backend").(string)
	homeTenancyId := d.Get("home_tenancy_id").(string)

	path := ociAuthBackendConfigPath(backend)

	data := map[string]interface{}{
		"home_tenancy_id": homeTenancyId,
	}

	log.Printf("[DEBUG] Writing OCI auth backend config to %q", path)
	_, err := config.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote OCI auth backend config to %q", path)

	d.SetId(path)

	return ociAuthBackendRead(ctx, d, meta)
}

func ociAuthBackendRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	log.Printf("[DEBUG] Reading OCI auth backend config")
	secret, err := config.Logical().Read(d.Id())
	if err != nil {
		return diag.Errorf("error reading OCI auth backend config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Read OCI auth backend config")

	if secret == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", d.Id())
		d.SetId("")
		return nil
	}

	idPieces := strings.Split(d.Id(), "/")
	if len(idPieces) != 3 {
		return diag.Errorf("expected %q to have 4 pieces, has %d", d.Id(), len(idPieces))
	}
	d.Set("backend", idPieces[1])
	d.Set("home_tenancy_id", secret.Data["home_tenancy_id"])
	return nil
}

func ociAuthBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	log.Printf("[DEBUG] Deleting OCI auth backend config from %q", d.Id())
	_, err := config.Logical().Delete(d.Id())
	if err != nil {
		return diag.Errorf("error deleting OCI auth backend config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted OCI auth backend config from %q", d.Id())

	return nil
}

func ociAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}
