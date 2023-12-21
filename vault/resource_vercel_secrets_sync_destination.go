// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldProjectID              = "project_id"
	fieldTeamID                 = "team_id"
	fieldDeploymentEnvironments = "deployment_environments"
)

var vercelSyncDestinationFields = []string{
	fieldAccessToken,
	fieldProjectID,
	fieldTeamID,
	fieldDeploymentEnvironments,
}

var vercelNonSensitiveFields = []string{
	fieldProjectID,
	fieldTeamID,
	fieldDeploymentEnvironments,
}

func vercelSecretsSyncDestinationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(vercelSecretsSyncDestinationWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(vercelSecretsSyncDestinationRead),
		DeleteContext: vercelSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the Vercel destination.",
				ForceNew:    true,
			},
			fieldAccessToken: {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
				Description: "Vercel API access token with the permissions to manage " +
					"environment variables.",
				ForceNew: true,
			},
			fieldProjectID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Project ID where to manage environment variables.",
				ForceNew:    true,
			},
			fieldTeamID: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Vercel API access token with the permissions to manage " +
					"environment variables.",
				ForceNew: true,
			},
			fieldDeploymentEnvironments: {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Required: true,
				Description: "Deployment environments where the environment " +
					"variables are available. Accepts 'development', " +
					"'preview' & 'production'.",
				ForceNew: true,
			},
		},
	}
}

func vercelSecretsSyncDestinationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := vercelSecretsSyncDestinationPath(name)

	data := map[string]interface{}{}

	for _, k := range vercelSyncDestinationFields {
		data[k] = d.Get(k)
	}

	log.Printf("[DEBUG] Writing Vercel sync destination to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error enabling Vercel sync destination %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled Vercel sync destination %q", path)

	d.SetId(name)

	return vercelSecretsSyncDestinationRead(ctx, d, meta)
}

func vercelSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	name := d.Id()
	path := vercelSecretsSyncDestinationPath(name)

	log.Printf("[DEBUG] Reading Vercel sync destination")
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading Vercel sync destination from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Vercel sync destination")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	for _, k := range vercelNonSensitiveFields {
		if data, ok := resp.Data[vaultFieldConnectionDetails]; ok {
			if m, ok := data.(map[string]interface{}); ok {
				if v, ok := m[k]; ok {
					if err := d.Set(k, v); err != nil {
						return diag.Errorf("error setting state key %q: err=%s", k, err)
					}
				}
			}
		}
	}

	return nil
}

func vercelSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := vercelSecretsSyncDestinationPath(d.Id())

	log.Printf("[DEBUG] Deleting Vercel sync destination at %q", path)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting Vercel sync destination at %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted Vercel sync destination at %q", path)

	return nil
}

func vercelSecretsSyncDestinationPath(name string) string {
	return "sys/sync/destinations/vercel-project/" + name
}
