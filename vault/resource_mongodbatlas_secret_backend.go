// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"golang.org/x/net/context"
)

func mongodbAtlasSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: mongodbAtlasSecretBackendCreateUpdate,
		ReadContext:   ReadContextWrapper(mongodbAtlasSecretBackendRead),
		UpdateContext: mongodbAtlasSecretBackendCreateUpdate,
		DeleteContext: mongodbAtlasSecretBackendDelete,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where MongoDB Atlas secret backend is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			consts.FieldPath: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Path where MongoDB Atlas configuration is located",
			},
			consts.FieldPublicKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Public Programmatic API Key used to authenticate with the MongoDB Atlas API",
			},
			consts.FieldPrivateKey: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Private Programmatic API Key used to connect with MongoDB Atlas API",
			},
		},
	}
}

func mongodbAtlasSecretBackendCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mount := d.Get(consts.FieldMount).(string)
	privateKey := d.Get(consts.FieldPrivateKey).(string)
	publicKey := d.Get(consts.FieldPublicKey).(string)

	data := map[string]interface{}{
		consts.FieldPrivateKey: privateKey,
		consts.FieldPublicKey:  publicKey,
	}

	path := mount + "/config"
	log.Printf("[DEBUG] Writing MongoDB Atlas config at %q", path)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return diag.Errorf("error writing to %q, err=%s", path, err)
	}

	log.Printf("[DEBUG] Mounted MongoDB Atlas backend at %q", path)
	d.SetId(path)

	return mongodbAtlasSecretBackendRead(ctx, d, meta)
}

func mongodbAtlasSecretBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	mount := strings.TrimSuffix(path, "/config")
	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading MongoDB Atlas config at %s", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading MongoDB Atlas config at %q/config: err=%s", path, err)
	}

	if resp == nil {
		log.Printf("[WARN] MongoDB Atlas config not found, removing from state")
		d.SetId("")

		return nil
	}

	if err := d.Set(consts.FieldPublicKey, resp.Data[consts.FieldPublicKey]); err != nil {
		return diag.Errorf("error setting state key %q on MongoDB Atlas config, err=%s", consts.FieldPublicKey, err)
	}

	// set private key from TF config since it won't be returned from Vault
	if err := d.Set(consts.FieldPrivateKey, d.Get(consts.FieldPrivateKey).(string)); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func mongodbAtlasSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}
