// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"log"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/net/context"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func mongodbAtlasSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: mongodbAtlasSecretBackendCreateUpdate,
		ReadContext:   provider.ReadContextWrapper(mongodbAtlasSecretBackendRead),
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
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				Description:  "The Private Programmatic API Key used to connect with MongoDB Atlas API",
				ExactlyOneOf: []string{consts.FieldPrivateKey, consts.FieldPrivateKeyWO},
			},
			consts.FieldPrivateKeyWO: {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				WriteOnly:    true,
				Description:  "The Private Programmatic API Key used to connect with MongoDB Atlas API. This is a write-only field that is not stored in state.",
				ExactlyOneOf: []string{consts.FieldPrivateKey, consts.FieldPrivateKeyWO},
			},
			consts.FieldPrivateKeyWOVersion: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Incrementing version counter for the private_key_wo field. Increment to force an update to the private key.",
				RequiredWith: []string{consts.FieldPrivateKeyWO},
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
	publicKey := d.Get(consts.FieldPublicKey).(string)

	var privateKey string

	// Check if using write-only field (new resource or version changed)
	if d.IsNewResource() || d.HasChange(consts.FieldPrivateKeyWOVersion) {
		if _, ok := d.GetOk(consts.FieldPrivateKeyWOVersion); ok {
			p := cty.GetAttrPath(consts.FieldPrivateKeyWO)
			woVal, _ := d.GetRawConfigAt(p)
			if !woVal.IsNull() {
				privateKey = woVal.AsString()
			}
		}
	}

	// Fallback to legacy field if write-only not set
	if privateKey == "" {
		if v, ok := d.GetOk(consts.FieldPrivateKey); ok {
			privateKey = v.(string)
		}
	}

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

	// Only set private_key if using legacy field (not write-only)
	// Write-only fields should never be stored in state
	if _, ok := d.GetOk(consts.FieldPrivateKeyWOVersion); !ok {
		// Not using write-only, so set legacy field from config
		if err := d.Set(consts.FieldPrivateKey, d.Get(consts.FieldPrivateKey).(string)); err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func mongodbAtlasSecretBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return nil
}
