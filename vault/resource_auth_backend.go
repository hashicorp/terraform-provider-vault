// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func AuthBackendResource() *schema.Resource {
	return provider.MustAddMountMigrationSchema(&schema.Resource{
		SchemaVersion: 1,

		CreateContext: authBackendWrite,
		DeleteContext: authBackendDelete,
		ReadContext:   provider.ReadContextWrapper(authBackendRead),
		UpdateContext: authBackendUpdate,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		MigrateState:  resourceAuthBackendMigrateState,
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),

		Schema: map[string]*schema.Schema{
			consts.FieldType: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the auth backend",
			},

			consts.FieldPath: {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				Description:  "path to mount the backend. This defaults to the type.",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},

			consts.FieldDescription: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			consts.FieldLocal: {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Description: "Specifies if the auth method is local only",
			},

			consts.FieldAccessor: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},

			consts.FieldIdentityTokenKey: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The key to use for signing identity tokens.",
			},

			consts.FieldTune: authMountTuneSchema(),
		},
	}, false)
}

func authBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	mountType := d.Get(consts.FieldType).(string)
	path := d.Get(consts.FieldPath).(string)

	if path == "" {
		path = mountType
	}

	config := &api.MountConfigInput{}
	useAPIver117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
	if useAPIver117Ent {
		if v, ok := d.GetOk(consts.FieldIdentityTokenKey); ok {
			config.IdentityTokenKey = v.(string)
		}
	}

	options := &api.EnableAuthOptions{
		Type:        mountType,
		Description: d.Get(consts.FieldDescription).(string),
		Local:       d.Get(consts.FieldLocal).(bool),
		Config:      *config,
	}

	log.Printf("[DEBUG] Writing auth %q to Vault", path)
	if err := client.Sys().EnableAuthWithOptionsWithContext(ctx, path, options); err != nil {
		return diag.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return authBackendUpdate(ctx, d, meta)
}

func authBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	if err := client.Sys().DisableAuthWithContext(ctx, path); err != nil {
		return diag.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func authBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	mount, err := mountutil.GetAuthMount(ctx, client, path)
	if errors.Is(err, mountutil.ErrMountNotFound) {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldType, mount.Type); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldDescription, mount.Description); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldLocal, mount.Local); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldAccessor, mount.Accessor); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldIdentityTokenKey, mount.Config.IdentityTokenKey); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func authBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	if !d.IsNewResource() {
		path, e = util.Remount(d, client, consts.FieldPath, true)
		if e != nil {
			return diag.FromErr(e)
		}
	}

	backendType := d.Get(consts.FieldType).(string)
	var config api.MountConfigInput
	var callTune bool

	if d.HasChange(consts.FieldTune) {
		log.Printf("[INFO] Auth '%q' tune configuration changed", path)

		if raw, ok := d.GetOk(consts.FieldTune); ok {
			log.Printf("[DEBUG] Writing %s auth tune to '%q'", backendType, path)

			config = expandAuthMethodTune(raw.(*schema.Set).List())
		}
		callTune = true
	}

	if d.HasChanges(consts.FieldIdentityTokenKey, consts.FieldDescription) && !d.IsNewResource() {
		desc := d.Get(consts.FieldDescription).(string)
		config.Description = &desc

		useAPIVer117Ent := provider.IsAPISupported(meta, provider.VaultVersion117) && provider.IsEnterpriseSupported(meta)
		if useAPIVer117Ent {
			config.IdentityTokenKey = d.Get(consts.FieldIdentityTokenKey).(string)
		}

		callTune = true
	}

	if callTune {
		if err := tuneMount(client, "auth/"+path, config); err != nil {
			return diag.FromErr(e)
		}

		log.Printf("[INFO] Written %s auth tune to '%q'", backendType, path)
	}

	return authBackendRead(ctx, d, meta)
}
