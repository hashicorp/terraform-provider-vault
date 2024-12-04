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
	"github.com/hashicorp/terraform-provider-vault/util"
)

func AuthBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
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

	// Add common mount schema to the resource
	provider.MustAddSchema(r, getAuthMountSchema(
		consts.FieldPath,
		consts.FieldType,
		consts.FieldDescription,
		consts.FieldAccessor,
		consts.FieldLocal,
		consts.FieldIdentityTokenKey,
	))

	return r
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

	log.Printf("[DEBUG] Writing auth %q to Vault", path)
	if err := createAuthMount(ctx, d, meta, client, &createMountRequestParams{
		Path:          path,
		MountType:     mountType,
		SkipTokenType: false,
	}); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(path)

	return authBackendUpdate(ctx, d, meta)
}

func authBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	return authMountDisable(ctx, client, d.Id())
}

func authBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := readAuthMount(ctx, d, meta, true, false); err != nil {
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

		// tune auth mount if needed
		if err := updateAuthMount(ctx, d, meta, true, false); err != nil {
			return diag.FromErr(err)
		}
	}

	return authBackendRead(ctx, d, meta)
}
