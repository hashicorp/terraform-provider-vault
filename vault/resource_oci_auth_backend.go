// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func ociAuthBackendResource() *schema.Resource {
	r := provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: ociAuthBackendWrite,
		UpdateContext: ociAuthBackendUpdate,
		ReadContext:   provider.ReadContextWrapper(ociAuthBackendRead),
		DeleteContext: ociAuthBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema: map[string]*schema.Schema{
			consts.FieldPath: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				Default:     consts.MountTypeOCI,
				// standardize on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldDescription: {
				Type:     schema.TypeString,
				Optional: true,
			},
			consts.FieldAccessor: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},
			consts.FieldOCIHomeTenancyID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: " The Tenancy OCID of your OCI account.",
				Sensitive:   true,
			},
			consts.FieldTune: authMountTuneSchema(),
		},
	}, false)

	// Add common automated root rotation schema to the resource.
	provider.MustAddSchema(r, provider.GetAutomatedRootRotationSchema())

	return r
}

func ociAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	desc := d.Get(consts.FieldDescription).(string)

	log.Printf("[DEBUG] Enabling %s auth backend %q", consts.AuthMethodOCI, path)
	err := client.Sys().EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{
		Type:        consts.AuthMethodOCI,
		Description: desc,
	})

	if err != nil {
		return diag.Errorf("error enabling %s auth backend %q: %s", consts.AuthMethodOCI, path, err)
	}
	log.Printf("[DEBUG] Enabled %s auth backend %q", consts.AuthMethodOCI, path)

	d.SetId(path)

	return ociAuthBackendUpdate(ctx, d, meta)
}

func ociAuthBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	ociPath := d.Id()
	ociAuthPath := "auth/" + ociPath
	path := ociAuthBackendConfigPath(ociPath)

	if !d.IsNewResource() {
		newMount, err := util.Remount(d, client, consts.FieldPath, true)
		if err != nil {
			return diag.FromErr(err)
		}

		ociAuthPath = "auth/" + newMount
		path = ociAuthBackendConfigPath(newMount)

		if d.HasChanges(consts.FieldDescription) {
			desc := d.Get(consts.FieldDescription).(string)
			config := api.MountConfigInput{
				Description: &desc,
			}
			if err := client.Sys().TuneMountWithContext(ctx, path, config); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	data := map[string]interface{}{}
	data[consts.FieldOCIHomeTenancyID] = d.Get(consts.FieldOCIHomeTenancyID)

	if d.HasChange(consts.FieldTune) {
		log.Printf("[INFO] %s Auth %q tune configuration changed", consts.AuthMethodOCI, ociAuthPath)
		if raw, ok := d.GetOk(consts.FieldTune); ok {
			log.Printf("[DEBUG] Writing %s auth tune to %q", consts.AuthMethodOCI, ociAuthPath)
			err := authMountTune(ctx, client, ociAuthPath, raw)
			if err != nil {
				return nil
			}
		}
	}

	if d.HasChange(consts.FieldDescription) {
		description := d.Get(consts.FieldDescription).(string)
		tune := api.MountConfigInput{Description: &description}
		err := client.Sys().TuneMountWithContext(ctx, ociAuthPath, tune)
		if err != nil {
			log.Printf("[ERROR] Error updating %s auth description at %q", consts.AuthMethodOCI, ociAuthPath)
			return diag.FromErr(err)
		}
	}

	log.Printf("[DEBUG] Writing %s config at path %q", consts.AuthMethodOCI, path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		d.SetId("")
		return diag.Errorf("error writing %s config %q: %s", consts.AuthMethodOCI, path, err)
	}

	log.Printf("[DEBUG] Wrote %s config %q", consts.AuthMethodOCI, path)

	return ociAuthBackendRead(ctx, d, meta)
}

func ociAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	ociPath := d.Id()
	ociAuthPath := "auth/" + ociPath
	path := ociAuthBackendConfigPath(ociPath)

	log.Printf("[DEBUG] Reading %s auth backend config %q", consts.AuthMethodOCI, path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading %s auth backend config %q: %s", consts.AuthMethodOCI, path, err)
	}
	log.Printf("[DEBUG] Read %s auth backend config %q", consts.AuthMethodOCI, path)

	if resp == nil {
		log.Printf("[WARN] %s auth backend config %q not found, removing from state", consts.AuthMethodOCI, path)
		d.SetId("")
		return nil
	}

	params := []string{
		consts.FieldOCIHomeTenancyID,
	}

	for _, param := range params {
		if err := d.Set(param, resp.Data[param]); err != nil {
			return diag.FromErr(err)
		}
	}

	mount, err := mountutil.GetAuthMount(ctx, client, ociPath)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", ociPath)
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading %s auth tune from '%s/tune'", consts.AuthMethodOCI, ociAuthPath)
	rawTune, err := authMountTuneGet(ctx, client, ociAuthPath)
	if err != nil {
		return diag.Errorf("error reading tune information from Vault: %s", err)
	}
	input, err := retrieveMountConfigInput(d)
	if err != nil {
		return diag.Errorf("error retrieving tune configuration from state: %s", err)
	}
	mergedTune := mergeAuthMethodTune(rawTune, input)
	if err := d.Set(consts.FieldTune, []map[string]interface{}{mergedTune}); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path '%s/tune' to state: %s", ociAuthPath, err)
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldAccessor, mount.Accessor); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldDescription, mount.Description); err != nil {
		return diag.FromErr(err)
	}
	// set the auth backend's path
	if err := d.Set(consts.FieldPath, ociPath); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func ociAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting %s auth backend %q", consts.AuthMethodOCI, path)
	err := client.Sys().DisableAuthWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error deleting %s auth backend %q: %q", consts.AuthMethodOCI, path, err)
	}
	log.Printf("[DEBUG] Deleted %s auth backend %q", consts.AuthMethodOCI, path)

	return nil
}

func ociAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}
