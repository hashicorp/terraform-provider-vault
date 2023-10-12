// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func identityEntityAliasResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: identityEntityAliasCreate,
		UpdateContext: identityEntityAliasUpdate,
		ReadContext:   provider.ReadContextWrapper(identityEntityAliasRead),
		DeleteContext: identityEntityAliasDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the entity alias.",
			},

			consts.FieldMountAccessor: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Mount accessor to which this alias belongs toMount accessor to which this alias belongs to.",
			},

			"canonical_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the entity to which this is an alias.",
			},
			"custom_metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Custom metadata to be associated with this alias.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func identityEntityAliasCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	lock, unlock := getEntityLockFuncs(d, entity.RootAliasIDPath)
	lock()
	defer unlock()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := entity.RootAliasPath
	name := d.Get("name").(string)
	data := util.GetAPIRequestDataWithMap(d, map[string]string{
		"name":                    "",
		consts.FieldMountAccessor: "",
		"canonical_id":            "",
		"custom_metadata":         "",
	})

	diags := diag.Diagnostics{}

	mountAccessor := data[consts.FieldMountAccessor].(string)
	alias, err := entity.LookupEntityAlias(
		client,
		&entity.FindAliasParams{
			Name:          name,
			MountAccessor: mountAccessor,
		},
	)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("Failed to get entity aliases by mount accessor, err=%s", err),
		})
	}

	if alias != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary: fmt.Sprintf(
				"entity alias %q already exists for mount accessor %q, "+
					"id=%q", name, mountAccessor, alias.ID),
			Detail: "In the case where this error occurred during the creation of more than one alias, " +
				"it may be necessary to assign a unique alias name to each of affected resources and " +
				"then rerun the apply. After a successful apply the desired original alias names can then be " +
				"reassigned",
		})

		return diags
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary: fmt.Sprintf(
				"error writing entity alias to %q: %s", name, err),
		})

		return diags
	}

	if resp == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary: fmt.Sprintf(
				"unexpected empty response during entity alias creation name=%q", name),
		})

		return diags

	}

	log.Printf("[DEBUG] Wrote entity alias %q", name)

	d.SetId(resp.Data["id"].(string))

	return identityEntityAliasRead(ctx, d, meta)
}

func identityEntityAliasUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	lock, unlock := getEntityLockFuncs(d, entity.RootAliasIDPath)
	lock()
	defer unlock()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	log.Printf("[DEBUG] Updating entity alias %q", id)
	path := entity.JoinAliasID(id)

	diags := diag.Diagnostics{}
	data := util.GetAPIRequestDataWithMap(d, map[string]string{
		"name":                    "",
		consts.FieldMountAccessor: "",
		"canonical_id":            "",
		"custom_metadata":         "",
	})
	if _, err := client.Logical().Write(path, data); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("error updating entity alias %q: %s", id, err),
		})

		return diags
	}

	log.Printf("[DEBUG] Updated entity alias %q", id)

	return identityEntityAliasRead(ctx, d, meta)
}

func identityEntityAliasRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	path := entity.JoinAliasID(id)

	diags := diag.Diagnostics{}

	log.Printf("[DEBUG] Reading entity alias %q from %q", id, path)
	resp, err := entity.ReadEntity(client, path, d.IsNewResource())
	if err != nil {
		if group.IsIdentityNotFoundError(err) {
			log.Printf("[WARN] entity alias %q not found, removing from state", id)
			d.SetId("")
			return diags
		}

		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("error reading entity alias %q: %s", id, err),
		})

		return diags
	}

	d.SetId(resp.Data["id"].(string))
	for _, k := range []string{"name", consts.FieldMountAccessor, "canonical_id", "custom_metadata"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  fmt.Sprintf("error setting state key %q on entity alias %q: err=%q", k, id, err),
			})

			return diags
		}
	}

	return diags
}

func identityEntityAliasDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	lock, unlock := getEntityLockFuncs(d, entity.RootAliasIDPath)
	lock()
	defer unlock()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	path := entity.JoinAliasID(id)

	diags := diag.Diagnostics{}

	baseMsg := fmt.Sprintf("entity alias ID %q on mount_accessor %q", id, d.Get(consts.FieldMountAccessor))
	log.Printf("[INFO] Deleting %s", baseMsg)
	_, err := client.Logical().Delete(path)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  fmt.Sprintf("failed deleting %s, err=%s", baseMsg, err),
		})
		return diags
	}
	log.Printf("[INFO] Successfully deleted %s", baseMsg)

	return diags
}

func getEntityLockFuncs(d *schema.ResourceData, root string) (func(), func()) {
	mountAccessor := d.Get(consts.FieldMountAccessor).(string)
	lockKey := strings.Join([]string{root, mountAccessor}, "/")
	lock := func() {
		provider.VaultMutexKV.Lock(lockKey)
	}

	unlock := func() {
		provider.VaultMutexKV.Unlock(lockKey)
	}
	return lock, unlock
}
