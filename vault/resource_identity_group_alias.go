// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	identityGroupAliasPath   = "/identity/group-alias"
	identityGroupAliasIDPath = identityGroupAliasPath + "/id"
)

func identityGroupAliasResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: identityGroupAliasCreate,
		UpdateContext: identityGroupAliasUpdate,
		ReadContext:   provider.ReadContextWrapper(identityGroupAliasRead),
		DeleteContext: identityGroupAliasDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the group alias.",
			},

			consts.FieldMountAccessor: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Mount accessor to which this alias belongs to.",
			},

			"canonical_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the group to which this is an alias.",
			},
		},
	}
}

func identityGroupAliasCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	lock, unlock := getEntityLockFuncs(d, identityGroupAliasIDPath)
	lock()
	defer unlock()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get("name").(string)
	mountAccessor := d.Get(consts.FieldMountAccessor).(string)
	canonicalID := d.Get("canonical_id").(string)

	path := identityGroupAliasPath

	data := map[string]interface{}{
		"name":                    name,
		consts.FieldMountAccessor: mountAccessor,
		"canonical_id":            canonicalID,
	}

	resp, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error writing IdentityGroupAlias to %q: %s", name, err))
	}
	log.Printf("[DEBUG] Wrote IdentityGroupAlias %q", name)
	d.SetId(resp.Data["id"].(string))

	return identityGroupAliasRead(ctx, d, meta)
}

func identityGroupAliasUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	lock, unlock := getEntityLockFuncs(d, identityGroupAliasIDPath)
	lock()
	defer unlock()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroupAlias %q", id)
	path := getIdentityGroupAliasIDPath(id)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating IdentityGroupAlias %q: %s", id, err))
	}

	data := map[string]interface{}{
		"name":                    resp.Data["name"],
		consts.FieldMountAccessor: resp.Data[consts.FieldMountAccessor],
		"canonical_id":            resp.Data["canonical_id"],
	}

	if name, ok := d.GetOk("name"); ok {
		data["name"] = name
	}
	if mountAccessor, ok := d.GetOk(consts.FieldMountAccessor); ok {
		data[consts.FieldMountAccessor] = mountAccessor
	}
	if canonicalID, ok := d.GetOk("canonical_id"); ok {
		data["canonical_id"] = canonicalID
	}

	_, err = client.Logical().WriteWithContext(ctx, path, data)

	if err != nil {
		return diag.FromErr(fmt.Errorf("error updating IdentityGroupAlias %q: %s", id, err))
	}
	log.Printf("[DEBUG] Updated IdentityGroupAlias %q", id)

	return identityGroupAliasRead(ctx, d, meta)
}

func identityGroupAliasRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	path := getIdentityGroupAliasIDPath(id)

	log.Printf("[DEBUG] Reading IdentityGroupAlias %s from %q", id, path)
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading IdentityGroupAlias %q: %s", id, err))
	}
	log.Printf("[DEBUG] Read IdentityGroupAlias %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroupAlias %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	d.SetId(resp.Data["id"].(string))
	for _, k := range []string{"name", consts.FieldMountAccessor, "canonical_id"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key \"%s\" on IdentityGroupAlias %q: %s", k, id, err))
		}
	}
	return nil
}

func identityGroupAliasDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	lock, unlock := getEntityLockFuncs(d, identityGroupAliasIDPath)
	lock()
	defer unlock()

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()

	path := getIdentityGroupAliasIDPath(id)

	log.Printf("[DEBUG] Deleting IdentityGroupAlias %q", id)
	_, err := client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error IdentityGroupAlias %q", id))
	}
	log.Printf("[DEBUG] Deleted IdentityGroupAlias %q", id)

	return nil
}

func identityGroupAliasNamePath(name string) string {
	return fmt.Sprintf("%s/name/%s", identityGroupAliasPath, name)
}

func getIdentityGroupAliasIDPath(id string) string {
	return fmt.Sprintf("%s/%s", identityGroupAliasIDPath, id)
}
