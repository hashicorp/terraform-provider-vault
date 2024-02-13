// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const identityGroupAliasPath = "/identity/group-alias"

func identityGroupAliasResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupAliasCreate,
		Update: identityGroupAliasUpdate,
		Read:   provider.ReadWrapper(identityGroupAliasRead),
		Delete: identityGroupAliasDelete,
		Exists: identityGroupAliasExists,
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

func identityGroupAliasCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	mountAccessor := d.Get(consts.FieldMountAccessor).(string)
	canonicalID := d.Get("canonical_id").(string)

	path := identityGroupAliasPath

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	data := map[string]interface{}{
		"name":                    name,
		consts.FieldMountAccessor: mountAccessor,
		"canonical_id":            canonicalID,
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing IdentityGroupAlias to %q: %s", name, err)
	}
	log.Printf("[DEBUG] Wrote IdentityGroupAlias %q", name)
	d.SetId(resp.Data["id"].(string))

	return identityGroupAliasRead(d, meta)
}

func identityGroupAliasUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroupAlias %q", id)
	path := identityGroupAliasIDPath(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupAlias %q: %s", id, err)
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

	_, err = client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityGroupAlias %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupAlias %q", id)

	return identityGroupAliasRead(d, meta)
}

func identityGroupAliasRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	path := identityGroupAliasIDPath(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Reading IdentityGroupAlias %s from %q", id, path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading IdentityGroupAlias %q: %s", id, err)
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
			return fmt.Errorf("error setting state key \"%s\" on IdentityGroupAlias %q: %s", k, id, err)
		}
	}
	return nil
}

func identityGroupAliasDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	path := identityGroupAliasIDPath(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Deleting IdentityGroupAlias %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityGroupAlias %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityGroupAlias %q", id)

	return nil
}

func identityGroupAliasExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	id := d.Id()

	path := identityGroupAliasIDPath(id)
	key := id

	// use the name if no ID is set
	if len(id) == 0 {
		key = d.Get("name").(string)
		path = identityGroupAliasNamePath(key)
	}

	log.Printf("[DEBUG] Checking if IdentityGroupAlias %q exists", key)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityGroupAlias %q exists: %s", key, err)
	}
	log.Printf("[DEBUG] Checked if IdentityGroupAlias %q exists", key)

	return resp != nil, nil
}

func identityGroupAliasNamePath(name string) string {
	return fmt.Sprintf("%s/name/%s", identityGroupAliasPath, name)
}

func identityGroupAliasIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", identityGroupAliasPath, id)
}
