package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityGroupAliasPath = "/identity/group-alias"

func identityGroupAliasResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupAliasCreate,
		Update: identityGroupAliasUpdate,
		Read:   identityGroupAliasRead,
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
				ForceNew:    true,
			},

			"mount_accessor": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Mount accessor to which this alias belongs to.",
			},

			"canonical_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the group to which this is an alias.",
			},

			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the group alias.",
			},
		},
	}
}

func identityGroupAliasCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	mountAccessor := d.Get("mount_accessor").(string)
	canonicalID := d.Get("canonical_id").(string)

	path := identityGroupAliasPath

	data := map[string]interface{}{
		"name":           name,
		"mount_accessor": mountAccessor,
		"canonical_id":   canonicalID,
	}

	resp, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityGroupAlias to %q: %s", name, err)
	}
	log.Printf("[DEBUG] Wrote IdentityGroupAlias %q", name)

	d.Set("id", resp.Data["id"])

	d.SetId(resp.Data["id"].(string))

	return identityGroupAliasRead(d, meta)
}

func identityGroupAliasUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroupAlias %q", id)
	path := identityGroupAliasIDPath(id)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupAlias %q: %s", id, err)
	}

	data := map[string]interface{}{
		"name":           resp.Data["name"],
		"mount_accessor": resp.Data["mount_accessor"],
		"canonical_id":   resp.Data["canonical_id"],
	}

	if mountAccessor, ok := d.GetOk("mount_accessor"); ok {
		data["mount_accessor"] = mountAccessor
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
	client := meta.(*api.Client)
	id := d.Id()

	path := identityGroupAliasIDPath(id)

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

	for _, k := range []string{"id", "name", "mount_accessor", "canonical_id"} {
		d.Set(k, resp.Data[k])
	}
	return nil
}

func identityGroupAliasDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityGroupAliasIDPath(id)

	log.Printf("[DEBUG] Deleting IdentityGroupAlias %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityGroupAlias %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityGroupAlias %q", id)

	return nil
}

func identityGroupAliasExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
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
