package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func identityGroupMemberGroupIdsResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupMemberGroupIdsUpdate,
		Update: identityGroupMemberGroupIdsUpdate,
		Read:   ReadWrapper(identityGroupMemberGroupIdsRead),
		Delete: identityGroupMemberGroupIdsDelete,

		Schema: map[string]*schema.Schema{
			"member_group_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Group IDs to be assigned as group members.",
			},
			"exclusive": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				Description: `Should the resource manage member group ids
exclusively? Beware of race conditions when disabling exclusive management`,
			},
			"group_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the group.",
			},
		},
	}
}

func identityGroupMemberGroupIdsUpdate(d *schema.ResourceData, meta interface{}) error {
	gid := d.Get("group_id").(string)
	path := identityGroupIDPath(gid)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	log.Printf("[DEBUG] Updating IdentityGroupMemberGroupIds %q", gid)

	if d.HasChange("group_id") {
		o, n := d.GetChange("group_id")
		log.Printf("[DEBUG] Group ID has changed old=%q, new=%q", o, n)
	}

	resp, err := readIdentityGroup(client, gid, d.IsNewResource())
	if err != nil {
		return err
	}

	data, err := group.GetGroupMember(d, resp, "member_group_ids")
	if err != nil {
		return err
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupMemberGroupIds %q: %s", gid, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupMemberGroupIds %q", gid)

	d.SetId(gid)

	return identityGroupMemberGroupIdsRead(d, meta)
}

func identityGroupMemberGroupIdsRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Read IdentityGroupMemberGroupIds %s", id)
	resp, err := readIdentityGroup(client, id, d.IsNewResource())
	if err != nil {
		if isIdentityNotFoundError(err) {
			log.Printf("[WARN] IdentityGroupMemberGroupIds %q not found, removing from state", id)
			d.SetId("")
			return nil
		}
		return err
	}

	if err := d.Set("group_id", id); err != nil {
		return err
	}

	if err := group.SetGroupMember(d, resp, "member_group_ids"); err != nil {
		return err
	}

	return nil
}

func identityGroupMemberGroupIdsDelete(d *schema.ResourceData, meta interface{}) error {
	id := d.Get("group_id").(string)
	path := identityGroupIDPath(id)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	log.Printf("[DEBUG] Deleting IdentityGroupMemberGroupIds %q", id)

	resp, err := readIdentityGroup(client, id, false)
	if err != nil {
		if isIdentityNotFoundError(err) {
			return nil
		}
		return err
	}

	data, err := group.DeleteGroupMember(d, resp, "member_group_ids")
	if err != nil {
		return err
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupMemberGroupIds %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupMemberGroupIds %q", id)

	return nil
}
