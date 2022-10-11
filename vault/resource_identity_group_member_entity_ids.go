package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func identityGroupMemberEntityIdsResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupMemberEntityIdsUpdate,
		Update: identityGroupMemberEntityIdsUpdate,
		Read:   ReadWrapper(identityGroupMemberEntityIdsRead),
		Delete: identityGroupMemberEntityIdsDelete,

		Schema: map[string]*schema.Schema{
			consts.FieldMemberEntityIDs: {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Entity IDs to be assigned as group members.",
			},
			consts.FieldExclusive: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				Description: `Should the resource manage member entity ids 
exclusively? Beware of race conditions when disabling exclusive management`,
			},
			consts.FieldGroupID: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the group.",
			},
			consts.FieldGroupName: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the group.",
				Deprecated: `The value for group_name may not always be accurate, 
use "data.vault_identity_group.*.group_name", "vault_identity_group.*.group_name" instead`,
			},
		},
	}
}

func identityGroupMemberEntityIdsUpdate(d *schema.ResourceData, meta interface{}) error {
	gid := d.Get(consts.FieldGroupID).(string)
	path := identityGroupIDPath(gid)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	log.Printf("[DEBUG] Updating IdentityGroupMemberEntityIds %q", gid)

	if d.HasChange(consts.FieldGroupID) {
		o, n := d.GetChange(consts.FieldGroupID)
		log.Printf("[DEBUG] Group ID has changed old=%q, new=%q", o, n)
	}
	resp, err := readIdentityGroup(client, gid, d.IsNewResource())
	if err != nil {
		return err
	}

	data, err := group.GetGroupMember(d, resp, consts.FieldMemberEntityIDs)
	if err != nil {
		return err
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupMemberEntityIds %q: %s", gid, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupMemberEntityIds %q", gid)

	d.SetId(gid)

	return identityGroupMemberEntityIdsRead(d, meta)
}

func identityGroupMemberEntityIdsRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Read IdentityGroupMemberEntityIds %s", id)
	resp, err := readIdentityGroup(client, id, d.IsNewResource())
	if err != nil {
		if isIdentityNotFoundError(err) {
			log.Printf("[WARN] IdentityGroupMemberEntityIds %q not found, removing from state", id)
			d.SetId("")
			return nil
		}
		return err
	}

	if err := d.Set(consts.FieldGroupID, id); err != nil {
		return err
	}
	if err := d.Set(consts.FieldGroupName, resp.Data["name"]); err != nil {
		return err
	}

	if err := group.SetGroupMember(d, resp, consts.FieldMemberEntityIDs); err != nil {
		return err
	}

	return nil
}

func identityGroupMemberEntityIdsDelete(d *schema.ResourceData, meta interface{}) error {
	id := d.Get(consts.FieldGroupID).(string)
	path := identityGroupIDPath(id)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	log.Printf("[DEBUG] Deleting IdentityGroupMemberEntityIds %q", id)

	resp, err := readIdentityGroup(client, id, false)
	if err != nil {
		if isIdentityNotFoundError(err) {
			return nil
		}
		return err
	}

	data, err := group.DeleteGroupMember(d, resp, consts.FieldMemberEntityIDs)
	if err != nil {
		return err
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupMemberEntityIds %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupMemberEntityIds %q", id)

	return nil
}
