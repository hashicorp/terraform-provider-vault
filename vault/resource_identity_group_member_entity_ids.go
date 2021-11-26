package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func identityGroupMemberEntityIdsResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupMemberEntityIdsUpdate,
		Update: identityGroupMemberEntityIdsUpdate,
		Read:   identityGroupMemberEntityIdsRead,
		Delete: identityGroupMemberEntityIdsDelete,

		Schema: map[string]*schema.Schema{
			"member_entity_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Entity IDs to be assigned as group members.",
			},

			"exclusive": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Should the resource manage member entity ids exclusively? Beware of race conditions when disabling exclusive management",
			},

			"group_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the group.",
			},

			"group_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the group.",
			},
		},
	}
}

func identityGroupMemberEntityIdsUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Get("group_id").(string)

	log.Printf("[DEBUG] Updating IdentityGroupMemberEntityIds %q", id)
	path := identityGroupIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := make(map[string]interface{})
	memberEntityIds := d.Get("member_entity_ids").(*schema.Set).List()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return err
	}

	t, ok := resp.Data["type"]
	if ok && t != "external" {
		if d.Get("exclusive").(bool) {
			data["member_entity_ids"] = memberEntityIds
		} else {
			apiMemberEntityIds, err := readIdentityGroupMemberEntityIds(client, id)
			if err != nil {
				return err
			}
			if d.HasChange("member_entity_ids") {
				oldMemberEntityIdsI, _ := d.GetChange("member_entity_ids")
				oldMemberEntityIds := oldMemberEntityIdsI.(*schema.Set).List()
				for _, memberEntityId := range oldMemberEntityIds {
					apiMemberEntityIds = util.SliceRemoveIfPresent(apiMemberEntityIds, memberEntityId)
				}
			}
			for _, memberEntityId := range memberEntityIds {
				apiMemberEntityIds = util.SliceAppendIfMissing(apiMemberEntityIds, memberEntityId)
			}
			data["member_entity_ids"] = apiMemberEntityIds
		}
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupMemberEntityIds %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupMemberEntityIds %q", id)

	d.SetId(id)

	return identityGroupMemberEntityIdsRead(d, meta)
}

func identityGroupMemberEntityIdsRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG] Read IdentityGroupMemberEntityIds %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroupMemberEntityIds %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	d.Set("group_id", id)
	d.Set("group_name", resp.Data["name"])

	if d.Get("exclusive").(bool) {
		respdata := resp.Data["member_entity_ids"]
		if err = d.Set("member_entity_ids", respdata); err != nil {
			return fmt.Errorf("error setting member entity ids for IdentityGroupMemberEntityIds %q: %s", id, err)
		}
	} else {
		userMemberEntityIds := d.Get("member_entity_ids").(*schema.Set).List()
		newMemberEntityIds := make([]string, 0)
		apiMemberEntityIds := resp.Data["member_entity_ids"].([]interface{})

		for _, memberEntityId := range userMemberEntityIds {
			if found, _ := util.SliceHasElement(apiMemberEntityIds, memberEntityId); found {
				newMemberEntityIds = append(newMemberEntityIds, memberEntityId.(string))
			}
		}
		if err = d.Set("member_entity_ids", newMemberEntityIds); err != nil {
			return fmt.Errorf("error setting member entity ids for IdentityGroupMemberEntityIds %q: %s", id, err)
		}
	}
	return nil
}

func identityGroupMemberEntityIdsDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Get("group_id").(string)

	log.Printf("[DEBUG] Deleting IdentityGroupMemberEntityIds %q", id)
	path := identityGroupIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := make(map[string]interface{})

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return err
	}

	t, ok := resp.Data["type"]
	if ok && t != "external" {
		if d.Get("exclusive").(bool) {
			data["member_entity_ids"] = make([]string, 0)
		} else {
			apiMemberEntityIds, err := readIdentityGroupMemberEntityIds(client, id)
			if err != nil {
				return err
			}
			for _, memberEntityId := range d.Get("member_entity_ids").(*schema.Set).List() {
				apiMemberEntityIds = util.SliceRemoveIfPresent(apiMemberEntityIds, memberEntityId)
			}
			data["member_entity_ids"] = apiMemberEntityIds
		}
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupMemberEntityIds %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupMemberEntityIds %q", id)

	return nil
}
