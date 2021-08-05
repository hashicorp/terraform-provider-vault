package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				Description: `Should the resource manage member entity ids 
exclusively? Beware of race conditions when disabling exclusive management`,
			},
			"group_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "ID of the group.",
			},
			"group_name": {
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
	gid := d.Get("group_id").(string)
	path := identityGroupIDPath(gid)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client := meta.(*api.Client)

	log.Printf("[DEBUG] Updating IdentityGroupMemberEntityIds %q", gid)

	if d.HasChange("group_id") {
		o, n := d.GetChange("group_id")
		log.Printf("[DEBUG] Group ID has changed old=%q, new=%q", o, n)
	}
	data := make(map[string]interface{})
	resp, err := readIdentityGroup(client, gid, d.IsNewResource())
	if err != nil {
		return err
	}

	var curIDS []interface{}
	if t, ok := resp.Data["type"]; ok && t.(string) != "external" {
		if v, ok := resp.Data["member_entity_ids"]; ok {
			curIDS = v.([]interface{})
		}

		if d.Get("exclusive").(bool) || len(curIDS) == 0 {
			data["member_entity_ids"] = d.Get("member_entity_ids").(*schema.Set).List()
		} else {
			set := map[interface{}]bool{}
			for _, v := range curIDS {
				set[v] = true
			}

			o, _ := d.GetChange("member_entity_ids")
			if !d.IsNewResource() && o != nil {
				// set.delete()
				for _, i := range o.(*schema.Set).List() {
					delete(set, i)
				}
			}

			if ids, ok := d.GetOk("member_entity_ids"); ok {
				for _, id := range ids.(*schema.Set).List() {
					// set.add()
					set[id] = true
				}
			}

			// set.keys()
			var result []interface{}
			for k := range set {
				result = append(result, k)
			}
			data["member_entity_ids"] = result
		}
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
	client := meta.(*api.Client)
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

	if err := d.Set("group_id", id); err != nil {
		return err
	}
	if err := d.Set("group_name", resp.Data["name"]); err != nil {
		return err
	}

	curIDS := resp.Data["member_entity_ids"]
	if d.Get("exclusive").(bool) {
		if err = d.Set("member_entity_ids", curIDS); err != nil {
			return err
		}
	} else {
		set := map[interface{}]bool{}
		if ids, ok := curIDS.([]interface{}); ok {
			for _, v := range ids {
				set[v] = true
			}
		}

		var result []interface{}
		// set.intersection()
		if i, ok := d.GetOk("member_entity_ids"); ok {
			for _, v := range i.(*schema.Set).List() {
				if _, ok := set[v]; ok {
					result = append(result, v)
				}
			}
		}
		if err = d.Set("member_entity_ids", result); err != nil {
			return err
		}
	}
	return nil
}

func identityGroupMemberEntityIdsDelete(d *schema.ResourceData, meta interface{}) error {
	id := d.Get("group_id").(string)
	path := identityGroupIDPath(id)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	client := meta.(*api.Client)

	log.Printf("[DEBUG] Deleting IdentityGroupMemberEntityIds %q", id)

	data := make(map[string]interface{})

	resp, err := readIdentityGroup(client, id, false)
	if err != nil {
		if isIdentityNotFoundError(err) {
			return nil
		}
		return err
	}

	t, ok := resp.Data["type"]
	if ok && t != "external" {
		if d.Get("exclusive").(bool) {
			data["member_entity_ids"] = make([]string, 0)
		} else {
			set := map[interface{}]bool{}
			if v, ok := resp.Data["member_entity_ids"]; ok {
				for _, id := range v.([]interface{}) {
					set[id] = true
				}
			}

			result := []interface{}{}
			if len(set) > 0 {
				if v, ok := d.GetOk("member_entity_ids"); ok {
					for _, id := range v.(*schema.Set).List() {
						delete(set, id)
					}
				}

				for k := range set {
					result = append(result, k)
				}
			}
			data["member_entity_ids"] = result
		}
	}

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupMemberEntityIds %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupMemberEntityIds %q", id)

	return nil
}
