package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func identityGroupPoliciesResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupPoliciesUpdate,
		Update: identityGroupPoliciesUpdate,
		Read:   identityGroupPoliciesRead,
		Delete: identityGroupPoliciesDelete,

		Schema: map[string]*schema.Schema{
			"policies": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies to be tied to the group.",
			},

			"exclusive": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Should the resource manage policies exclusively? Beware of race conditions when disabling exclusive management",
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

func identityGroupPoliciesUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Get("group_id").(string)

	log.Printf("[DEBUG] Updating IdentityGroupPolicies %q", id)
	path := identityGroupIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := make(map[string]interface{})
	policies := d.Get("policies").(*schema.Set).List()

	if d.Get("exclusive").(bool) {
		data["policies"] = policies
	} else {
		apiPolicies, err := readIdentityGroupPolicies(client, id)
		if err != nil {
			return err
		}
		for _, policy := range policies {
			apiPolicies = util.SliceAppendIfMissing(apiPolicies, policy)
		}
		data["policies"] = apiPolicies
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicies %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupPolicies %q", id)

	d.SetId(id)

	return identityGroupPoliciesRead(d, meta)
}

func identityGroupPoliciesRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG] Read IdentityGroupPolicies %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroupPolicies %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	d.Set("group_id", id)
	d.Set("group_name", resp.Data["name"])

	if d.Get("exclusive").(bool) {
		if err = d.Set("policies", resp.Data["policies"]); err != nil {
			return fmt.Errorf("error setting policies for IdentityGroupPolicies %q: %s", id, err)
		}
	} else {
		userPolicies := d.Get("policies").(*schema.Set).List()
		newPolicies := make([]string, 0)
		apiPolicies := resp.Data["policies"].([]interface{})

		for _, policy := range userPolicies {
			if found, _ := util.SliceHasElement(apiPolicies, policy); found {
				newPolicies = append(newPolicies, policy.(string))
			}
		}
		if err = d.Set("policies", newPolicies); err != nil {
			return fmt.Errorf("error setting policies for IdentityGroupPolicies %q: %s", id, err)
		}
	}
	return nil
}

func identityGroupPoliciesDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Get("group_id").(string)

	log.Printf("[DEBUG] Deleting IdentityGroupPolicies %q", id)
	path := identityGroupIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := make(map[string]interface{})

	if d.Get("exclusive").(bool) {
		data["policies"] = make([]string, 0)
	} else {
		apiPolicies, err := readIdentityGroupPolicies(client, id)
		if err != nil {
			return err
		}
		for _, policy := range d.Get("policies").(*schema.Set).List() {
			apiPolicies = util.SliceRemoveIfPresent(apiPolicies, policy)
		}
		data["policies"] = apiPolicies
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicies %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupPolicies %q", id)

	return nil
}
