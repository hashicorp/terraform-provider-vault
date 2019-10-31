package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func identityEntityPoliciesResource() *schema.Resource {
	return &schema.Resource{
		Create: identityEntityPoliciesUpdate,
		Update: identityEntityPoliciesUpdate,
		Read:   identityEntityPoliciesRead,
		Delete: identityEntityPoliciesDelete,

		Schema: map[string]*schema.Schema{
			"policies": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies to be tied to the entity.",
			},

			"exclusive": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Should the resource manage policies exclusively",
			},

			"entity_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the entity.",
			},

			"entity_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the entity.",
			},
		},
	}
}

func identityEntityPoliciesUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Get("entity_id").(string)

	log.Printf("[DEBUG] Updating IdentityEntityPolicies %q", id)
	path := identityEntityIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := make(map[string]interface{})
	policies := d.Get("policies").(*schema.Set).List()

	if d.Get("exclusive").(bool) {
		data["policies"] = policies
	} else {
		apiPolicies, err := readIdentityEntityPolicies(client, id)
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
		return fmt.Errorf("error updating IdentityEntityPolicies %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityEntityPolicies %q", id)

	d.SetId(id)

	return identityEntityPoliciesRead(d, meta)
}

func identityEntityPoliciesRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityEntity(client, id)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG] Read IdentityEntityPolicies %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityEntityPolicies %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	d.Set("entity_id", id)
	d.Set("entity_name", resp.Data["name"])

	if d.Get("exclusive").(bool) {
		if err = d.Set("policies", resp.Data["policies"]); err != nil {
			return fmt.Errorf("error setting policies for IdentityEntityPolicies %q: %s", id, err)
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
			return fmt.Errorf("error setting policies for IdentityEntityPolicies %q: %s", id, err)
		}
	}
	return nil
}

func identityEntityPoliciesDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Get("entity_id").(string)

	log.Printf("[DEBUG] Deleting IdentityEntityPolicies %q", id)
	path := identityEntityIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := make(map[string]interface{})

	if d.Get("exclusive").(bool) {
		data["policies"] = make([]string, 0)
	} else {
		apiPolicies, err := readIdentityEntityPolicies(client, id)
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
		return fmt.Errorf("error updating IdentityEntityPolicies %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityEntityPolicies %q", id)

	return nil
}
