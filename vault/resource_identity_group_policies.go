// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func identityGroupPoliciesResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupPoliciesUpdate,
		Update: identityGroupPoliciesUpdate,
		Read:   provider.ReadWrapper(identityGroupPoliciesRead),
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Get("group_id").(string)

	log.Printf("[DEBUG] Updating IdentityGroupPolicies %q", id)
	path := group.IdentityGroupIDPath(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	data := make(map[string]interface{})
	policies := d.Get("policies").(*schema.Set).List()

	if d.Get("exclusive").(bool) {
		data["policies"] = policies
	} else {
		apiPolicies, err := readIdentityGroupPolicies(client, id, d.IsNewResource())
		if err != nil {
			return err
		}
		if d.HasChange("policies") {
			oldPoliciesI, _ := d.GetChange("policies")
			oldPolicies := oldPoliciesI.(*schema.Set).List()
			for _, policy := range oldPolicies {
				apiPolicies = util.SliceRemoveIfPresent(apiPolicies, policy)
			}
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Read IdentityGroupPolicies %s", id)
	resp, err := group.ReadIdentityGroup(client, id, d.IsNewResource())
	if err != nil {
		if group.IsIdentityNotFoundError(err) {
			log.Printf("[WARN] IdentityGroupPolicies %q not found, removing from state", id)
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

	if d.Get("exclusive").(bool) {
		if err = d.Set("policies", resp.Data["policies"]); err != nil {
			return fmt.Errorf("error setting policies for IdentityGroupPolicies %q: %s", id, err)
		}
	} else {
		userPolicies := d.Get("policies").(*schema.Set).List()
		newPolicies := make([]string, 0)

		var apiPolicies []interface{}
		if val, ok := resp.Data["policies"]; ok && val != nil {
			apiPolicies = val.([]interface{})
		} else {
			apiPolicies = make([]interface{}, 0)
		}

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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Get("group_id").(string)

	log.Printf("[DEBUG] Deleting IdentityGroupPolicies %q", id)
	path := group.IdentityGroupIDPath(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	data := make(map[string]interface{})

	if d.Get("exclusive").(bool) {
		data["policies"] = make([]string, 0)
	} else {
		apiPolicies, err := readIdentityGroupPolicies(client, id, false)
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
