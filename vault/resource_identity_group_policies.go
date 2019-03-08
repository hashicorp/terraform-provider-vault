package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func identityGroupPoliciesResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupPoliciesCreate,
		Update: identityGroupPoliciesUpdate,
		Read:   identityGroupPoliciesRead,
		Delete: identityGroupPoliciesDelete,
		Exists: identityGroupPoliciesExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

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
				Default:     false,
				Description: "Should the resource manage policies exclusively?",
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
func identityGroupPoliciesUpdateFields(d *schema.ResourceData, data map[string]interface{}, presentPolicies []interface{}) error {
	o, n := d.GetChange("policies")
	if d.Get("exclusive").(bool) {
		data["policies"] = n.(*schema.Set).List()
	} else {
		data["policies"] = identityGroupPoliciesDetermineNew(presentPolicies, o.(*schema.Set).List(), n.(*schema.Set).List())
	}
	return nil
}

func identityGroupPoliciesCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	groupId := d.Get("group_id").(string)

	path := identityGroupPath

	data := map[string]interface{}{
		"id": groupId,
	}

	if err := identityGroupPoliciesUpdateFields(d, data, []interface{}{}); err != nil {
		return fmt.Errorf("error writing IdentityGroupPolicies to %q: %s", groupId, err)
	}

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityGroupPolicies to %q: %s", groupId, err)
	}
	log.Printf("[DEBUG] Wrote IdentityGroupPolicies %q", groupId)

	d.SetId(d.Get("group_id").(string))

	return identityGroupPoliciesRead(d, meta)
}

func identityGroupPoliciesUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroupPolicies %q", id)
	path := identityGroupIDPath(id)

	presentPolicies, err := readIdentityGroupPolicies(client, id)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicies %q - %s: %s", id, d.Get("policies"), err)
	}

	data := map[string]interface{}{}

	if err := identityGroupPoliciesUpdateFields(d, data, presentPolicies); err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicies %q: %s", id, err)
	}

	_, err = client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicies %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupPolicies %q", id)

	return identityGroupPoliciesRead(d, meta)
}

func identityGroupPoliciesRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading IdentityGroupPolicies %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read IdentityGroupPolicies %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroupPolicies %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	for responseKey, stateKey := range map[string]string{
		"policies": "policies",
		"id":       "group_id",
		"name":     "group_name",
	} {
		if err := d.Set(stateKey, resp.Data[responseKey]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityGroupPolicies %q: %s", stateKey, id, err)
		}
	}
	return nil
}

func identityGroupPoliciesDelete(d *schema.ResourceData, meta interface{}) error {
	if err := d.Set("policies", []string{}); err != nil {
		return fmt.Errorf("failed setting policy to empty set: %s", err)
	}
	return identityGroupPoliciesUpdate(d, meta)
}

func identityGroupPoliciesExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityGroupPolicies %q exists: %s", id, err)
	}
	log.Printf("[DEBUG] Checked if IdentityGroupPolicies %q exists", id)

	return resp != nil, nil
}
