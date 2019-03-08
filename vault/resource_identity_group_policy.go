package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func identityGroupPolicyResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupPolicyCreate,
		Update: identityGroupPolicyUpdate,
		Read:   identityGroupPolicyRead,
		Delete: identityGroupPolicyDelete,
		Exists: identityGroupPolicyExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"policy": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Policy to be attached to a group.",
			},

			"group_policies": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies that are present on a group",
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

func identityGroupPoliciesDetermineNew(presentPolicies, oldStatePolicies, newStatePolicies []interface{}) []string {
	policies := schema.NewSet(schema.HashString, presentPolicies)

	for _, policy := range oldStatePolicies {
		policies.Remove(policy)
	}
	for _, policy := range newStatePolicies {
		policies.Add(policy)
	}

	var ret []string
	for _, policy := range policies.List() {
		ret = append(ret, policy.(string))
	}
	return ret
}

func identityGroupPolicyUpdateFields(d *schema.ResourceData, data map[string]interface{}, presentPolicies []interface{}) error {
	o, n := d.GetChange("policy")
	data["policies"] = identityGroupPoliciesDetermineNew(presentPolicies, []interface{}{o}, []interface{}{n})
	return nil
}

func identityGroupPolicyCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	groupId := d.Get("group_id").(string)

	path := identityGroupPath

	data := map[string]interface{}{
		"id": groupId,
	}

	if err := identityGroupPolicyUpdateFields(d, data, []interface{}{}); err != nil {
		return fmt.Errorf("error writing IdentityGroupPolicy to %q: %s", groupId, err)
	}

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityGroupPolicy to %q: %s", groupId, err)
	}
	log.Printf("[DEBUG] Wrote IdentityGroupPolicy %q", groupId)

	d.SetId(d.Get("group_id").(string))

	return identityGroupPolicyRead(d, meta)
}

func identityGroupPolicyUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroupPolicy %q", id)
	path := identityGroupIDPath(id)

	data := map[string]interface{}{}

	presentPolicies, err := readIdentityGroupPolicies(client, id)
	if err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicy %q - %s: %s", id, d.Get("policy"), err)
	}

	if err := identityGroupPolicyUpdateFields(d, data, presentPolicies); err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicy %q: %s", id, err)
	}

	_, err = client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityGroupPolicy %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroupPolicy %q", id)

	return identityGroupPolicyRead(d, meta)
}

func identityGroupPolicyRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading IdentityGroupPolicy %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read IdentityGroupPolicy %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroupPolicy %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	for responseKey, stateKey := range map[string]string{
		"policies": "group_policies",
		"id":       "group_id",
		"name":     "group_name",
	} {
		if err := d.Set(stateKey, resp.Data[responseKey]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityGroupPolicy %q: %s", stateKey, id, err)
		}
	}
	return nil
}

func identityGroupPolicyDelete(d *schema.ResourceData, meta interface{}) error {
	if err := d.Set("policy", ""); err != nil {
		return fmt.Errorf("failed setting policy to empty string: %s", err)
	}
	return identityGroupPolicyUpdate(d, meta)
}

func identityGroupPolicyExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityGroupPolicy %q exists: %s", id, err)
	}
	log.Printf("[DEBUG] Checked if IdentityGroupPolicy %q exists", id)

	return resp != nil, nil
}
