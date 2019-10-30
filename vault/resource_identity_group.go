package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

const identityGroupPath = "/identity/group"

func identityGroupResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupCreate,
		Update: identityGroupUpdate,
		Read:   identityGroupRead,
		Delete: identityGroupDelete,
		Exists: identityGroupExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the group.",
				Optional:    true,
				Computed:    true,
			},

			"type": {
				Type:        schema.TypeString,
				Description: "Type of the group, internal or external. Defaults to internal.",
				ForceNew:    true,
				Optional:    true,
				Default:     "internal",
			},

			"metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Metadata to be associated with the group.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"policies": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies to be tied to the group.",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return d.Get("external_policies").(bool)
				},
			},

			"external_policies": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage policies externally through `vault_identity_group_policies`, allows using group ID in assigned policies.",
			},

			"member_group_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Group IDs to be assigned as group members.",
			},

			"member_entity_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Entity IDs to be assigned as group members.",
				// Suppress the diff if group type is "external" because we cannot manage
				// group members
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if d.Get("type").(string) == "external" {
						return true
					}
					return false
				},
			},
		},
	}
}

func identityGroupUpdateFields(d *schema.ResourceData, data map[string]interface{}) error {
	if name, ok := d.GetOk("name"); ok {
		data["name"] = name
	}

	if externalPolicies, ok := d.GetOk("external_policies"); !(ok && externalPolicies.(bool)) {
		if policies, ok := d.GetOk("policies"); ok {
			data["policies"] = policies.(*schema.Set).List()
		}
	}

	if memberEntityIDs, ok := d.GetOk("member_entity_ids"); ok && d.Get("type").(string) == "internal" {
		data["member_entity_ids"] = memberEntityIDs.(*schema.Set).List()
	}

	if memberGroupIDs, ok := d.GetOk("member_group_ids"); ok {
		data["member_group_ids"] = memberGroupIDs.(*schema.Set).List()
	}

	if metadata, ok := d.GetOk("metadata"); ok {
		data["metadata"] = metadata
	}

	return nil
}

func identityGroupCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	typeValue := d.Get("type").(string)

	path := identityGroupPath

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := map[string]interface{}{
		"name": name,
		"type": typeValue,
	}

	if err := identityGroupUpdateFields(d, data); err != nil {
		return fmt.Errorf("error writing IdentityGroup to %q: %s", name, err)
	}

	resp, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityGroup to %q: %s", name, err)
	}
	log.Printf("[DEBUG] Wrote IdentityGroup %q", name)

	d.SetId(resp.Data["id"].(string))

	return identityGroupRead(d, meta)
}

func identityGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroup %q", id)
	path := identityGroupIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := map[string]interface{}{}

	if err := identityGroupUpdateFields(d, data); err != nil {
		return fmt.Errorf("error updating IdentityGroup %q: %s", id, err)
	}

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityGroup %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroup %q", id)

	return identityGroupRead(d, meta)
}

func identityGroupRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading IdentityGroup %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read IdentityGroup %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroup %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	readFields := []string{"name", "type", "metadata", "member_entity_ids", "member_group_ids", "policies"}

	for _, k := range readFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityGroup %q: %s", k, id, err)
		}
	}
	return nil
}

func identityGroupDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityGroupIDPath(id)

	log.Printf("[DEBUG] Deleting IdentityGroup %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityGroup %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityGroup %q", id)

	return nil
}

func identityGroupExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	id := d.Id()
	key := id

	if len(id) == 0 {
		return false, nil
	} else {
		key = d.Get("name").(string)
	}

	log.Printf("[DEBUG] Checking if IdentityGroup %q exists", key)
	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityGroup %q exists: %s", key, err)
	}
	log.Printf("[DEBUG] Checked if IdentityGroup %q exists", key)
	return resp != nil, nil
}

func identityGroupIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", identityGroupPath, id)
}

func readIdentityGroupPolicies(client *api.Client, groupID string) ([]interface{}, error) {
	resp, err := readIdentityGroup(client, groupID)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("error IdentityGroup %s does not exist", groupID)
	}

	if v, ok := resp.Data["policies"]; ok && v != nil {
		return v.([]interface{}), nil
	}
	return make([]interface{}, 0), nil
}

// This function may return `nil` for the IdentityGroup if it does not exist
func readIdentityGroup(client *api.Client, groupID string) (*api.Secret, error) {
	path := identityGroupIDPath(groupID)
	log.Printf("[DEBUG] Reading IdentityGroup %s from %q", groupID, path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return resp, fmt.Errorf("failed reading IdentityGroup %s from %s", groupID, path)
	}
	return resp, nil
}
