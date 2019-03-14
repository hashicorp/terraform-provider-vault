package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
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

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the group.",
				ForceNew:    true,
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
	if policies, ok := d.GetOk("policies"); ok {
		data["policies"] = policies.(*schema.Set).List()
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

	d.Set("id", resp.Data["id"])

	d.SetId(resp.Data["id"].(string))

	return identityGroupRead(d, meta)
}

func identityGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroup %q", id)
	path := identityGroupIDPath(id)

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

	path := identityGroupIDPath(id)

	log.Printf("[DEBUG] Reading IdentityGroup %s from %q", id, path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading AppRole auth backend role SecretID %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read IdentityGroup %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroup %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"name", "type", "metadata", "policies", "member_entity_ids", "member_group_ids"} {
		if v, ok := resp.Data[k]; ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for Identity Group %q: %q", k, path, err)
			}
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

	path := identityGroupIDPath(id)
	key := id

	// use the name if no ID is set
	if len(id) == 0 {
		key = d.Get("name").(string)
		path = identityGroupNamePath(key)
	}

	log.Printf("[DEBUG] Checking if IdentityGroup %q exists", key)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityGroup %q exists: %s", key, err)
	}
	log.Printf("[DEBUG] Checked if IdentityGroup %q exists", key)

	return resp != nil, nil
}

func identityGroupNamePath(name string) string {
	return fmt.Sprintf("%s/name/%s", identityGroupPath, name)
}

func identityGroupIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", identityGroupPath, id)
}
