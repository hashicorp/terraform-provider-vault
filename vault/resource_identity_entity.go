package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

const identityEntityPath = "/identity/entity"

func identityEntityResource() *schema.Resource {
	return &schema.Resource{
		Create: identityEntityCreate,
		Update: identityEntityUpdate,
		Read:   identityEntityRead,
		Delete: identityEntityDelete,
		Exists: identityEntityExists,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the entity.",
				ForceNew:    true,
			},

			"metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Metadata to be associated with the entity.",
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
				Description: "Policies to be tied to the entity.",
			},

			"disabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether the entity is disabled. Disabled entities' associated tokens cannot be used, but are not revoked.",
			},
		},
	}
}

func identityEntityUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if name, ok := d.GetOk("name"); ok {
		data["name"] = name
	}

	if policies, ok := d.GetOk("policies"); ok {
		data["policies"] = policies.(*schema.Set).List()
	}

	if metadata, ok := d.GetOk("metadata"); ok {
		data["metadata"] = metadata
	}

	if disabled, ok := d.GetOk("disabled"); ok {
		data["disabled"] = disabled
	}
}

func identityEntityCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	path := identityEntityPath

	data := map[string]interface{}{
		"name": name,
	}

	identityEntityUpdateFields(d, data)

	resp, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityEntity to %q: %s", name, err)
	}
	log.Printf("[DEBUG] Wrote IdentityEntity %q", name)

	d.Set("id", resp.Data["id"])

	d.SetId(resp.Data["id"].(string))

	return identityEntityRead(d, meta)
}

func identityEntityUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityEntity %q", id)
	path := identityEntityIDPath(id)

	data := map[string]interface{}{}

	identityEntityUpdateFields(d, data)

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityEntity %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityEntity %q", id)

	return identityEntityRead(d, meta)
}

func identityEntityRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityEntityIDPath(id)

	log.Printf("[DEBUG] Reading IdentityEntity %s from %q", id, path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading IdentityEntity %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read IdentityEntity %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityEntity %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"name", "metadata", "disabled", "policies"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error reading %s of IdentityEntity %q: %q", k, path, err)
		}
	}
	return nil
}

func identityEntityDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityEntityIDPath(id)

	log.Printf("[DEBUG] Deleting IdentityEntitty %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityEntity %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityEntity %q", id)

	return nil
}

func identityEntityExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityEntityIDPath(id)
	key := id

	// use the name if no ID is set
	if len(id) == 0 {
		key = d.Get("name").(string)
		path = identityEntityNamePath(key)
	}

	log.Printf("[DEBUG] Checking if IdentityEntity %q exists", key)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityEntity %q exists: %s", key, err)
	}
	log.Printf("[DEBUG] Checked if IdentityEntity %q exists", key)

	return resp != nil, nil
}

func identityEntityNamePath(name string) string {
	return fmt.Sprintf("%s/name/%s", identityEntityPath, name)
}

func identityEntityIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", identityEntityPath, id)
}
