// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func identityEntityResource() *schema.Resource {
	return &schema.Resource{
		Create: identityEntityCreate,
		Update: identityEntityUpdate,
		Read:   provider.ReadWrapper(identityEntityRead),
		Delete: identityEntityDelete,
		Exists: identityEntityExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the entity.",
				Optional:    true,
				Computed:    true,
			},

			consts.FieldMetadata: {
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
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return d.Get("external_policies").(bool)
				},
			},

			"external_policies": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage policies externally through `vault_identity_entity_policies`.",
			},

			"disabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether the entity is disabled. Disabled entities' associated tokens cannot be used, but are not revoked.",
			},
		},
	}
}

func identityEntityUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	if create {
		if name, ok := d.GetOk("name"); ok {
			data["name"] = name
		}

		if externalPolicies, ok := d.GetOk("external_policies"); !(ok && externalPolicies.(bool)) {
			if policies, ok := d.GetOk("policies"); ok {
				data["policies"] = policies.(*schema.Set).List()
			}
		}

		if metadata, ok := d.GetOk(consts.FieldMetadata); ok {
			data["metadata"] = metadata
		}

		if disabled, ok := d.GetOk("disabled"); ok {
			data["disabled"] = disabled
		}
	} else {
		if d.HasChanges("name", "external_policies", "policies", "metadata", "disabled") {
			data["name"] = d.Get("name")
			data["metadata"] = d.Get("metadata")
			data["disabled"] = d.Get("disabled")
			data["policies"] = d.Get("policies").(*schema.Set).List()

			// Edge case where if external_policies is true, no policies
			// should be configured on the entity.
			data["external_policies"] = d.Get("external_policies").(bool)
			if data["external_policies"].(bool) {
				delete(data, "policies")
			}
		}
	}
}

func identityEntityCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)

	path := entity.RootEntityPath

	data := map[string]interface{}{
		"name": name,
	}

	identityEntityUpdateFields(d, data, true)

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing IdentityEntity to %q: %s", name, err)
	}

	if resp == nil {
		path := identityEntityNamePath(name)
		entityMsg := "Unable to determine entity id."

		if entity, err := client.Logical().Read(path); err == nil {
			entityMsg = fmt.Sprintf("Entity resource ID %q may be imported.", entity.Data["id"])
		}

		return fmt.Errorf("Identity Entity %q already exists. %s", name, entityMsg)
	} else {
		log.Printf("[DEBUG] Wrote IdentityEntity %q", name)
	}

	d.SetId(resp.Data["id"].(string))

	return identityEntityRead(d, meta)
}

func identityEntityUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityEntity %q", id)
	path := entity.JoinEntityID(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	data := map[string]interface{}{}

	identityEntityUpdateFields(d, data, false)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating IdentityEntity %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityEntity %q", id)

	return identityEntityRead(d, meta)
}

func identityEntityRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Read IdentityEntity %s", id)
	resp, err := readIdentityEntity(client, id, d.IsNewResource())
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}

		if group.IsIdentityNotFoundError(err) {
			log.Printf("[WARN] IdentityEntity %q not found, removing from state", id)
			d.SetId("")
			return nil
		}
		return fmt.Errorf("error reading IdentityEntity %q: %w", id, err)
	}

	for _, k := range []string{"name", "metadata", "disabled", "policies"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityEntity %q: %s", k, id, err)
		}
	}
	return nil
}

func identityEntityDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	path := entity.JoinEntityID(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Deleting IdentityEntitty %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityEntity %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityEntity %q", id)

	return nil
}

func identityEntityExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	id := d.Id()

	path := entity.JoinEntityID(id)
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
	return fmt.Sprintf("%s/name/%s", entity.RootEntityPath, name)
}

func readIdentityEntityPolicies(client *api.Client, entityID string) ([]interface{}, error) {
	resp, err := readIdentityEntity(client, entityID, false)
	if err != nil {
		return nil, err
	}

	if v, ok := resp.Data["policies"]; ok && v != nil {
		return v.([]interface{}), nil
	}
	return make([]interface{}, 0), nil
}

func readIdentityEntity(client *api.Client, entityID string, retry bool) (*api.Secret, error) {
	path := entity.JoinEntityID(entityID)
	log.Printf("[DEBUG] Reading Entity %q from %q", entityID, path)

	return entity.ReadEntity(client, path, retry)
}
