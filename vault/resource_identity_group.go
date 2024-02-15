// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	fieldExternalMemberGroupIDs = "external_member_group_ids"
)

func identityGroupResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupCreate,
		Update: identityGroupUpdate,
		Read:   provider.ReadWrapper(identityGroupRead),
		Delete: identityGroupDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		SchemaVersion: 1,
		StateUpgraders: []schema.StateUpgrader{
			{
				Version: 0,
				Type:    identityGroupExternalGroupIDsResourceV0().CoreConfigSchema().ImpliedType(),
				Upgrade: identityGroupExternalGroupIDsUpgradeV0,
			},
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
			consts.FieldMetadata: {
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
				// Suppress the diff if group type is "external" because we cannot manage
				// group members
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if d.Get("type").(string) == "external" || d.Get(fieldExternalMemberGroupIDs).(bool) == true {
						return true
					}
					return false
				},
			},
			"member_entity_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Entity IDs to be assigned as group members.",
				// Suppress the diff if group type is "external" because we cannot manage
				// group members
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if d.Get("type").(string) == "external" || d.Get("external_member_entity_ids").(bool) == true {
						return true
					}
					return false
				},
			},

			"external_member_entity_ids": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage member entities externally through `vault_identity_group_member_entity_ids`",
			},

			fieldExternalMemberGroupIDs: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage member groups externally through `vault_identity_group_member_group_ids`",
			},
		},
	}
}

func identityGroupUpdateFields(d *schema.ResourceData, meta interface{}, data map[string]interface{}) error {
	if d.IsNewResource() {
		if name, ok := d.GetOk("name"); ok {
			data["name"] = name
		}

		if externalPolicies, ok := d.GetOk("external_policies"); !(ok && externalPolicies.(bool)) {
			data["policies"] = d.Get("policies").(*schema.Set).List()
		}

		// Member groups and entities can't be set for external groups
		if d.Get("type").(string) == "internal" {
			if externalMemberEntityIds, ok := d.GetOk("external_member_entity_ids"); !(ok && externalMemberEntityIds.(bool)) {
				data["member_entity_ids"] = d.Get("member_entity_ids").(*schema.Set).List()
			}

			externalMemberGroupIds := d.Get(fieldExternalMemberGroupIDs)
			if !externalMemberGroupIds.(bool) {
				data["member_group_ids"] = d.Get("member_group_ids").(*schema.Set).List()
			}
		}

		if metadata, ok := d.GetOk(consts.FieldMetadata); ok {
			data["metadata"] = metadata
		}
	} else {
		if d.HasChanges("name", "external_policies", "policies", "metadata", "member_entity_ids", "member_group_ids") {
			data["name"] = d.Get("name")
			data["metadata"] = d.Get(consts.FieldMetadata)
			data["policies"] = d.Get("policies").(*schema.Set).List()
			// Member groups and entities can't be set for external groups
			if d.Get("type").(string) == "internal" {
				if !d.Get("external_member_entity_ids").(bool) {
					data["member_entity_ids"] = d.Get("member_entity_ids").(*schema.Set).List()
				}

				if !d.Get(fieldExternalMemberGroupIDs).(bool) {
					data["member_group_ids"] = d.Get("member_group_ids").(*schema.Set).List()
				}
			}
			// Edge case where if external_policies is true, we will set policies to whatever that is
			// already configured on the group to prevent removal
			data["external_policies"] = d.Get("external_policies").(bool)
			if data["external_policies"].(bool) {
				client, e := provider.GetClient(d, meta)
				if e != nil {
					return e
				}
				id := d.Id()
				apiPolicies, err := readIdentityGroupPolicies(client, id, false)
				if err != nil {
					return err
				}
				data["policies"] = apiPolicies
			}
		}
	}

	return nil
}

func identityGroupCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	name := d.Get("name").(string)
	typeValue := d.Get("type").(string)

	path := group.IdentityGroupPath

	data := map[string]interface{}{
		"type": typeValue,
	}

	if err := identityGroupUpdateFields(d, meta, data); err != nil {
		return fmt.Errorf("error writing IdentityGroup to %q: %s", name, err)
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing IdentityGroup to %q: %s", name, err)
	}

	if resp == nil {
		path := identityGroupNamePath(name)
		resp, err := client.Logical().Read(path)
		if err == nil {
			err = errors.New("unknown")
			if resp != nil {
				err = fmt.Errorf(
					"group already exists with path=%q, id=%q", path, resp.Data["id"])
			}
		}
		return fmt.Errorf("failed to create identity group %q, reason=%w", name, err)
	}

	log.Printf("[DEBUG] Created IdentityGroup %q", resp.Data["name"])
	d.SetId(resp.Data["id"].(string))

	return identityGroupRead(d, meta)
}

func identityGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroup %q", id)
	path := group.IdentityGroupIDPath(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	data := map[string]interface{}{}

	if err := identityGroupUpdateFields(d, meta, data); err != nil {
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	log.Printf("[DEBUG] Read IdentityGroup %s", id)
	resp, err := group.ReadIdentityGroup(client, id, d.IsNewResource())
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}

		if group.IsIdentityNotFoundError(err) {
			log.Printf("[WARN] IdentityGroup %q not found, removing from state", id)
			d.SetId("")
			return nil
		}
		return fmt.Errorf("error reading IdentityGroup %q: %s", id, err)
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
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	id := d.Id()

	path := group.IdentityGroupIDPath(id)

	provider.VaultMutexKV.Lock(path)
	defer provider.VaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Deleting IdentityGroup %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityGroup %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityGroup %q", id)

	return nil
}

func identityGroupNamePath(name string) string {
	return fmt.Sprintf("%s/name/%s", group.IdentityGroupPath, name)
}

func readIdentityGroupPolicies(client *api.Client, groupID string, retry bool) ([]interface{}, error) {
	resp, err := group.ReadIdentityGroup(client, groupID, retry)
	if err != nil {
		return nil, err
	}

	if v, ok := resp.Data["policies"]; ok && v != nil {
		return v.([]interface{}), nil
	}
	return make([]interface{}, 0), nil
}

func readIdentityGroupMemberEntityIds(client *api.Client, groupID string, retry bool) ([]interface{}, error) {
	resp, err := group.ReadIdentityGroup(client, groupID, retry)
	if err != nil {
		return nil, err
	}

	if v, ok := resp.Data["member_entity_ids"]; ok && v != nil {
		return v.([]interface{}), nil
	}
	return make([]interface{}, 0), nil
}

func identityGroupExternalGroupIDsResourceV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			fieldExternalMemberGroupIDs: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage member groups externally through `vault_identity_group_member_group_ids`",
			},
		},
	}
}

func identityGroupExternalGroupIDsUpgradeV0(
	_ context.Context, rawState map[string]interface{}, _ interface{},
) (map[string]interface{}, error) {
	if rawState[fieldExternalMemberGroupIDs] == nil {
		rawState[fieldExternalMemberGroupIDs] = false
	}

	return rawState, nil
}
