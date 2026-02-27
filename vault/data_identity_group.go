// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	identityGroupFields = []string{
		"creation_time",
		"last_update_time",
		"member_entity_ids",
		"member_group_ids",
		"metadata",
		"modify_index",
		consts.FieldNamespaceID,
		"parent_group_ids",
		"policies",
		"type",
	}

	identityGroupAliasFields = []string{
		"canonical_id",
		"creation_time",
		"id",
		"last_update_time",
		"merged_from_canonical_ids",
		"metadata",
		consts.FieldMountAccessor,
		"mount_path",
		"mount_type",
		"name",
	}
)

func identityGroupDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(identityGroupDataSourceRead),

		Schema: map[string]*schema.Schema{
			"group_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Name of the group.",
			},
			"group_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "ID of the group.",
			},
			"alias_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "ID of the alias.",
			},
			"alias_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Name of the alias. This should be supplied in conjunction with `alias_mount_accessor`.",
			},
			"alias_mount_accessor": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Accessor of the mount to which the alias belongs to. This should be supplied in conjunction with `alias_name`.",
			},

			consts.FieldDataJSON: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Group data from Vault in JSON String form",
			},

			"creation_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"last_update_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"member_entity_ids": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"member_group_ids": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"metadata": {
				Type:     schema.TypeMap,
				Computed: true,
			},
			"modify_index": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			consts.FieldNamespaceID: {
				Type:     schema.TypeString,
				Computed: true,
			},
			"parent_group_ids": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"policies": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"type": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"alias_canonical_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"alias_creation_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"alias_last_update_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"alias_merged_from_canonical_ids": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"alias_metadata": {
				Type:     schema.TypeMap,
				Computed: true,
			},
			"alias_mount_path": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"alias_mount_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func identityGroupLookup(client *api.Client, data map[string]interface{}) (*api.Secret, error) {
	log.Print("[DEBUG] Looking up IdentityGroup")
	resp, err := client.Logical().Write(group.LookupPath, data)
	if err != nil {
		return nil, fmt.Errorf("Error reading Identity Group '%v': %s", data, err)
	}

	if resp == nil {
		return nil, fmt.Errorf("no Identity Group found '%v'", data)
	}

	_, ok := resp.Data["id"]
	if !ok {
		return nil, fmt.Errorf("no Identity Group found '%v'", data)
	}

	return resp, nil
}

func identityGroupDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	data := map[string]interface{}{}

	if v, ok := d.GetOk("group_name"); ok {
		data["name"] = v.(string)
	}
	if v, ok := d.GetOk("group_id"); ok {
		data["id"] = v.(string)
	}
	if v, ok := d.GetOk("alias_id"); ok {
		data["alias_id"] = v.(string)
	}
	if v, ok := d.GetOk("alias_name"); ok {
		data["alias_name"] = v.(string)
	}
	if v, ok := d.GetOk("alias_mount_accessor"); ok {
		data["alias_mount_accessor"] = v.(string)
	}

	log.Print("[DEBUG] Reading IdentityGroup")
	resp, err := identityGroupLookup(client, data)
	if err != nil {
		return err
	}
	id := resp.Data["id"]

	d.SetId(id.(string))
	d.Set("group_id", id)
	d.Set("group_name", resp.Data["name"])

	if alias, ok := resp.Data["alias"]; ok {
		alias := alias.(map[string]interface{})

		for _, k := range identityGroupAliasFields {
			v, ok := alias[k]
			key := fmt.Sprintf("alias_%s", k)
			if ok {
				if err := d.Set(key, v); err != nil {
					return fmt.Errorf("error setting state key %s for IdentityGroup: %s", key, err)
				}
			}
		}
	}

	for _, k := range identityGroupFields {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error setting state key %s for IdentityGroup: %s", k, err)
			}
		}
	}

	// Ignoring error because this value came from JSON in the
	// first place so no reason why it should fail to re-encode.
	jsonDataBytes, _ := json.Marshal(resp.Data)
	d.Set(consts.FieldDataJSON, string(jsonDataBytes))

	return nil
}
