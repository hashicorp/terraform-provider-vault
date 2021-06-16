package vault

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	identityEntityFields = []string{
		"creation_time",
		"direct_group_ids",
		"disabled",
		"group_ids",
		"inherited_group_ids",
		"last_update_time",
		"merged_entity_ids",
		"metadata",
		"namespace_id",
		"policies",
	}

	identityEntityAliasFields = []string{
		"canonical_id",
		"creation_time",
		"id",
		"last_update_time",
		"merged_from_canonical_ids",
		"metadata",
		"mount_accessor",
		"mount_path",
		"mount_type",
		"name",
	}

	identityEntityAliasSchema = map[string]*schema.Schema{
		"canonical_id": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"creation_time": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"id": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"last_update_time": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"merged_from_canonical_ids": {
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
		"mount_accessor": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"mount_path": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"mount_type": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"name": {
			Type:     schema.TypeString,
			Computed: true,
		},
	}
)

func identityEntityDataSource() *schema.Resource {
	return &schema.Resource{
		Read: identityEntityDataSourceRead,

		Schema: map[string]*schema.Schema{
			"entity_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Name of the entity.",
			},
			"entity_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "ID of the entity.",
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

			"data_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Entity data from Vault in JSON String form",
			},

			"creation_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"last_update_time": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"direct_group_ids": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"disabled": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"group_ids": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"inherited_group_ids": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},
			"merged_entity_ids": {
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
			"namespace_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"policies": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed: true,
			},

			"aliases": {
				Type: schema.TypeSet,
				Elem: &schema.Resource{
					Schema: identityEntityAliasSchema,
				},
				Computed: true,
			},
		},
	}
}

func identityEntityLookup(client *api.Client, data map[string]interface{}) (*api.Secret, error) {
	log.Print("[DEBUG] Looking up IdentityEntity")
	resp, err := client.Logical().Write("identity/lookup/entity", data)

	if err != nil {
		return nil, fmt.Errorf("Error reading Identity Entity '%v': %s", data, err)
	}

	if resp == nil {
		return nil, fmt.Errorf("no Identity Entity found '%v'", data)
	}

	_, ok := resp.Data["id"]
	if !ok {
		return nil, fmt.Errorf("no Identity Entity found '%v'", data)
	}

	return resp, nil
}

func identityEntityDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	data := map[string]interface{}{}

	if v, ok := d.GetOk("entity_name"); ok {
		data["name"] = v.(string)
	}
	if v, ok := d.GetOk("entity_id"); ok {
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

	log.Print("[DEBUG] Reading IdentityEntity")
	resp, err := identityEntityLookup(client, data)

	if err != nil {
		return err
	}
	id := resp.Data["id"]

	d.SetId(id.(string))
	d.Set("entity_id", id)
	d.Set("entity_name", resp.Data["name"])

	for _, k := range identityEntityFields {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error setting state key %s for IdentityEntity: %s", k, err)
			}
		}
	}

	aliases, ok := resp.Data["aliases"]
	if ok && aliases != nil {
		rawAliases := aliases.([]interface{})
		transformed := schema.NewSet(schema.HashResource(&schema.Resource{Schema: identityEntityAliasSchema}), []interface{}{})

		for _, alias := range rawAliases {
			alias := alias.(map[string]interface{})
			data = make(map[string]interface{})
			for _, k := range identityEntityAliasFields {
				data[k] = alias[k]
			}
			transformed.Add(data)
		}
		d.Set("aliases", transformed)
	}

	// Ignoring error because this value came from JSON in the
	// first place so no reason why it should fail to re-encode.
	jsonDataBytes, _ := json.Marshal(resp.Data)
	d.Set("data_json", string(jsonDataBytes))

	return nil
}
