// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func mongodbAtlasSecretRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: mongodbAtlasSecretRoleCreateUpdate,
		ReadContext:   ReadContextWrapper(mongodbAtlasSecretRoleRead),
		UpdateContext: mongodbAtlasSecretRoleCreateUpdate,
		DeleteContext: mongodbAtlasSecretRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where MongoDB Atlas secret backend is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			consts.FieldPath: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where MongoDB Atlas backend is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role",
			},
			"organization_id": {
				Type:        schema.TypeString,
				Required:    false,
				Description: "ID for the organization to which the target API Key belongs",
			},
			"project_id": {
				Type:        schema.TypeString,
				Required:    false,
				Description: "ID for the project to which the target API Key belongs",
			},
			"roles": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of roles that the API Key needs to have",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"id_addresses": {
				Type:        schema.TypeList,
				Required:    false,
				Description: "IP address to be added to the whitelist for the API key",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"cidr_blocks": {
				Type:        schema.TypeList,
				Required:    false,
				Description: "Whitelist entry in CIDR notation to be added for the API key",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"project_roles": {
				Type:        schema.TypeList,
				Required:    false,
				Description: "Roles assigned when an org API key is assigned to a project API key",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Duration in seconds after which the issued credential should expire",
			},
			"max_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The maximum allowed lifetime of credentials issued using this role",
			},
		},
	}
}

func mongodbAtlasSecretRoleCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	name := d.Get("name").(string)

	path := backend + "/roles/" + name
	log.Printf("[DEBUG] Creating role %q in MongoDB Atlas", name)

	data := map[string]interface{}{}
	if v, ok := d.GetOk("organization_id"); ok {
		data["organization_id"] = v
	}
	if v, ok := d.GetOk("project_id"); ok {
		data["project_id"] = v
	}
	if v, ok := d.GetOk("roles"); ok {
		data["roles"] = v
	}
	if v, ok := d.GetOk("ip_addresses"); ok {
		data["ip_addresses"] = v
	}
	if v, ok := d.GetOk("cidr_blocks"); ok {
		data["cidr_blocks"] = v
	}
	if v, ok := d.GetOk("project_roles"); ok {
		data["project_roles"] = v
	}
	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v
	}

	if _, err := client.Logical().Write(path, data); err != nil {
		return diag.Errorf("error updating MongoDB Atlas role %q, err=%s", name, err)
	}

	d.SetId(path)

	return mongodbAtlasSecretRoleRead(ctx, d, meta)
}

func mongodbAtlasSecretRoleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Reading MongoDB Atlas role at %q", path)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading MongoDB Atlas role at %s, err=%w", path, err))
	}
	if resp == nil {
		log.Printf("[WARN] MongoDB Atlas role not found, removing from state")
		d.SetId("")

		return diag.FromErr(fmt.Errorf("expected role at %s, no role found", path))
	}

	if v, ok := resp.Data["name"]; ok {
		if err := d.Set("name", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'name': %s", err))
		}
	}
	if v, ok := resp.Data["organization_id"]; ok {
		if err := d.Set("organization_id", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'organization_id': %s", err))
		}
	}
	if v, ok := resp.Data["project_id"]; ok {
		if err := d.Set("project_id", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'project_id': %s", err))
		}
	}
	if v, ok := resp.Data["roles"]; ok {
		if err := d.Set("roles", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'roles': %s", err))
		}
	}
	if v, ok := resp.Data["ip_addresses"]; ok {
		if err := d.Set("ip_addresses", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'ip_addresses': %s", err))
		}
	}
	if v, ok := resp.Data["cidr_blocks"]; ok {
		if err := d.Set("cidr_blocks", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'cidr_blocks': %s", err))
		}
	}
	if v, ok := resp.Data["project_roles"]; ok {
		if err := d.Set("project_roles", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'project_roles': %s", err))
		}
	}
	if v, ok := resp.Data["ttl"]; ok {
		if err := d.Set("ttl", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'ttl': %s", err))
		}
	}
	if v, ok := resp.Data["max_ttl"]; ok {
		if err := d.Set("max_ttl", v); err != nil {
			return diag.FromErr(fmt.Errorf("error setting state key 'max_ttl': %s", err))
		}
	}

	return nil
}

func mongodbAtlasSecretRoleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Id()

	log.Printf("[DEBUG] Deleting MongoDB Atlas role %s", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting role %s", path)
	}
	log.Printf("[DEBUG] Deleted MongoDB Atlas role %q", path)

	return nil
}
