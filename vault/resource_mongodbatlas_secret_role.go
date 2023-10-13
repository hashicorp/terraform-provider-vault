// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	mongodbAtlasSecretMountFromPathRegex    = regexp.MustCompile("^(.+)/roles/.+$")
	mongodbAtlasSecretRoleNameFromPathRegex = regexp.MustCompile("^.+/roles/(.+)$")
)

func mongodbAtlasSecretRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: mongodbAtlasSecretRoleCreateUpdate,
		ReadContext:   provider.ReadContextWrapper(mongodbAtlasSecretRoleRead),
		UpdateContext: mongodbAtlasSecretRoleCreateUpdate,
		DeleteContext: mongodbAtlasSecretRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path where MongoDB Atlas secret backend is mounted",
				ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
			},
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role",
			},
			consts.FieldOrganizationID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ID for the organization to which the target API Key belongs",
			},
			consts.FieldProjectID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ID for the project to which the target API Key belongs",
			},
			consts.FieldRoles: {
				Type:        schema.TypeList,
				Required:    true,
				Description: "List of roles that the API Key needs to have",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldIPAddresses: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "IP address to be added to the whitelist for the API key",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldCIDRBlocks: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Whitelist entry in CIDR notation to be added for the API key",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldProjectRoles: {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Roles assigned when an org API key is assigned to a project API key",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			consts.FieldTTL: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Duration in seconds after which the issued credential should expire",
			},
			consts.FieldMaxTTL: {
				Type:        schema.TypeString,
				Optional:    true,
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

	mount := d.Get(consts.FieldMount).(string)
	name := d.Get(consts.FieldName).(string)

	path := mount + "/roles/" + name
	log.Printf("[DEBUG] Creating role %q in MongoDB Atlas", name)

	data := map[string]interface{}{}
	fields := []string{
		consts.FieldOrganizationID,
		consts.FieldProjectID,
		consts.FieldRoles,
		consts.FieldIPAddresses,
		consts.FieldCIDRBlocks,
		consts.FieldProjectRoles,
		consts.FieldTTL,
		consts.FieldMaxTTL,
	}
	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, path, data); err != nil {
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
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading MongoDB Atlas role at %s, err=%w", path, err))
	}
	if resp == nil {
		log.Printf("[WARN] MongoDB Atlas role not found, removing from state")
		d.SetId("")
		return nil
	}

	mount, err := mongodbAtlasSecretMountFromPath(path)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}

	name, err := mongodbAtlasSecretRoleNameFromPath(path)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	fields := []string{
		consts.FieldOrganizationID,
		consts.FieldProjectID,
		consts.FieldRoles,
		consts.FieldIPAddresses,
		consts.FieldCIDRBlocks,
		consts.FieldProjectRoles,
		consts.FieldTTL,
		consts.FieldMaxTTL,
	}
	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q on MongoDB Atlas backend role, err=%s",
				k, err)
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

func mongodbAtlasSecretMountFromPath(path string) (string, error) {
	if !mongodbAtlasSecretMountFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := mongodbAtlasSecretMountFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func mongodbAtlasSecretRoleNameFromPath(path string) (string, error) {
	if !mongodbAtlasSecretRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := mongodbAtlasSecretRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}
