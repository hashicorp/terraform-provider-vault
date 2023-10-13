// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldBoundSubjects       = "bound_subjects"
	fieldBoundSubjectsType   = "bound_subjects_type"
	fieldBoundAttributes     = "bound_attributes"
	fieldBoundAttributesType = "bound_attributes_type"
	fieldGroupsAttribute     = "groups_attribute"
)

var (
	samlAuthMountFromPathRegex    = regexp.MustCompile("^auth/(.+)/role/[^/]+$")
	samlAuthRoleNameFromPathRegex = regexp.MustCompile("^auth/.+/role/([^/]+)$")

	samlRoleAPIFields = []string{
		fieldBoundSubjects,
		fieldBoundSubjectsType,
		fieldBoundAttributes,
		fieldBoundAttributesType,
		fieldGroupsAttribute,
	}
)

func samlAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldPath: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Path where SAML Auth engine is mounted.",
			ForceNew:    true,
		},
		consts.FieldName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Unique name of the role.",
			ForceNew:    true,
		},
		fieldBoundSubjects: {
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:    true,
			Description: "The subject being asserted for SAML authentication.",
		},
		fieldBoundSubjectsType: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The type of matching assertion to perform on bound_subjects.",
		},
		fieldBoundAttributes: {
			Type: schema.TypeMap,
			//Elem: &schema.Schema{
			//	Type: schema.TypeString,
			//},
			Optional:    true,
			Description: "Mapping of attribute names to values that are expected to exist in the SAML assertion",
		},
		fieldBoundAttributesType: {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The type of matching assertion to perform on bound_attributes.",
		},
		fieldGroupsAttribute: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The attribute to use to identify the set of groups to which the user belongs.",
		},
	}
	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(samlAuthBackendRoleWrite, provider.VaultVersion115),
		ReadContext:   provider.ReadContextWrapper(samlAuthBackendRoleRead),
		UpdateContext: samlAuthBackendRoleWrite,
		DeleteContext: samlAuthBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: fields,
	}
}

func samlAuthBackendRoleWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Get(consts.FieldPath).(string)
	name := d.Get(consts.FieldName).(string)

	rolePath := samlAuthBackendRolePath(path, name)

	data := map[string]interface{}{}

	for _, k := range samlRoleAPIFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	// handle bound_attributes field
	// vault expects a comma separated string
	//if v, ok := d.GetOk(fieldBoundAttributes); ok {
	//	if val, ok := v.([]string); ok {
	//		data[fieldBoundAttributes] = strings.Join(val, ",")
	//	}
	//}

	// add common token fields
	updateTokenFields(d, data, true)

	log.Printf("[DEBUG] Writing saml auth backend role to %q", rolePath)
	_, err := client.Logical().Write(rolePath, data)
	if err != nil {
		return diag.Errorf("error writing to %q: %s", rolePath, err)
	}
	log.Printf("[DEBUG] Wrote saml auth backend role to %q", rolePath)

	d.SetId(rolePath)

	return samlAuthBackendRoleRead(ctx, d, meta)
}

func samlAuthBackendRoleRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	id := d.Id()
	log.Printf("[DEBUG] Reading saml auth backend config")
	resp, err := client.Logical().Read(id)
	if err != nil {
		return diag.Errorf("error reading saml auth backend config from %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read saml auth backend config")

	if resp == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", id)
		d.SetId("")
		return nil
	}

	mount, err := samlAuthResourceMountFromPath(id)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldPath, mount); err != nil {
		return diag.FromErr(err)
	}

	name, err := samlAuthResourceRoleNameFromPath(id)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, name); err != nil {
		return diag.FromErr(err)
	}

	if err := readTokenFields(d, resp); err != nil {
		return diag.FromErr(err)
	}

	// set all API fields to TF state
	for _, k := range samlRoleAPIFields {
		if v, ok := resp.Data[k]; ok {
			// flatten map into TypeMap that was sent to Vault
			if k == fieldBoundAttributes {
				if val, ok := v.(map[string]interface{}); ok {
					v = samlAuthRoleFlattenBoundAttributesMap(val)
				}
			}

			if err := d.Set(k, v); err != nil {
				return diag.Errorf("error setting state key %q: err=%s", k, err)
			}
		}
	}

	return nil
}

func samlAuthBackendRoleDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting SAML auth role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return diag.Errorf("error deleting SAML auth role %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted SAML auth role %q", path)

	return nil
}

func samlAuthBackendRolePath(path string, name string) string {
	return "auth/" + strings.Trim(path, "/") + "/role/" + name
}

func samlAuthResourceMountFromPath(path string) (string, error) {
	if !samlAuthMountFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no mount found")
	}
	res := samlAuthMountFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for mount", len(res))
	}
	return res[1], nil
}

func samlAuthResourceRoleNameFromPath(path string) (string, error) {
	if !samlAuthRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := samlAuthRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func samlAuthRoleFlattenBoundAttributesMap(attr map[string]interface{}) map[string]string {
	newAttrs := map[string]string{}
	for key, val := range attr {
		if v, ok := val.([]interface{}); ok {
			el := []string{}
			for _, k := range v {
				el = append(el, k.(string))
			}

			newAttrs[key] = strings.Join(el, ",")
		}
	}

	return newAttrs
}
