// Copyright IBM Corp. 2016, 2025
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
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	awsStaticRolesAffix = "static-roles"
)

// awsStaticRolesRegex matches vault paths, capturing backend and role names. This is greedy-by-default,
// which means if someone does something like 'a/static-roles/static-roles/b', the ambiguity will be
// resolved by putting the extras into the backend part of the path.
var awsStaticRolesRegex = regexp.MustCompile("^(.+)/static-roles/(.+)$")

func awsSecretBackendStaticRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		// backend is deprecated, but the other AWS resource types use it, and predate the deprecation.
		// It's probably more helpful to the end user to maintain this consistency, in this particular case.
		consts.FieldBackend: {
			Type:         schema.TypeString,
			Optional:     true,
			Default:      consts.MountTypeAWS,
			Description:  "The path where the AWS secrets backend is mounted.",
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		consts.FieldName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		consts.FieldUsername: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The username of the existing AWS IAM user to manage password rotation for.",
			ForceNew:    true,
		},
		consts.FieldRotationPeriod: {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "How often Vault should rotate the password of the user entry.",
		},
		consts.FieldAssumeRoleArn: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The ARN of the role to assume when managing the static role. This is required for cross-account role management. ",
		},
		consts.FieldAssumeRoleSessionName: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Session name to use when assuming the role.",
		},
		consts.FieldExternalID: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "External ID to use when assuming the role.",
		},
	}
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(createUpdateAWSStaticRoleResource, provider.VaultVersion114),
		UpdateContext: createUpdateAWSStaticRoleResource,
		ReadContext:   provider.ReadContextWrapper(readAWSStaticRoleResource),
		DeleteContext: deleteAWSStaticRoleResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

var awsSecretBackendStaticRoleFields = []string{
	consts.FieldName,
	consts.FieldUsername,
	consts.FieldRotationPeriod,
}

var awsSecretBackendStaticAssumeRoleFields = []string{
	consts.FieldAssumeRoleArn,
	consts.FieldAssumeRoleSessionName,
	consts.FieldExternalID,
}

// createUpdateAWSStaticRoleResources upserts an aws static-role to our vault instance.
func createUpdateAWSStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	role := d.Get(consts.FieldName).(string)
	rolePath := fmt.Sprintf("%s/%s/%s", backend, awsStaticRolesAffix, role)
	log.Printf("[DEBUG] Creating AWS static role at %q", rolePath)
	data := map[string]interface{}{}
	for _, field := range awsSecretBackendStaticRoleFields {
		if v, ok := d.GetOk(field); ok {
			data[field] = v
		}
	}

	useAPIVer119Ent := provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta)
	if useAPIVer119Ent {
		for _, field := range awsSecretBackendStaticAssumeRoleFields {
			if v, ok := d.GetOk(field); ok {
				data[field] = v
			}
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, rolePath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error writing %q: %s", rolePath, err))
	}

	d.SetId(rolePath)
	log.Printf("[DEBUG] Wrote %q", rolePath)
	return readAWSStaticRoleResource(ctx, d, meta)
}

func readAWSStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading %q", path)
	backend, role, err := parseAWSStaticRolePath(path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("invalid id %q; %w", path, err))
	}

	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, role); err != nil {
		return diag.FromErr(err)
	}

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	for _, field := range awsSecretBackendStaticRoleFields {
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
			}
		}
	}

	useAPIVer119Ent := provider.IsAPISupported(meta, provider.VaultVersion119) && provider.IsEnterpriseSupported(meta)
	if useAPIVer119Ent {
		for _, field := range awsSecretBackendStaticAssumeRoleFields {
			if val, ok := resp.Data[field]; ok {
				if err := d.Set(field, val); err != nil {
					return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
				}
			}
		}
	}

	return nil
}

func deleteAWSStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	rolePath := d.Id()
	_, err = client.Logical().DeleteWithContext(ctx, rolePath)
	if err != nil {
		if util.Is404(err) {
			d.SetId("")
			return nil
		}

		return diag.FromErr(fmt.Errorf("error deleting static role %q: %w", rolePath, err))
	}

	return nil
}

// parseAWSStaticRolePath attempts to parse out the backend and role name from the provided path.
func parseAWSStaticRolePath(path string) (backend, name string, err error) {
	ms := awsStaticRolesRegex.FindStringSubmatch(path)
	if ms == nil {
		return "", "", fmt.Errorf("no pattern match for path %s", path)
	}
	if len(ms) != 3 { // 0 = entire match, 1 = first capture group (backend), 2 = second capture group (role name)
		return "", "", fmt.Errorf("unexpected number (%d) of matches found, expected 3", len(ms))
	}

	return ms[1], ms[2], nil

}
