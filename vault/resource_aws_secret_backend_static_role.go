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
	"github.com/hashicorp/terraform-provider-vault/util"
)

func awsSecretBackendStaticRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldMount: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeAWS,
			Optional:     true,
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
	}
	return &schema.Resource{
		CreateContext: createUpdateAWSStaticRoleResource,
		UpdateContext: createUpdateAWSStaticRoleResource,
		ReadContext:   ReadContextWrapper(readAWSStaticRoleResource),
		DeleteContext: deleteAWSStaticRoleResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

var awsSecretBackendStaticRoleFields = []string{
	consts.FieldUsername,
	consts.FieldRotationPeriod,
}

// createUpdateAWSStaticRoleResources upserts an aws static-role to our vault instance.
func createUpdateAWSStaticRoleResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	mount := d.Get(consts.FieldMount).(string)
	role := d.Get(consts.FieldName).(string)
	rolePath := fmt.Sprintf("%s/static-roles/%s", mount, role)
	log.Printf("[DEBUG] Creating AWAS static role at %q", rolePath)
	data := map[string]interface{}{}
	for _, field := range awsSecretBackendStaticRoleFields {
		if v, ok := d.GetOk(field); ok {
			data[field] = v
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

	rolePath := d.Id()
	log.Printf("[DEBUG] Reading %q", rolePath)

	resp, err := client.Logical().ReadWithContext(ctx, rolePath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", rolePath)
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
