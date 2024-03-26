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

func ldapSecretBackendLibrarySetResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldMount: {
			Type:         schema.TypeString,
			Default:      consts.MountTypeLDAP,
			Optional:     true,
			Description:  "The path where the LDAP secrets backend is mounted.",
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		consts.FieldName: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The name of the set of service accounts.",
			ForceNew:    true,
		},
		consts.FieldServiceAccountNames: {
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Required:    true,
			ForceNew:    true,
			Description: "The names of all the service accounts that can be checked out from this set.",
		},
		consts.FieldTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "The maximum amount of time a single check-out lasts before Vault automatically checks it back in. Defaults to 24 hours.",
			Computed:    true,
		},
		consts.FieldMaxTTL: {
			Type:        schema.TypeInt,
			Optional:    true,
			Description: "The maximum amount of time a check-out last with renewal before Vault automatically checks it back in. Defaults to 24 hours.",
			Computed:    true,
		},
		consts.FieldDisableCheckInEnforcement: {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Disable enforcing that service accounts must be checked in by the entity or client token that checked them out.",
		},
	}
	return &schema.Resource{
		CreateContext: createUpdateLDAPLibrarySetResource,
		UpdateContext: createUpdateLDAPLibrarySetResource,
		ReadContext:   provider.ReadContextWrapper(readLDAPLibrarySetResource),
		DeleteContext: deleteLDAPLibrarySetResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: fields,
	}
}

var ldapSecretBackendLibrarySetFields = []string{
	consts.FieldName,
	consts.FieldServiceAccountNames,
	consts.FieldTTL,
	consts.FieldMaxTTL,
	consts.FieldDisableCheckInEnforcement,
}

func createUpdateLDAPLibrarySetResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Get(consts.FieldMount).(string)
	set := d.Get(consts.FieldName).(string)
	libraryPath := fmt.Sprintf("%s/library/%s", path, set)
	log.Printf("[DEBUG] Creating LDAP library set at %q", libraryPath)
	data := map[string]interface{}{}
	for _, field := range ldapSecretBackendLibrarySetFields {
		if v, ok := d.GetOk(field); ok {
			data[field] = v
		}
	}

	if _, err := client.Logical().WriteWithContext(ctx, libraryPath, data); err != nil {
		return diag.FromErr(fmt.Errorf("error writing %q: %s", libraryPath, err))
	}

	d.SetId(libraryPath)
	log.Printf("[DEBUG] Wrote %q", libraryPath)
	return readLDAPLibrarySetResource(ctx, d, meta)
}

func readLDAPLibrarySetResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	libraryPath := d.Id()
	log.Printf("[DEBUG] Reading %q", libraryPath)

	resp, err := client.Logical().ReadWithContext(ctx, libraryPath)
	if err != nil {
		return diag.FromErr(err)
	}

	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", libraryPath)
		d.SetId("")
		return nil
	}
	for _, field := range ldapSecretBackendLibrarySetFields {
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.FromErr(fmt.Errorf("error setting state key '%s': %s", field, err))
			}
		}
	}

	return nil
}

func deleteLDAPLibrarySetResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	libraryPath := d.Id()
	_, err = client.Logical().DeleteWithContext(ctx, libraryPath)
	if err != nil {
		if util.Is404(err) {
			d.SetId("")
			return nil
		}

		return diag.FromErr(fmt.Errorf("error deleting library set %q: %w", libraryPath, err))
	}

	return nil
}
