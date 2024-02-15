// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func ldapDynamicCredDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readLDAPDynamicCreds),
		Schema: map[string]*schema.Schema{
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "LDAP Secret Backend to read credentials from.",
			},
			consts.FieldRoleName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			consts.FieldLeaseID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by Vault.",
			},
			consts.FieldLeaseDuration: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds.",
			},
			consts.FieldLeaseRenewable: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
			consts.FieldDistinguishedNames: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "List of the distinguished names (DN) created.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			consts.FieldPassword: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Password for the dynamic role.",
				Sensitive:   true,
			},
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the dynamic role.",
			},
		},
	}
}

func readLDAPDynamicCreds(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	mount := d.Get(consts.FieldMount).(string)
	role := d.Get(consts.FieldRoleName).(string)
	fullPath := fmt.Sprintf("%s/creds/%s", mount, role)

	secret, err := client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", fullPath)
	if secret == nil {
		return diag.FromErr(fmt.Errorf("no role found at %q", fullPath))
	}

	response, err := parseLDAPDynamicCredSecret(secret)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(secret.LeaseID)
	if err := d.Set(consts.FieldLeaseID, secret.LeaseID); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldLeaseDuration, secret.LeaseDuration); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldLeaseRenewable, secret.Renewable); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldDistinguishedNames, response.distinguishedNames); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldPassword, response.password); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldUsername, response.username); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

type lDAPDynamicCredResponse struct {
	distinguishedNames []string
	password           string
	username           string
}

func parseLDAPDynamicCredSecret(secret *api.Secret) (lDAPDynamicCredResponse, error) {
	var distinguishedNames []string
	if distinguishedNamesRaw, ok := secret.Data[consts.FieldDistinguishedNames]; ok {
		for _, dnRaw := range distinguishedNamesRaw.([]interface{}) {
			distinguishedNames = append(distinguishedNames, dnRaw.(string))
		}
	}

	username := secret.Data[consts.FieldUsername].(string)
	if username == "" {
		return lDAPDynamicCredResponse{}, fmt.Errorf("username is not set in response")
	}

	password := secret.Data[consts.FieldPassword].(string)
	if password == "" {
		return lDAPDynamicCredResponse{}, fmt.Errorf("password is not set in response")
	}

	return lDAPDynamicCredResponse{
		distinguishedNames: distinguishedNames,
		password:           password,
		username:           username,
	}, nil
}
