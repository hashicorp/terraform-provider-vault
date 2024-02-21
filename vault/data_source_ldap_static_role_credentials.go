// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func ldapStaticCredDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(readLDAPStaticCreds),
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
			consts.FieldDN: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Distinguished name (DN) of the existing LDAP entry to manage password rotation for.",
			},
			consts.FieldLastVaultRotation: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last time Vault rotated this static role's password.",
			},
			consts.FieldPassword: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Password for the static role.",
				Sensitive:   true,
			},
			consts.FieldLastPassword: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last known password for the static role.",
				Sensitive:   true,
			},
			consts.FieldRotationPeriod: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "How often Vault should rotate the password of the user entry.",
			},
			consts.FieldTTL: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Duration in seconds after which the issued credential should expire.",
			},
			consts.FieldUsername: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the static role.",
			},
			consts.FieldSkipImportRotation: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Skip rotation of the password on import.",
			},
		},
	}
}

func readLDAPStaticCreds(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	mount := d.Get(consts.FieldMount).(string)
	role := d.Get(consts.FieldRoleName).(string)
	fullPath := fmt.Sprintf("%s/static-cred/%s", mount, role)

	secret, err := client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", fullPath)
	if secret == nil {
		return diag.FromErr(fmt.Errorf("no role found at %q", fullPath))
	}

	response, err := parseLDAPStaticCredSecret(secret)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(fullPath)
	if err := d.Set(consts.FieldDN, response.dn); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldLastPassword, response.lastPassword); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldLastVaultRotation, response.lastVaultRotation); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldPassword, response.password); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldRotationPeriod, response.rotationPeriod); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldTTL, response.ttl); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldUsername, response.username); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

type lDAPStaticCredResponse struct {
	dn                string
	lastPassword      string
	lastVaultRotation string
	password          string
	rotationPeriod    int64
	ttl               int64
	username          string
}

func parseLDAPStaticCredSecret(secret *api.Secret) (lDAPStaticCredResponse, error) {
	var (
		dn                string
		lastPassword      string
		lastVaultRotation string
		rotationPeriod    int64
		ttl               int64
	)
	if dnRaw, ok := secret.Data[consts.FieldDN]; ok {
		dn = dnRaw.(string)
	}

	if lastPasswordRaw, ok := secret.Data[consts.FieldLastPassword]; ok {
		lastPassword = lastPasswordRaw.(string)
	}

	if lastVaultRotationRaw, ok := secret.Data[consts.FieldLastVaultRotation]; ok {
		lastVaultRotation = lastVaultRotationRaw.(string)
	}

	if rotationPeriodRaw, ok := secret.Data[consts.FieldRotationPeriod]; ok {
		rotationPeriod, _ = rotationPeriodRaw.(json.Number).Int64()
	}

	if ttlRaw, ok := secret.Data[consts.FieldTTL]; ok {
		ttl, _ = ttlRaw.(json.Number).Int64()
	}

	username := secret.Data[consts.FieldUsername].(string)
	if username == "" {
		return lDAPStaticCredResponse{}, fmt.Errorf("username is not set in response")
	}

	password := secret.Data[consts.FieldPassword].(string)
	if password == "" {
		return lDAPStaticCredResponse{}, fmt.Errorf("password is not set in response")
	}

	return lDAPStaticCredResponse{
		dn:                dn,
		lastPassword:      lastPassword,
		lastVaultRotation: lastVaultRotation,
		password:          password,
		rotationPeriod:    rotationPeriod,
		ttl:               ttl,
		username:          username,
	}, nil
}
