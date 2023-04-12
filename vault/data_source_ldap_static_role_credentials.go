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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

func ldapStaticCredDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: ReadContextWrapper(readLDAPStaticCreds),
		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "LDAP Secret Backend to read credentials from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			"dn": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Distinguished name (DN) of the existing LDAP entry to manage password rotation for.",
			},
			"last_vault_rotation": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last time Vault rotated this service account's password.",
			},
			"password": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Password for the service account.",
				Sensitive:   true,
			},
			"last_password": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last known password for the service account.",
				Sensitive:   true,
			},
			"rotation_period": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "How often Vault should rotate the password of the user entry.",
				Sensitive:   true,
			},
			"ttl": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The maximum amount of time a single check-out lasts before Vault automatically checks it back in.",
			},
			"username": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the service account.",
			},
		},
	}
}

func readLDAPStaticCreds(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	path := fmt.Sprintf("%s/static-cred/%s", backend, role)

	secret, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", path)
	if secret == nil {
		return diag.FromErr(fmt.Errorf("no role found at %q", path))
	}

	response, err := parseLDAPStaticCredSecret(secret)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(response.username)
	d.Set("dn", response.dn)
	d.Set("last_password", response.lastPassword)
	d.Set("last_vault_rotation", response.lastVaultRotation)
	d.Set("password", response.password)
	d.Set("rotation_period", response.rotationPeriod)
	d.Set("ttl", response.ttl)
	d.Set("username", response.username)
	return nil
}

type lDAPStaticCredResponse struct {
	dn                string
	lastPassword      string
	lastVaultRotation string
	password          string
	rotationPeriod    string
	ttl               string
	username          string
}

func parseLDAPStaticCredSecret(secret *api.Secret) (lDAPStaticCredResponse, error) {
	var (
		dn                string
		lastPassword      string
		lastVaultRotation string
		rotationPeriod    string
		ttl               string
	)
	if dnRaw, ok := secret.Data["dn"]; ok {
		dn = dnRaw.(string)
	}

	if lastPasswordRaw, ok := secret.Data["last_password"]; ok {
		lastPassword = lastPasswordRaw.(string)
	}

	if lastVaultRotationRaw, ok := secret.Data["last_vault_rotation"]; ok {
		lastVaultRotation = lastVaultRotationRaw.(string)
	}

	if rotationPeriodRaw, ok := secret.Data["rotation_period"]; ok {
		rotationPeriod = rotationPeriodRaw.(json.Number).String()
	}

	if ttlRaw, ok := secret.Data["ttl"]; ok {
		ttl = ttlRaw.(json.Number).String()
	}

	username := secret.Data["username"].(string)
	if username == "" {
		return lDAPStaticCredResponse{}, fmt.Errorf("username is not set in response")
	}

	password := secret.Data["password"].(string)
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
