// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func terraformCloudCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: ReadWrapper(terraformCloudCredentialsDataSourceRead),
		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Nomad secret backend to generate tokens from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			consts.FieldLeaseID: {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Associated Vault lease ID, if one exists",
			},
			"token": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Terraform Token provided by the Vault backend",
			},
			"token_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the Terraform Token provided",
			},
			"organization": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the Terraform Cloud or Enterprise organization",
			},
			"team_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the Terraform Cloud or Enterprise team under organization (e.g., settings/teams/team-xxxxxxxxxxxxx)",
			},
		},
	}
}

func terraformCloudCredentialsDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	path := fmt.Sprintf("%s/creds/%s", backend, role)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return fmt.Errorf("no role found at %q", path)
	}

	token := secret.Data["token"].(string)

	if token == "" {
		return fmt.Errorf("token is not set in response")
	}

	tokenId := secret.Data["token_id"].(string)
	organization := secret.Data["organization"]
	teamId := secret.Data["team_id"]

	d.SetId(tokenId)

	if secret.LeaseID != "" {
		d.Set(consts.FieldLeaseID, secret.LeaseID)
	} else {
		d.Set(consts.FieldLeaseID, "")
	}

	d.Set("token", token)
	d.Set("token_id", tokenId)
	d.Set("organization", organization)
	d.Set("team_id", teamId)

	return nil
}
