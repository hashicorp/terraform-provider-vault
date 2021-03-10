package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func terraformCloudSecretCredsResource() *schema.Resource {
	return &schema.Resource{
		Create: createTerraformCloudSecretCredsResource,
		Read:   readTerraformCloudSecretCredsResource,
		Update: updateTerraformCloudSecretCredsResource,
		Delete: deleteTerraformCloudSecretCredsResource,
		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Terraform Cloud secret backend to generate tokens from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			"token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Terraform Token provided by the Vault backend",
				Sensitive:   true,
			},
			"token_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the Terraform Token provided",
			},
			"organization": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "Name of the Terraform Cloud or Enterprise organization",
			},
			"team_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "ID of the Terraform Cloud or Enterprise team under organization (e.g., settings/teams/team-xxxxxxxxxxxxx)",
			},
		},
	}
}

func createTerraformCloudSecretCredsResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
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
	d.Set("token", token)
	d.Set("token_id", tokenId)
	d.Set("organization", organization)
	d.Set("team_id", teamId)

	return nil
}

func deleteTerraformCloudSecretCredsResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	tokenId := d.Id()

	err := client.Sys().Revoke(tokenId)
	if err != nil {
		return fmt.Errorf("error revoking token from Vault: %s", err)
	}
	log.Printf("[DEBUG] Revoked tokenId: %q from Vault", tokenId)
	return nil
}

func updateTerraformCloudSecretCredsResource(d *schema.ResourceData, meta interface{}) error {
	err := deleteTerraformCloudSecretCredsResource(d, meta)
	if err != nil {
		return fmt.Errorf("previous token not revoked: %s", err)
	}
	err = readTerraformCloudSecretCredsResource(d, meta)
	return err
}

func readTerraformCloudSecretCredsResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	tokenId := d.Id()

	creds, err := client.Sys().Renew(tokenId, 0)
	if err != nil {
		if strings.Contains(err.Error(), "lease not found") {
			return nil
		} else {
			return err
		}
	}

	if creds.LeaseDuration > 0 {
		data := creds.Data
		d.SetId(tokenId)
		d.Set("token", data["token"])
		d.Set("token_id", tokenId)
		d.Set("organization", data["organization"])
		d.Set("team_id", data["teamId"])
	}

	return nil
}
