package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
				Description: "Terraform Cloud secret backend to generate tokens from",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			"lease_id": {
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

	if secret.LeaseID != "" {
		d.Set("lease_id", secret.LeaseID)
	} else {
		d.Set("lease_id", "")
	}

	d.Set("token", token)
	d.Set("token_id", tokenId)
	d.Set("organization", organization)
	d.Set("team_id", teamId)

	return nil
}

func deleteTerraformCloudSecretCredsResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	leaseId := d.Get("lease_id").(string)

	if leaseId != "" {
		err := client.Sys().Revoke(leaseId)
		if err != nil {
			return fmt.Errorf("error revoking token from Vault: %s", err)
		}
		log.Printf("[DEBUG] Revoked lease: %q from Vault, removing user token %s from state", leaseId, d.Id())
		d.SetId("")
	} else {
		log.Printf("[DEBUG] No lease to revoke for Team/Org tokens")
	}
	return nil
}

func updateTerraformCloudSecretCredsResource(d *schema.ResourceData, meta interface{}) error {
	err := deleteTerraformCloudSecretCredsResource(d, meta)
	if err != nil {
		return fmt.Errorf("previous token not revoked: %s", err)
	}
	err = createTerraformCloudSecretCredsResource(d, meta)
	return err
}

func readTerraformCloudSecretCredsResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	leaseId := d.Get("lease_id")

	if leaseId != "" {
		data := map[string]interface{}{
			"lease_id": leaseId,
		}
		_, err := client.Logical().Write("/sys/leases/lookup", data)
		if err != nil {
			if strings.Contains(err.Error(), "invalid lease") {
				log.Printf("User token %s lease expired, removing user token from state", d.Get("token_id"))
				d.SetId("")
				return nil
			}
			return err
		}

		return nil
	}
	return createTerraformCloudSecretCredsResource(d, meta)
}
