package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/hashicorp/vault/api"
)

func awsSecretDataSource() *schema.Resource {
	return &schema.Resource{
		Read: awsSecretDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path from which the secret will be read.",
			},

			"access_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS access key ID read from Vault.",
			},

			"secret_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS secret key read from Vault.",
			},

			"security_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS security token read from Vault. (Only returned for STS.)",
			},

			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},

			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},

			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},

			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func awsSecretDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	log.Printf("[DEBUG] Reading %q from Vault", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return fmt.Errorf("No role found at %q; are you sure you're using the right path?", path)
	}

	d.SetId(secret.RequestID)
	d.Set("access_key", secret.Data["access_key"])
	d.Set("secret_key", secret.Data["secret_key"])
	d.Set("security_token", secret.Data["security_token"])
	d.Set("lease_id", secret.LeaseID)
	d.Set("lease_duration", secret.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format(time.RFC3339))
	d.Set("lease_renewable", secret.Renewable)

	// TODO(paddy): poll until we think credentials are available

	return nil
}
