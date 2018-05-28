package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/hashicorp/vault/api"
)

func sshSignCertificateDataSource() *schema.Resource {
	return &schema.Resource{
		Read: sshSignCertificateRead,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "SSH Secret Engine to read credentials from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the name of the role to sign. This is part of the request URL.",
			},
			"cert_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "user",
				Description: "Specifies the type of certificate to be created; either 'user' or 'host'.",
			},
			"public_key": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "SSH Public Key to Sign.",
			},
			"ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1800,
				Description: "Number of seconds that the signature will be valid for (defaults to 30 minutes). Cannot be greater than the role's max_ttl value. If not provided, the role's ttl value will be used.",
			},
			"valid_principals": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "*",
				Description: "Specifies valid principals, either usernames or hostnames, that the certificate should be signed for.",
			},
			"key_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Specifies the key id that the created certificate should have. If not specified, the display name of the token will be used.",
			},
			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},
			"serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Serial number of the signed certificate.",
			},
			"signed_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Signed certificate key.",
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

func sshSignCertificateRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	certType := d.Get("cert_type").(string)
	role := d.Get("role").(string)
	publicKey := d.Get("public_key").(string)
	ttl := d.Get("ttl").(int)
	validPrincipals := d.Get("valid_principals").(string)
	keyId := d.Get("key_id").(string)
	path := backend + "/sign/" + role

	data := map[string]interface{}{
		"cert_type":        certType,
		"public_key":       publicKey,
		"ttl":              ttl,
		"key_id":           keyId,
		"valid_principals": validPrincipals,
	}

	log.Printf("[DEBUG] Writing %q to Vault", path)
	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error writing to Vault: %s", err)
	}
	log.Printf("[DEBUG] Write %q to Vault", path)

	if secret == nil {
		return fmt.Errorf("No role found at %q; are you sure you're using the right backend and role?", path)
	}

	d.SetId(secret.RequestID)
	d.Set("signed_key", secret.Data["signed_key"])
	d.Set("serial_number", secret.Data["serial_number"])
	d.Set("lease_id", secret.LeaseID)
	d.Set("lease_duration", secret.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format("RFC3339"))
	d.Set("lease_renewable", secret.Renewable)

	return nil
}
