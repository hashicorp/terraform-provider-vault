package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func consulAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: consulAccessCredentialsDataSourceRead,
		Schema: map[string]*schema.Schema{
			// FIXME: Should this be name or role? The data sources seem to be inconsistent regarding preference
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of an existing role against which to create this Consul credential",
			},
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The path of the Consul Secret Backend the role belongs to.",
			},
			"token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The secret token.",
			},
			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The consul accessor token.",
			},
			// FIXME: AWS access credential has lease information, do we need to do the same?
		},
	}
}

func consulAccessCredentialsDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := fmt.Sprintf("%s/creds/%s", backend, role)

	payload := map[string][]string{}

	log.Printf("[DEBUG] Requesting token from %s on Consul secret backend %q", role, backend)
	secret, err := client.Logical().ReadWithData(path, payload)
	if err != nil {
		return fmt.Errorf("error creating token from %s on Consul secret backend %q: %s", role, backend, err)
	}
	log.Printf("[DEBUG] Created token from %s on Consul secret backend %q: %s", role, backend, secret.LeaseID)
	secretToken := secret.Data["token"].(string)
	accessorToken := secret.Data["accessor"].(string)

	d.SetId(secret.LeaseID)
	d.Set("token", secretToken)
	d.Set("accessor", accessorToken)

	return nil
}
