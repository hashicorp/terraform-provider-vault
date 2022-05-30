package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func azureAuthBackendConfigResource() *schema.Resource {
	return &schema.Resource{
		Create: azureAuthBackendWrite,
		Read:   azureAuthBackendRead,
		Update: azureAuthBackendWrite,
		Delete: azureAuthBackendDelete,
		Exists: azureAuthBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "azure",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"tenant_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The tenant id for the Azure Active Directory organization.",
				Sensitive:   true,
			},
			"client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The client id for credentials to query the Azure APIs. Currently read permissions to query compute resources are required.",
				Sensitive:   true,
			},
			"client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The client secret for credentials to query the Azure APIs",
				Sensitive:   true,
			},
			"resource": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The configured URL for the application registered in Azure Active Directory.",
			},
			"environment": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Azure cloud environment. Valid values: AzurePublicCloud, AzureUSGovernmentCloud, AzureChinaCloud, AzureGermanCloud.",
			},
		},
	}
}

func azureAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*api.Client)

	// if backend comes from the config, it won't have the StateFunc
	// applied yet, so we need to apply it again.
	backend := d.Get("backend").(string)
	tenantId := d.Get("tenant_id").(string)
	clientId := d.Get("client_id").(string)
	clientSecret := d.Get("client_secret").(string)
	resource := d.Get("resource").(string)
	environment := d.Get("environment").(string)

	path := azureAuthBackendConfigPath(backend)

	data := map[string]interface{}{
		"tenant_id":     tenantId,
		"client_id":     clientId,
		"client_secret": clientSecret,
		"resource":      resource,
		"environment":   environment,
	}

	log.Printf("[DEBUG] Writing Azure auth backend config to %q", path)
	_, err := config.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Azure auth backend config to %q", path)

	d.SetId(path)

	return azureAuthBackendRead(d, meta)
}

func azureAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*api.Client)

	log.Printf("[DEBUG] Reading Azure auth backend config")
	secret, err := config.Logical().Read(d.Id())
	if err != nil {
		return fmt.Errorf("error reading Azure auth backend config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Read Azure auth backend config")

	if secret == nil {
		log.Printf("[WARN] No info found at %q; removing from state.", d.Id())
		d.SetId("")
		return nil
	}
	idPieces := strings.Split(d.Id(), "/")
	if len(idPieces) != 3 {
		return fmt.Errorf("expected %q to have 4 pieces, has %d", d.Id(), len(idPieces))
	}
	d.Set("backend", idPieces[1])
	d.Set("tenant_id", secret.Data["tenant_id"])
	d.Set("client_id", secret.Data["client_id"])
	if v, ok := secret.Data["client_secret"]; ok {
		d.Set("client_secret", v)
	}
	d.Set("resource", secret.Data["resource"])
	d.Set("environment", secret.Data["environment"])
	return nil
}

func azureAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	config := meta.(*api.Client)

	log.Printf("[DEBUG] Deleting Azure auth backend config from %q", d.Id())
	_, err := config.Logical().Delete(d.Id())
	if err != nil {
		return fmt.Errorf("error deleting Azure auth backend config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted Azure auth backend config from %q", d.Id())

	return nil
}

func azureAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	config := meta.(*api.Client)

	log.Printf("[DEBUG] Checking if Azure auth backend is configured at %q", d.Id())
	secret, err := config.Logical().Read(d.Id())
	if err != nil {
		return true, fmt.Errorf("error checking if Azure auth backend is configured at %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Checked if Azure auth backend is configured at %q", d.Id())
	return secret != nil, nil
}

func azureAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}
