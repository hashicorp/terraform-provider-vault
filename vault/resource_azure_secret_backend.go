package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func azureSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: azureSecretBackendCreate,
		Read:   azureSecretBackendRead,
		Update: azureSecretBackendUpdate,
		Delete: azureSecretBackendDelete,
		Exists: azureSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "azure",
				Description: "Path to mount the backend at.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, fmt.Errorf("path cannot end in '/'"))
					}
					return
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"subscription_id": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Required:    true,
				Sensitive:   true,
				Description: "The subscription id for the Azure Active Directory.",
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
			"environment": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "AzurePublicCloud",
				Description: "The Azure cloud environment. Valid values: AzurePublicCloud, AzureUSGovernmentCloud, AzureChinaCloud, AzureGermanCloud.",
			},
		},
	}
}

func azureSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	description := d.Get("description").(string)
	tenantID := d.Get("tenant_id").(string)
	clientID := d.Get("client_id").(string)
	clientSecret := d.Get("client_secret").(string)
	environment := d.Get("environment").(string)
	subscriptionID := d.Get("subscription_id").(string)

	configPath := azureSecretBackendPath(path)

	data := map[string]interface{}{
		"tenant_id":       tenantID,
		"client_id":       clientID,
		"client_secret":   clientSecret,
		"environment":     environment,
		"subscription_id": subscriptionID,
	}

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Azure backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        "azure",
		Description: description,
		Config:      api.MountConfigInput{},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted Azure backend at %q", path)
	d.SetId(path)

	d.SetPartial("path")

	log.Printf("[DEBUG] Writing Azure configuration to %q", configPath)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error writing Azure configuration for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Azure configuration to %q", configPath)
	d.Partial(false)

	return azureSecretBackendRead(d, meta)
}

func azureSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading Azure backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Azure backend mount %q from Vault", path)

	// the API always returns the path with a trailing slash, so let's make
	// sure we always specify it as a trailing slash.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read Azure secret Backend config %s", path)
	resp, err := client.Logical().Read(azureSecretBackendPath(path))
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	if v, ok := resp.Data["client_id"].(string); ok {
		d.Set("client_id", v)
	}
	if v, ok := resp.Data["subscription_id"].(string); ok {
		d.Set("subscription_id", v)
	}
	if v, ok := resp.Data["tenant_id"].(string); ok {
		d.Set("tenant_id", v)
	}
	if v, ok := resp.Data["environment"].(string); ok && v != "" {
		d.Set("environment", v)
	} else {
		d.Set("environment", "AzurePublicCloud")
	}

	d.Set("path", path)
	d.Set("description", mount.Description)

	return nil
}

func azureSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	if d.HasChange("client_id") || d.HasChange("environment") || d.HasChange("tenant_id") || d.HasChange("client_secret") {
		log.Printf("[DEBUG] Updating Azure Backend Config at %q", azureSecretBackendPath(path))
		data := map[string]interface{}{
			"tenant_id":     d.Get("tenant_id").(string),
			"client_id":     d.Get("client_id").(string),
			"client_secret": d.Get("client_secret").(string),
		}

		environment := d.Get("environment").(string)
		if environment != "" {
			data["environment"] = environment
		}

		_, err := client.Logical().Write(azureSecretBackendPath(path), data)
		if err != nil {
			return fmt.Errorf("error writing config for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated Azure Backend Config at %q", azureSecretBackendPath(path))
	}
	return azureSecretBackendRead(d, meta)
}

func azureSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Azure backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting Azure backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Azure backend %q", path)
	return nil
}

func azureSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := d.Id()
	log.Printf("[DEBUG] Checking if Azure backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if Azure backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}

func azureSecretBackendPath(path string) string {
	return strings.Trim(path, "/") + "/config"
}
