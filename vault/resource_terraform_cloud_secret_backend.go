package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func terraformCloudSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: terraformCloudSecretBackendCreate,
		Read:   terraformCloudSecretBackendRead,
		Update: terraformCloudSecretBackendUpdate,
		Delete: terraformCloudSecretBackendDelete,
		Exists: terraformCloudSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "terraform",
				Description: "Unique name of the Vault Terraform Cloud mount to configure",
				StateFunc: func(s interface{}) string {
					return strings.Trim(s.(string), "/")
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the Terraform Cloud access token to use.",
				Sensitive:   true,
			},
			"address": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "https://app.terraform.io",
				Description: "Specifies the address of the Terraform Cloud instance, provided as \"host:port\" like \"127.0.0.1:8500\".",
			},
			"base_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "/api/v2/",
				Description: "Specifies the base path for the Terraform Cloud or Enterprise API.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Human-friendly description of the mount for the backend.",
			},
			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     "0",
				Description: "Maximum possible lease duration for secrets in seconds",
			},
		},
	}
}

func terraformCloudSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	address := d.Get("address").(string)
	token := d.Get("token").(string)
	basePath := d.Get("base_path").(string)

	configPath := terraformCloudSecretBackendConfigPath(path)

	info := &api.MountInput{
		Type:        "terraform",
		Description: d.Get("description").(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		},
	}

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Terraform Cloud backend at %q", path)

	if err := client.Sys().Mount(path, info); err != nil {
		return fmt.Errorf("Error mounting to %q: %s", path, err)
	}

	log.Printf("[DEBUG] Mounted Terraform Cloud backend at %q", path)
	d.SetId(path)

	d.SetPartial("path")
	d.SetPartial("description")
	d.SetPartial("default_lease_ttl_seconds")
	d.SetPartial("max_lease_ttl_seconds")

	log.Printf("[DEBUG] Writing Terraform Cloud configuration to %q", configPath)
	data := map[string]interface{}{
		"address":   address,
		"token":     token,
		"base_path": basePath,
	}
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("Error writing Terraform Cloud configuration for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote Terraform Cloud configuration to %q", configPath)
	d.SetPartial("address")
	d.SetPartial("token")
	d.SetPartial("base_path")
	d.Partial(false)

	return nil
}

func terraformCloudSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	configPath := terraformCloudSecretBackendConfigPath(path)

	log.Printf("[DEBUG] Reading Terraform Cloud backend mount %q from Vault", path)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("Error reading mount %q: %s", path, err)
	}

	// path can have a trailing slash, but doesn't need to have one
	// this standardises on having a trailing slash, which is how the
	// API always responds.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	d.Set("path", path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)

	log.Printf("[DEBUG] Reading %s from Vault", configPath)
	secret, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] secret: %#v", secret)

	// token, sadly, we can't read out
	// the API doesn't support it
	// So... if it drifts, it drift.
	d.Set("address", secret.Data["address"].(string))
	d.Set("base_path", secret.Data["base_path"].(string))

	return nil
}

func terraformCloudSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	configPath := terraformCloudSecretBackendConfigPath(path)

	d.Partial(true)

	if d.HasChange("default_lease_ttl_seconds") || d.HasChange("max_lease_ttl_seconds") {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		}

		log.Printf("[DEBUG] Updating lease TTLs for %q", path)
		if err := client.Sys().TuneMount(path, config); err != nil {
			return fmt.Errorf("Error updating mount TTLs for %q: %s", path, err)
		}

		d.SetPartial("default_lease_ttl_seconds")
		d.SetPartial("max_lease_ttl_seconds")
	}
	if d.HasChange("address") || d.HasChange("token") || d.HasChange("base_path") {
		log.Printf("[DEBUG] Updating Terraform Cloud configuration at %q", configPath)
		data := map[string]interface{}{
			"address":   d.Get("address").(string),
			"token":     d.Get("token").(string),
			"base_path": d.Get("base_path").(string),
		}
		if _, err := client.Logical().Write(configPath, data); err != nil {
			return fmt.Errorf("Error configuring Terraform Cloud configuration for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated Terraform Cloud configuration at %q", configPath)
		d.SetPartial("address")
		d.SetPartial("token")
		d.SetPartial("base_path")
	}
	d.Partial(false)
	return terraformCloudSecretBackendRead(d, meta)
}

func terraformCloudSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting Terraform Cloud backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("Error unmounting Terraform Cloud backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted Terraform Cloud backend %q", path)
	return nil
}

func terraformCloudSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Checking if Terraform Cloud backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("Error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if Terraform Cloud backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}

func terraformCloudSecretBackendConfigPath(backend string) string {
	return strings.Trim(backend, "/") + "/config"
}
