package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func nomadSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: nomadSecretBackendCreate,
		Read:   nomadSecretBackendRead,
		Update: nomadSecretBackendUpdate,
		Delete: nomadSecretBackendDelete,
		Exists: nomadSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "nomad",
				ForceNew:    true,
				Description: "Unique name of the Vault Nomad mount to configure",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
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
				Computed:    true,
				Description: "Default lease duration for secrets in seconds",
			},
			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Maximum possible lease duration for secrets in seconds",
			},
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the address of the Nomad instance, provided as \"host:port\" like \"127.0.0.1:4646\".", //TODO: is 4646 the right port?
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the Nomad ACL token to use. This must be a management type token.",
				Sensitive:   true,
			},
		},
	}
}

func nomadSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)
	address := d.Get("address").(string)
	token := d.Get("token").(string)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting Nomad backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        "nomad",
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted Nomad backend at %q", path)
	d.SetId(path)

	d.SetPartial("path")
	d.SetPartial("description")
	d.SetPartial("default_lease_ttl_seconds")
	d.SetPartial("max_lease_ttl_seconds")

	log.Printf("[DEBUG] Writing connection credentials to %q", path+"/config/access")
	data := map[string]interface{}{
		"address": address,
		"token":   token,
	}
	_, err = client.Logical().Write(path+"/config/access", data)
	if err != nil {
		return fmt.Errorf("error configuring connection credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote connection credentials to %q", path+"/config/access")
	d.SetPartial("address")
	d.SetPartial("token")
	d.Partial(false)
	return nomadSecretBackendRead(d, meta)
}

func nomadSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading Nomad secret backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Nomad secret backend mount %q from Vault", path)
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}
	d.Set("path", path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)

	//TODO: What are the outputs? Can nomad return the token?

	return nil
}

func nomadSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	d.Partial(true)
	if d.HasChange("default_lease_ttl_seconds") || d.HasChange("max_lease_ttl_seconds") {
		config := api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		}
		log.Printf("[DEBUG] Updating lease TTLs for %q", path)
		err := client.Sys().TuneMount(path, config)
		if err != nil {
			return fmt.Errorf("error updating mount TTLs for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated lease TTLs for %q", path)
		d.SetPartial("default_lease_ttl_seconds")
		d.SetPartial("max_lease_ttl_seconds")
	}
	if d.HasChange("connection_uri") || d.HasChange("username") || d.HasChange("password") || d.HasChange("verify_connection") {
		log.Printf("[DEBUG] Updating connecion credentials at %q", path+"/config/access")
		data := map[string]interface{}{
			"connection_uri":    d.Get("connection_uri").(string),
			"username":          d.Get("username").(string),
			"password":          d.Get("password").(string),
			"verify_connection": d.Get("verify_connection").(bool),
		}
		_, err := client.Logical().Write(path+"/config/access", data)
		if err != nil {
			return fmt.Errorf("error configuring connection credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated root credentials at %q", path+"/config/access")
		d.SetPartial("connection_url")
		d.SetPartial("username")
		d.SetPartial("password")
		d.SetPartial("verify_connection")
	}
	d.Partial(false)
	return nomadSecretBackendRead(d, meta)
}

func nomadSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Unmounting RabbitMQ backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("error unmounting RabbitMQ backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted RabbitMQ backend %q", path)
	return nil
}

func nomadSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if RabbitMQ backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if RabbitMQ backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}
