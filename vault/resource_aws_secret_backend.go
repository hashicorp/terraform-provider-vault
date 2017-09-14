package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func awsSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: awsSecretBackendCreate,
		Read:   awsSecretBackendRead,
		Update: awsSecretBackendUpdate,
		Delete: awsSecretBackendDelete,
		Exists: awsSecretBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "aws",
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
			"access_key": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The AWS Access Key ID to use when generating new credentials.",
				Sensitive:   true,
			},
			"secret_key": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The AWS Secret Access Key to use when generating new credentials.",
				Sensitive:   true,
			},
			"region": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The AWS region to make API calls against. Defaults to us-east-1.",
			},
		},
	}
}

func awsSecretBackendCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)
	description := d.Get("description").(string)
	defaultTTL := d.Get("default_lease_ttl_seconds").(int)
	maxTTL := d.Get("max_lease_ttl_seconds").(int)
	accessKey := d.Get("access_key").(string)
	secretKey := d.Get("secret_key").(string)
	region := d.Get("region").(string)

	d.Partial(true)
	log.Printf("[DEBUG] Mounting AWS backend at %q", path)
	err := client.Sys().Mount(path, &api.MountInput{
		Type:        "aws",
		Description: description,
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", defaultTTL),
			MaxLeaseTTL:     fmt.Sprintf("%ds", maxTTL),
		},
	})
	if err != nil {
		return fmt.Errorf("Error mounting to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Mounted AWS backend at %q", path)
	d.SetId(path)

	d.SetPartial("path")
	d.SetPartial("description")
	d.SetPartial("default_lease_ttl_seconds")
	d.SetPartial("max_lease_ttl_seconds")

	log.Printf("[DEBUG] Writing root credentials to %q", path+"/config/root")
	data := map[string]interface{}{
		"access_key": accessKey,
		"secret_key": secretKey,
	}
	if region != "" {
		data["region"] = region
	}
	_, err = client.Logical().Write(path+"/config/root", data)
	if err != nil {
		return fmt.Errorf("Error configuring root credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote root credentials to %q", path+"/config/root")
	d.SetPartial("access_key")
	d.SetPartial("secret_key")
	if region == "" {
		d.Set("region", "us-east-1")
	}
	d.SetPartial("region")
	d.Partial(false)

	return awsSecretBackendRead(d, meta)
}

func awsSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading AWS backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("Error reading mount %q: %s", path, err)
	}

	// the API always returns the path with a trailing slash, so let's make
	// sure we always specify it as a trailing slash.
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

	// access key, secret key, and region, sadly, we can't read out
	// the API doesn't support it
	// So... if they drift, they drift.

	return nil
}

func awsSecretBackendUpdate(d *schema.ResourceData, meta interface{}) error {
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
			return fmt.Errorf("Error updating mount TTLs for %q: %s", path, err)
		}
		d.SetPartial("default_lease_ttl_seconds")
		d.SetPartial("max_lease_ttl_seconds")
	}
	if d.HasChange("access_key") || d.HasChange("secret_key") || d.HasChange("region") {
		log.Printf("[DEBUG] Updating root credentials at %q", path+"/config/root")
		data := map[string]interface{}{
			"access_key": d.Get("access_key").(string),
			"secret_key": d.Get("secret_key").(string),
		}
		region := d.Get("region").(string)
		if region != "" {
			data["region"] = region
		}
		_, err := client.Logical().Write(path+"/config/root", data)
		if err != nil {
			return fmt.Errorf("Error configuring root credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated root credentials at %q", path+"/config/root")
		d.SetPartial("access_key")
		d.SetPartial("secret_key")
		if region == "" {
			d.Set("region", "us-east-1")
		}
		d.SetPartial("region")
	}
	d.Partial(false)
	return awsSecretBackendRead(d, meta)
}

func awsSecretBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting AWS backend %q", path)
	err := client.Sys().Unmount(path)
	if err != nil {
		return fmt.Errorf("Error unmounting AWS backend from %q: %s", path, err)
	}
	log.Printf("[DEBUG] Unmounted AWS backend %q", path)
	return nil
}

func awsSecretBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := d.Id()
	log.Printf("[DEBUG] Checking if AWS backend exists at %q", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return true, fmt.Errorf("Error retrieving list of mounts: %s", err)
	}
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}
