package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
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
			"path": {
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
			"access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The AWS Access Key ID to use when generating new credentials.",
				Sensitive:   true,
			},
			"secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The AWS Secret Access Key to use when generating new credentials.",
				Sensitive:   true,
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The AWS region to make API calls against. Defaults to us-east-1.",
			},
			"iam_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a custom HTTP IAM endpoint to use.",
			},
			"sts_endpoint": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a custom HTTP STS endpoint to use.",
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
	iamEndpoint := d.Get("iam_endpoint").(string)
	stsEndpoint := d.Get("sts_endpoint").(string)

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
		return fmt.Errorf("error mounting to %q: %s", path, err)
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
	if iamEndpoint != "" {
		data["iam_endpoint"] = iamEndpoint
	}
	if stsEndpoint != "" {
		data["sts_endpoint"] = stsEndpoint
	}
	_, err = client.Logical().Write(path+"/config/root", data)
	if err != nil {
		return fmt.Errorf("error configuring root credentials for %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote root credentials to %q", path+"/config/root")
	d.SetPartial("access_key")
	d.SetPartial("secret_key")
	if region == "" {
		d.Set("region", "us-east-1")
	}
	d.SetPartial("region")
	if iamEndpoint != "" {
		d.SetPartial("iam_endpoint")
	}
	if stsEndpoint != "" {
		d.SetPartial("sts_endpoint")
	}
	d.Partial(false)

	return awsSecretBackendRead(d, meta)
}

func awsSecretBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading AWS backend mount %q from Vault", path)
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mount %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read AWS backend mount %q from Vault", path)

	// the API always returns the path with a trailing slash, so let's make
	// sure we always specify it as a trailing slash.
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok {
		log.Printf("[WARN] Mount %q not found, removing backend from state.", path)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read AWS secret backend config/root %s", path)
	resp, err := client.Logical().Read(path + "/config/root")
	if err != nil {
		// This is here to support backwards compatibility with Vault. Read operations on the config/root
		// endpoint were just added and haven't been released yet, and so in currently released versions
		// the read operations return a 405 error. We'll gracefully revert back to the old behavior in that
		// case to allow for a transition period.
		respErr, ok := err.(*api.ResponseError)
		if !ok || respErr.StatusCode != 405 {
			return fmt.Errorf("error reading AWS secret backend config/root: %s", err)
		}
		log.Printf("[DEBUG] Unable to read config/root due to old version detected; skipping reading access_key and region parameters")
		resp = nil
	}
	if resp != nil {
		if v, ok := resp.Data["access_key"].(string); ok {
			d.Set("access_key", v)
		}
		// Terrible backwards compatibility hack. Previously, if no region was specified,
		// this provider would just write a region of "us-east-1" into its state. Now that
		// we're actually reading the region out from the backend, if it hadn't been set,
		// it will return an empty string. This could potentially cause unexpected diffs
		// for users of the provider, so to avoid it, we're doing something similar here
		// and injecting a fake region of us-east-1 into the state.
		if v, ok := resp.Data["region"].(string); ok && v != "" {
			d.Set("region", v)
		} else {
			d.Set("region", "us-east-1")
		}

		if v, ok := resp.Data["iam_endpoint"].(string); ok {
			d.Set("iam_endpoint", v)
		}
		if v, ok := resp.Data["sts_endpoint"].(string); ok {
			d.Set("sts_endpoint", v)
		}
	}

	d.Set("path", path)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)

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
			return fmt.Errorf("error updating mount TTLs for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated lease TTLs for %q", path)
		d.SetPartial("default_lease_ttl_seconds")
		d.SetPartial("max_lease_ttl_seconds")
	}
	if d.HasChange("access_key") || d.HasChange("secret_key") || d.HasChange("region") || d.HasChange("iam_endpoint") || d.HasChange("sts_endpoint") {
		log.Printf("[DEBUG] Updating root credentials at %q", path+"/config/root")
		data := map[string]interface{}{
			"access_key": d.Get("access_key").(string),
			"secret_key": d.Get("secret_key").(string),
		}
		region := d.Get("region").(string)
		iamEndpoint := d.Get("iam_endpoint").(string)
		stsEndpoint := d.Get("sts_endpoint").(string)
		if region != "" {
			data["region"] = region
		}
		if iamEndpoint != "" {
			data["iam_endpoint"] = iamEndpoint
		}
		if stsEndpoint != "" {
			data["sts_endpoint"] = stsEndpoint
		}
		_, err := client.Logical().Write(path+"/config/root", data)
		if err != nil {
			return fmt.Errorf("error configuring root credentials for %q: %s", path, err)
		}
		log.Printf("[DEBUG] Updated root credentials at %q", path+"/config/root")
		d.SetPartial("access_key")
		d.SetPartial("secret_key")
		if region == "" {
			d.Set("region", "us-east-1")
		}
		d.SetPartial("region")
		if iamEndpoint != "" {
			d.SetPartial("iam_endpoint")
		}
		if stsEndpoint != "" {
			d.SetPartial("sts_endpoint")
		}
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
		return fmt.Errorf("error unmounting AWS backend from %q: %s", path, err)
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
		return true, fmt.Errorf("error retrieving list of mounts: %s", err)
	}
	log.Printf("[DEBUG] Checked if AWS backend exists at %q", path)
	_, ok := mounts[strings.Trim(path, "/")+"/"]
	return ok, nil
}
