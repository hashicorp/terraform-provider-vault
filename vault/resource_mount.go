package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func MountResource() *schema.Resource {
	return &schema.Resource{
		Create: mountWrite,
		Update: mountUpdate,
		Delete: mountDelete,
		Read:   mountRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    false,
				Description: "Where the secret backend will be mounted",
			},

			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Type of the backend, such as 'aws'",
			},

			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Required:    false,
				ForceNew:    false,
				Description: "Human-friendly description of the mount",
			},

			"default_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Computed:    true,
				ForceNew:    false,
				Description: "Default lease duration for tokens and secrets in seconds",
			},

			"max_lease_ttl_seconds": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Computed:    true,
				ForceNew:    false,
				Description: "Maximum possible lease duration for tokens and secrets in seconds",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Accessor of the mount",
			},

			"local": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Computed:    false,
				ForceNew:    true,
				Description: "Local mount flag that can be explicitly set to true to enforce local mount in HA environment",
			},

			"options": {
				Type:        schema.TypeMap,
				Required:    false,
				Optional:    true,
				Computed:    false,
				ForceNew:    false,
				Description: "Specifies mount type specific options that are passed to the backend",
			},

			"seal_wrap": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Enable seal wrapping for the mount, causing values stored by the mount to be wrapped by the seal's encryption capability",
			},

			"external_entropy_access": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				ForceNew:    true,
				Description: "Enable the secrets engine to access Vault's external entropy source",
			},
		},
	}
}

func mountWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	info := &api.MountInput{
		Type:        d.Get("type").(string),
		Description: d.Get("description").(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		},
		Local:                 d.Get("local").(bool),
		Options:               opts(d),
		SealWrap:              d.Get("seal_wrap").(bool),
		ExternalEntropyAccess: d.Get("external_entropy_access").(bool),
	}

	path := d.Get("path").(string)

	log.Printf("[DEBUG] Creating mount %s in Vault", path)

	if err := client.Sys().Mount(path, info); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return mountRead(d, meta)
}

func mountUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	config := api.MountConfigInput{
		DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
		MaxLeaseTTL:     fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
		Options:         opts(d),
	}

	if d.HasChange("description") {
		description := fmt.Sprintf("%s", d.Get("description"))
		config.Description = &description
	}

	path := d.Id()

	if d.HasChange("path") {
		newPath := d.Get("path").(string)

		log.Printf("[DEBUG] Remount %s to %s in Vault", path, newPath)

		err := client.Sys().Remount(d.Id(), newPath)
		if err != nil {
			return fmt.Errorf("error remounting in Vault: %s", err)
		}

		d.SetId(newPath)
		path = newPath
	}

	log.Printf("[DEBUG] Updating mount %s in Vault", path)

	if err := client.Sys().TuneMount(path, config); err != nil {
		return fmt.Errorf("error updating Vault: %s", err)
	}

	return mountRead(d, meta)
}

func mountDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Unmounting %s from Vault", path)

	if err := client.Sys().Unmount(path); err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func mountRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Reading mount %s from Vault", path)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
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

	cfgType := d.Get("type").(string)

	// kv-v2 is an alias for kv, version 2. Vault will report it back as "kv"
	// and requires special handling to avoid perpetual drift.
	if cfgType == "kv-v2" && mount.Type == "kv" && mount.Options["version"] == "2" {
		mount.Type = "kv-v2"

		// The options block may be omitted when specifying kv-v2, but will always
		// be present in Vault's response if version 2. Omit the version setting
		// if it wasn't explicitly set in config.
		if opts(d)["version"] == "" {
			delete(mount.Options, "version")
		}
	}

	d.Set("path", path)
	d.Set("type", mount.Type)
	d.Set("description", mount.Description)
	d.Set("default_lease_ttl_seconds", mount.Config.DefaultLeaseTTL)
	d.Set("max_lease_ttl_seconds", mount.Config.MaxLeaseTTL)
	d.Set("accessor", mount.Accessor)
	d.Set("local", mount.Local)
	d.Set("options", mount.Options)
	d.Set("seal_wrap", mount.SealWrap)
	d.Set("external_entropy_access", mount.ExternalEntropyAccess)

	return nil
}

func opts(d *schema.ResourceData) map[string]string {
	options := map[string]string{}
	if opts, ok := d.GetOk("options"); ok {
		for k, v := range opts.(map[string]interface{}) {
			options[k] = v.(string)
		}
	}
	return options
}
