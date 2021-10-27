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
			"config": mountConfigSchema(),
		},
	}
}

func mountWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	var config api.MountConfigInput
	if rawConfig, ok := d.GetOk("config"); ok {
		config = expandMountConfigInput(rawConfig.(*schema.Set).List())
	}

	info := &api.MountInput{
		Type:                  d.Get("type").(string),
		Description:           d.Get("description").(string),
		Config:                config,
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
	var config api.MountConfigInput
	var tuneChange = false
	if rawConfig, ok := d.GetOk("config"); ok {
		config = expandMountConfigInput(rawConfig.(*schema.Set).List())
	}
	if d.HasChange("description") {
		description := fmt.Sprintf("%s", d.Get("description"))
		config.Description = &description
		tuneChange = true
	}
	if d.HasChange("options") {
		config.Options = opts(d)
		tuneChange = true
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
	if d.HasChange("config") || tuneChange {
		if err := client.Sys().TuneMount(path, config); err != nil {
			return fmt.Errorf("error updating Vault: %s", err)
		}
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
	d.Set("accessor", mount.Accessor)
	d.Set("local", mount.Local)
	d.Set("options", mount.Options)
	d.Set("seal_wrap", mount.SealWrap)
	d.Set("external_entropy_access", mount.ExternalEntropyAccess)
	rawConfig, err := mountConfigGet(client, path)
	if err != nil {
		return fmt.Errorf("error reading tune information from Vault: %s", err)
	}
	if err := d.Set("config", []map[string]interface{}{rawConfig}); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path '%q/tune' to state: %s", path, err)
		return err
	}

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

func mountConfigGet(client *api.Client, path string) (map[string]interface{}, error) {
	tune, err := client.Sys().MountConfig(path)
	if err != nil {
		log.Printf("[ERROR] Error when reading tune config from path %q: %s", path+"/tune", err)
		return nil, err
	}
	return flattenMountConfig(tune), nil
}
