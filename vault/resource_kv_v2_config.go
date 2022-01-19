package vault

import (
	"fmt"
	"log"
	"path"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

var kvV2ConfigDefaults = map[string]interface{}{
	"cas_required":         false,
	"max_versions":         "0",
	"delete_version_after": "0s",
}

func KvV2ConfigResource() *schema.Resource {
	return &schema.Resource{
		Create: kvV2ConfigWrite,
		Update: kvV2ConfigWrite,
		Delete: kvV2ConfigDelete,
		Read:   kvV2ConfigRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The kv-v2 backend mount point.",
			},
			"max_versions": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The number of versions to keep per key.",
				Default:     0,
			},
			"cas_required": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: " If true all keys will require the cas parameter to be set on all write requests.",
			},
			"delete_version_after": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "If set, specifies the length of time before a version is deleted. Accepts Go duration format string.",
				Default:     "0s",
			},
		},
	}
}

func kvV2ConfigWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	targetPath := d.Get("path").(string)
	c := map[string]interface{}{
		"max_versions":         d.Get("max_versions").(int),
		"cas_required":         d.Get("cas_required").(bool),
		"delete_version_after": d.Get("delete_version_after").(string),
	}
	err := checkKvV2Mount(client, targetPath)
	if err != nil {
		return err
	}
	apiPath := kvV2MountPathConfigPath(targetPath)
	_, err = client.Logical().Write(apiPath, c)
	if err != nil {
		return fmt.Errorf("error writing kv-v2 config to Vault: %s", err)
	}

	d.SetId(targetPath)
	if err := d.Set("path", targetPath); err != nil {
		return fmt.Errorf("error setting state key 'path': %s", err)
	}
	return kvV2ConfigRead(d, meta)
}

func kvV2ConfigDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	targetPath := d.Id()

	log.Printf("[DEBUG] Delete kv-v2 config for %s", targetPath)
	_, err := client.Logical().Write(kvV2MountPathConfigPath(targetPath), kvV2ConfigDefaults)
	if err != nil {
		return fmt.Errorf("error resetting kv-v2 config from Vault: %s", err)
	}

	return nil
}

func kvV2ConfigRead(d *schema.ResourceData, meta interface{}) error {
	targetPath := d.Id()
	return kvV2ConfigReadByPath(d, meta, targetPath)

}

func kvV2ConfigReadByPath(d *schema.ResourceData, meta interface{}, targetPath string) error {
	client := meta.(*api.Client)

	err := checkKvV2Mount(client, targetPath)
	if err != nil {
		return err
	}
	config, err := client.Logical().Read(kvV2MountPathConfigPath(targetPath))
	if err != nil {
		return fmt.Errorf("error reading kv-v2 config from Vault: %s", err)
	}
	if config.Data == nil {
		return fmt.Errorf("no config read from kv-v2 mount: %s", targetPath)
	}

	if val, ok := config.Data["max_versions"]; ok {
		if err := d.Set("max_versions", val); err != nil {
			return fmt.Errorf("error setting state key 'max_versions': %s", err)
		}
	}
	if val, ok := config.Data["cas_required"]; ok {
		if err := d.Set("cas_required", val); err != nil {
			return fmt.Errorf("error setting state key 'cas_required': %s", err)
		}
	}
	if val, ok := config.Data["delete_version_after"]; ok {
		if err := d.Set("delete_version_after", val); err != nil {
			return fmt.Errorf("error setting state key 'delete_version_after': %s", err)
		}
	}
	if err := d.Set("path", targetPath); err != nil {
		return fmt.Errorf("error setting state key 'path': %s", err)
	}
	d.SetId(targetPath)
	return nil

}

func checkKvV2Mount(client *api.Client, path string) error {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mounts from Vault: %s", err)
	}
	mount, ok := mounts[strings.Trim(path, "/")+"/"]
	if !ok || mount.Options["version"] != "2" {
		return fmt.Errorf("failed to read kv-v2 mount: %s", path)
	}
	return nil
}

func kvV2MountPathConfigPath(mountPath string) string {
	return path.Join(mountPath, "config")
}
