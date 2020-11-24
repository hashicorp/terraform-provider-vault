package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/terraform-providers/terraform-provider-vault/util"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	nomadSecretBackendFromPathRegex = regexp.MustCompile("^(.+)/config/lease")
)

func nomadSecretLeaseBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Default:     "nomad",
			ForceNew:    true,
			Optional:    true,
			Description: "The mount path for the Nomad backend.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
		"ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: "Maximum possible lease duration for secrets in seconds.",
		},
	}
	return &schema.Resource{
		Create: createNomadLeaseConfigResource,
		Update: updateNomadLeaseConfigResource,
		Read:   readNomadLeaseConfigResource,
		Delete: deleteNomadLeaseConfigResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createNomadLeaseConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	configPath := fmt.Sprintf("%s/config/lease", backend)

	log.Printf("[DEBUG] Creating %q", configPath)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("max_ttl"); ok {
		data["max_ttl"] = v
	}

	if v, ok := d.GetOkExists("ttl"); ok {
		data["ttl"] = v
	}

	log.Printf("[DEBUG] Writing %q", configPath)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", configPath, err)
	}
	d.SetId(configPath)
	log.Printf("[DEBUG] Wrote %q", configPath)
	return readNomadLeaseConfigResource(d, meta)
}

func readNomadLeaseConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	configPath := d.Id()
	log.Printf("[DEBUG] Reading %q", configPath)

	backend, err := nomadSecretBackendFromPath(configPath)
	if err != nil {
		return fmt.Errorf("invalid lease config ID %q: %s", configPath, err)
	}
	d.Set("backend", backend)

	resp, err := client.Logical().Read(configPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Read %q", configPath)

	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", configPath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["max_ttl"]; ok {
		if err := d.Set("max_ttl", val); err != nil {
			return fmt.Errorf("error setting state key 'max_ttl': %s", err)
		}
	}

	if val, ok := resp.Data["ttl"]; ok {
		if err := d.Set("ttl", val); err != nil {
			return fmt.Errorf("error setting state key 'ttl': %s", err)
		}
	}

	return nil
}

func updateNomadLeaseConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	configPath := d.Id()
	log.Printf("[DEBUG] Updating %q", configPath)

	data := map[string]interface{}{}
	if raw, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = raw
	}
	if raw, ok := d.GetOk("ttl"); ok {
		data["ttl"] = raw
	}
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return fmt.Errorf("error updating lease config %q: %s", configPath, err)
	}
	log.Printf("[DEBUG] Updated %q", configPath)
	return readNomadLeaseConfigResource(d, meta)
}

func deleteNomadLeaseConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	configPath := d.Id()
	log.Printf("[DEBUG] Deleting %q", configPath)

	if _, err := client.Logical().Delete(configPath); err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting %q: %s", configPath, err)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", configPath)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted lease config %q", configPath)
	return nil
}

func nomadSecretBackendFromPath(path string) (string, error) {
	if !nomadSecretBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := nomadSecretBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
