package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func transitSecretBackendCacheConfig() *schema.Resource {
	return &schema.Resource{
		Create: transitSecretBackendCacheConfigUpdate,
		Update: transitSecretBackendCacheConfigUpdate,
		Read:   transitSecretBackendCacheConfigRead,
		Delete: transitSecretBackendCacheConfigDelete,

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Transit secret backend the resource belongs to.",
				ForceNew:    true,
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"size": {
				Type:        schema.TypeInt,
				Description: "Number of cache entries. A size of 0 mean unlimited.",
				Required:    true,
			},
		},
	}
}

func transitSecretBackendCacheConfigUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	size := d.Get("size").(int)

	backend := d.Get("backend").(string) + "/cache-config"

	log.Printf("[DEBUG] Setting transit cache size to: %d", size)

	data := map[string]interface{}{
		"size": size,
	}
	_, err := client.Logical().Write(backend, data)
	if err != nil {
		return fmt.Errorf("error writing transit cache-config: %v", err)
	}
	log.Printf("[DEBUG] Set transit cache size")
	d.SetId(backend)

	data = map[string]interface{}{
		"mounts": []string{d.Get("backend").(string) + "/"},
	}
	_, err = client.Logical().Write("sys/plugins/reload/backend", data)
	if err != nil {
		return fmt.Errorf("error reloading transit plugin: %v", err)
	}

	return transitSecretBackendCacheConfigRead(d, meta)
}

func transitSecretBackendCacheConfigRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Id()

	secret, err := client.Logical().Read(backend)
	if err != nil {
		return fmt.Errorf("error reading transit cache-config: %v", err)
	}

	if secret == nil {
		log.Printf("[WARN] transit cache-config not found, removing from state")
		d.SetId("")
		return nil
	}

	d.Set("size", secret.Data["size"])

	return nil
}

func transitSecretBackendCacheConfigDelete(d *schema.ResourceData, meta interface{}) error {
	// Deleting the cache configuration is not supported in the Vault API
	return nil
}
