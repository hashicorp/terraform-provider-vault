package vault

import (
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func namespaceResource() *schema.Resource {
	return &schema.Resource{
		Create: namespaceWrite,
		Update: namespaceWrite,
		Delete: namespaceDelete,
		Read:   namespaceRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path of the namespace.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, errors.New("cannot write to a path ending in '/'"))
					}
					return
				},
			},
		},
	}
}

func namespaceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	log.Printf("[DEBUG] Creating namespace %s in Vault", path)
	_, err := client.Logical().Write("sys/namespaces/"+path, nil)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	return namespaceRead(d, meta)
}

func namespaceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	log.Printf("[DEBUG] Deleting namespace %s from Vault", path)

	_, err := client.Logical().Delete("sys/namespaces/" + path)

	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func namespaceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	resp, err := client.Logical().Read("sys/namespaces/" + path)

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	// remove trailing slash
	namespacePath := filepath.Clean(resp.Data["path"].(string))

	d.Set("path", namespacePath)
	d.SetId(resp.Data["id"].(string))

	return nil
}
