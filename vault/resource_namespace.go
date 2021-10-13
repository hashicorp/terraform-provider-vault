package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Path of the namespace.",
				ValidateFunc: validateNoTrailingSlash,
			},

			"namespace_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the namepsace.",
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

	upgradeNonPathdNamespaceID(d)

	path := d.Id()

	resp, err := client.Logical().Read("sys/namespaces/" + path)

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	if resp == nil {
		log.Printf("[WARN] Names %q not found, removing from state.", path)
		d.SetId("")
		return nil
	}

	d.SetId(resp.Data["path"].(string))
	d.Set("namespace_id", resp.Data["id"])

	noTrailingSlashPath := strings.TrimSuffix(path, "/")
	d.Set("path", noTrailingSlashPath)

	return nil
}

func upgradeNonPathdNamespaceID(d *schema.ResourceData) {
	// Upgrade ID to path
	id := d.Id()
	oldID := d.Id()
	path, ok := d.GetOk("path")
	if id != path && ok {
		log.Printf("[DEBUG] Upgrading old ID to path - %s to %s", id, path)
		d.SetId(path.(string))
		log.Printf("[DEBUG] Setting namespace_id to old ID - %s", oldID)
		d.Set("namespace_id", oldID)
	}
}
