package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func authBackendResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: authBackendWrite,
		Delete: authBackendDelete,
		Read:   authBackendRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		MigrateState: resourceAuthBackendMigrateState,

		Schema: map[string]*schema.Schema{
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the auth backend",
			},

			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "path to mount the backend. This defaults to the type.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, errors.New("cannot write to a path ending in '/'"))
					}
					return
				},
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},

			"description": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},
		},
	}
}

func authBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("type").(string)
	desc := d.Get("description").(string)
	path := d.Get("path").(string)

	if path == "" {
		path = name
	}

	log.Printf("[DEBUG] Writing auth %q to Vault", path)

	err := client.Sys().EnableAuth(path, name, desc)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return authBackendRead(d, meta)
}

func authBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	err := client.Sys().DisableAuth(path)

	if err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func authBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	targetPath := d.Id() + "/"

	auths, err := client.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for path, auth := range auths {
		if path == targetPath {
			d.Set("type", auth.Type)
			d.Set("path", path)
			d.Set("description", auth.Description)
			d.Set("accessor", auth.Accessor)
			return nil
		}
	}

	// If we fell out here then we didn't find our Auth in the list.
	d.SetId("")
	return nil
}
