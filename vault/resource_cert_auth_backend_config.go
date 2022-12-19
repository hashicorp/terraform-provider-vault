package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func certAuthBackendConfigResource() *schema.Resource {
	return &schema.Resource{
		Create: certAuthBackendWrite,
		Read:   ReadWrapper(certAuthBackendRead),
		Update: certAuthBackendWrite,
		Delete: certAuthBackendDelete,
		Exists: certAuthBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the auth backend to configure.",
				ForceNew:    true,
				Default:     "cert",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"disable_binding": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, during renewal, skips the matching of presented client identity with the client identity used during login.",
				Default:     false,
			},
			"enable_identity_alias_metadata": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "If set, metadata of the certificate including the metadata corresponding to allowed_metadata_extensions will be stored in the alias",
				Default:     false,
			},
		},
	}
}

func certAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	// if backend comes from the config, it won't have the StateFunc
	// applied yet, so we need to apply it again.
	backend := d.Get("backend").(string)
	disable_binding := d.Get("disable_binding").(bool)
	enable_identity_alias_metadata := d.Get("enable_identity_alias_metadata").(bool)

	path := certAuthBackendConfigPath(backend)

	data := map[string]interface{}{
		"disable_binding":                disable_binding,
		"enable_identity_alias_metadata": enable_identity_alias_metadata,
	}

	log.Printf("[DEBUG] Writing cert auth backend config to %q", path)
	_, err := config.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote cert auth backend config to %q", path)

	d.SetId(path)

	return certAuthBackendRead(d, meta)
}

func certAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	log.Printf("[DEBUG] Reading cert auth backend config")
	secret, err := config.Logical().Read(d.Id())
	if err != nil {
		return fmt.Errorf("error reading cert auth backend config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Read cert auth backend config")

	if v, ok := secret.Data["disable_binding"]; ok {
		d.Set("disable_binding", v)
	}
	if v, ok := secret.Data["enable_identity_alias_metadata"]; ok {
		d.Set("enable_identity_alias_metadata", v)
	}
	return nil
}

func certAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	log.Printf("[DEBUG] Deleting cert auth backend config from %q", d.Id())
	_, err := config.Logical().Delete(d.Id())
	if err != nil {
		return fmt.Errorf("error deleting cert auth backend config from %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Deleted cert auth backend config from %q", d.Id())

	return nil
}

func certAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	config, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}
	log.Printf("[DEBUG] Checking if cert auth backend is configured at %q", d.Id())
	secret, err := config.Logical().Read(d.Id())
	if err != nil {
		return true, fmt.Errorf("error checking if cert auth backend is configured at %q: %s", d.Id(), err)
	}
	log.Printf("[DEBUG] Checked if certAuthBackendRead auth backend is configured at %q", d.Id())
	return secret != nil, nil
}

func certAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}
