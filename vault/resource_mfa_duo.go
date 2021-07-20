package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func mfaDuoResource() *schema.Resource {
	return &schema.Resource{
		Create: mfaDuoWrite,
		Update: mfaDuoWrite,
		Delete: mfaDuoDelete,
		Read:   mfaDuoRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Name of the MFA method.",
				ValidateFunc: validateNoTrailingSlash,
			},
			"mount_accessor": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The mount to tie this method to for use in automatic mappings. The mapping will use the Name field of Aliases associated with this mount as the username in the mapping.",
			},
			"username_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A format string for mapping Identity names to MFA method names. Values to substitute should be placed in `{{}}`.",
			},
			"secret_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Secret key for Duo.",
			},
			"integration_key": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Integration key for Duo.",
			},
			"api_hostname": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "API hostname for Duo.",
			},
			"push_info": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Push information for Duo.",
			},
		},
	}
}

func mfaDuoWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	data := map[string]interface{}{}
	mfaDuoUpdateFields(d, data)

	log.Printf("[DEBUG] Writing role %q to MFA Duo auth backend", name)
	d.SetId(name)

	log.Printf("[DEBUG] Creating mfaDuo %s in Vault", name)
	_, err := client.Logical().Write(mfaDuoPath(name), data)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	return mfaDuoRead(d, meta)
}

func mfaDuoDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	log.Printf("[DEBUG] Deleting mfaDuo %s from Vault", mfaDuoPath(name))

	_, err := client.Logical().Delete(mfaDuoPath(name))

	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func mfaDuoRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	resp, err := client.Logical().Read(mfaDuoPath(name))

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] Read MFA Duo config %q", mfaDuoPath(name))

	d.Set("mount_accessor", resp.Data["mount_accessor"])
	d.Set("username_format", resp.Data["username_format"])
	d.Set("api_hostname", resp.Data["api_hostname"])

	// When you push the data up, it's push_info
	// when vault responds, it's pushinfo :(
	d.Set("push_info", resp.Data["pushinfo"])

	// secret_key and integration_key, can't read out from the api
	// So... if it drifts, it drift.

	d.SetId(name)

	return nil
}

func mfaDuoUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk("mount_accessor"); ok {
		data["mount_accessor"] = v.(string)
	}

	if v, ok := d.GetOk("username_format"); ok {
		data["username_format"] = v.(string)
	}

	if v, ok := d.GetOk("secret_key"); ok {
		data["secret_key"] = v.(string)
	}

	if v, ok := d.GetOk("integration_key"); ok {
		data["integration_key"] = v.(string)
	}

	if v, ok := d.GetOk("api_hostname"); ok {
		data["api_hostname"] = v.(string)
	}

	if v, ok := d.GetOk("push_info"); ok {
		data["push_info"] = v.(string)
	}

}

func mfaDuoPath(name string) string {
	return "sys/mfa/method/duo/" + strings.Trim(name, "/") + "/"
}
