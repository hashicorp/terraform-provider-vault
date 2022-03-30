package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func mfaPingIDResource() *schema.Resource {
	return &schema.Resource{
		Create: mfaPingIDWrite,
		Update: mfaPingIDWrite,
		Delete: mfaPingIDDelete,
		Read:   mfaPingIDRead,
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
				Type:     schema.TypeString,
				Required: true,
				Description: "The mount to tie this method to for use in automatic mappings. " +
					"The mapping will use the Name field of Aliases associated with this mount as the username in the mapping.",
			},
			"username_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A format string for mapping Identity names to MFA method names. Values to substitute should be placed in `{{}}`.",
			},
			"settings_file_base64": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "A base64-encoded third-party settings file retrieved from PingID's configuration page.",
			},
		},
	}
}

func mfaPingIDPath(name string) string {
	return "sys/mfa/method/pingid/" + strings.Trim(name, "/")
}

func mfaPingIDRequestData(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}

	// Read does not return any API Fields listed in docs
	// TODO confirm expected behavior
	fields := []string{
		"name", "mount_accessor", "settings_file_base64",
	}

	for _, k := range fields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	return data
}

func mfaPingIDWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := mfaPingIDPath(name)

	log.Printf("[DEBUG] Creating mfaPingID %s in Vault", name)
	_, err := client.Logical().Write(path, mfaPingIDRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing to Vault at %s, err=%w", path, err)
	}

	d.SetId(path)

	return mfaPingIDRead(d, meta)
}

func mfaPingIDRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading MFA PingID config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault at %s, err=%w", path, err)
	}

	fields := []string{
		"name", "mount_accessor", "username_format",
		"settings_file_base64",
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return err
		}
	}

	return nil
}

func mfaPingIDDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting mfaPingID %s from Vault", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting from Vault at %s, err=%w", path, err)
	}

	return nil
}
