package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func mfaOktaResource() *schema.Resource {
	return &schema.Resource{
		Create: mfaOktaWrite,
		Update: mfaOktaWrite,
		Delete: mfaOktaDelete,
		Read:   mfaOktaRead,
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
			"org_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the organization to be used in the Okta API.",
			},
			"api_token": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Okta API key.",
			},
			"base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "If set, will be used as the base domain for API requests.",
			},
			"primary_email": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "If set, the username will only match the primary email for the account.",
			},
		},
	}
}

func mfaOktaPath(name string) string {
	return "sys/mfa/method/okta/" + strings.Trim(name, "/")
}

func mfaOktaRequestData(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}

	nonBooleanAPIFields := []string{
		"name", "mount_accessor", "username_format",
		"org_name", "api_token", "base_url",
	}

	if v, ok := d.GetOkExists("primary_email"); ok {
		data["primary_email"] = v.(string)
	}

	for _, k := range nonBooleanAPIFields {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		}
	}

	return data
}

func mfaOktaWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := mfaOktaPath(name)

	log.Printf("[DEBUG] Creating mfaOkta %s in Vault", name)
	_, err := client.Logical().Write(path, mfaOktaRequestData(d))
	if err != nil {
		return fmt.Errorf("error writing to Vault at %s, err=%w", path, err)
	}

	d.SetId(path)

	return mfaOktaRead(d, meta)
}

func mfaOktaRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading MFA Okta config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault at %s, err=%w", path, err)
	}

	fields := []string{
		"name", "mount_accessor", "username_format",
		"org_name", "base_url", "primary_email",
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return err
		}
	}

	return nil
}

func mfaOktaDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting mfaOkta %s from Vault", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting from Vault at %s, err=%w", path, err)
	}

	return nil
}
