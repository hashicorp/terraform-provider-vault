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
		Create: mfaDuoCreate,
		Update: mfaDuoUpdate,
		Delete: mfaDuoDelete,
		Read:   mfaDuoRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "UUID identifying the MFA method.",
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
			"use_passcode": {
				Type:        schema.TypeBool,
				Default:     false,
				Optional:    true,
				Description: "If true, the user is reminded to use the passcode upon MFA validation.",
			},
		},
	}
}

func mfaDuoCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	data := map[string]interface{}{}
	mfaDuoUpdateFields(d, data)

	id := ""
	log.Printf("[DEBUG] Creating new mfaDuo method in Vault")
	resp, err := client.Logical().Write(mfaDuoPath(id), data)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}
	log.Printf("[DEBUG] Created new mfaDuo method in Vault")

	d.SetId(resp.Data["method_id"].(string))

	return mfaDuoRead(d, meta)
}

func mfaDuoUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	path := mfaDuoPath(id)
	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := map[string]interface{}{}
	mfaDuoUpdateFields(d, data)

	log.Printf("[DEBUG] Updating mfaDuo method %s in Vault", id)
	_, err := client.Logical().Write(mfaDuoPath(id), data)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}
	log.Printf("[DEBUG] Updated mfaDuo method %s in Vault", id)

	return mfaDuoRead(d, meta)
}

func mfaDuoDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	id := d.Id()

	log.Printf("[DEBUG] Deleting mfaDuo method %s from Vault", mfaDuoPath(id))

	_, err := client.Logical().Delete(mfaDuoPath(id))

	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func mfaDuoRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	id := d.Get("id").(string)

	resp, err := client.Logical().Read(mfaDuoPath(id))

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] Read MFA Duo method %q", mfaDuoPath(id))

	d.Set("id", resp.Data["id"])
	d.Set("username_format", resp.Data["username_format"])
	d.Set("api_hostname", resp.Data["api_hostname"])
	d.Set("use_passcode", resp.Data["use_passcode"])

	// When you push the data up, it's push_info
	// when vault responds, it's pushinfo :(
	d.Set("push_info", resp.Data["pushinfo"])

	// secret_key and integration_key, can't read out from the api
	// So... if it drifts, it drift.

	d.SetId(id)

	return nil
}

func mfaDuoUpdateFields(d *schema.ResourceData, data map[string]interface{}) {

	if v, ok := d.GetOk("id"); ok {
		data["id"] = v.(string)
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

	if v, ok := d.GetOk("use_passcode"); ok {
		data["use_passcode"] = v.(bool)
	}

}

func mfaDuoPath(id string) string {
	if id != "" {
		return "identity/mfa/method/duo/" + strings.Trim(id, "/")
	} else {
		return "identity/mfa/method/duo"
	}
}
