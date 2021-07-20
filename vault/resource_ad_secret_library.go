package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

var (
	adSecretBackendFromLibraryPathRegex = regexp.MustCompile("^(.+)/library/.+$")
	adSecretBackendSetNameFromPathRegex = regexp.MustCompile("^.+/library/(.+$)")
)

func adSecretBackendLibraryResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"backend": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "The mount path for the AD backend.",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `The name of the set of service accounts.`,
			ForceNew:    true,
		},
		"service_account_names": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Required:    true,
			Description: "The names of all the service accounts that can be checked out from this set. These service accounts must already exist in Active Directory.",
			ForceNew:    true,
		},
		"max_ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `The maximum amount of time, in seconds, a check-out last with renewal before Vault automatically checks it back in.`,
		},
		"ttl": {
			Type:        schema.TypeInt,
			Optional:    true,
			Computed:    true,
			Description: `The amount of time, in seconds, a single check-out lasts before Vault automatically checks it back in.`,
		},
		"disable_check_in_enforcement": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Disable enforcing that service accounts must be checked in by the entity or client token that checked them out.`,
		},
	}
	return &schema.Resource{
		Create: createLibraryResource,
		Update: updateLibraryResource,
		Read:   readLibraryResource,
		Delete: deleteLibraryResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func createLibraryResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	set := d.Get("name").(string)
	setPath := fmt.Sprintf("%s/library/%s", backend, set)

	log.Printf("[DEBUG] Creating %q", setPath)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("disable_check_in_enforcement"); ok {
		data["disable_check_in_enforcement"] = v
	}

	if v, ok := d.GetOkExists("service_account_names"); ok {
		data["service_account_names"] = v
	}

	if v, ok := d.GetOkExists("max_ttl"); ok {
		data["max_ttl"] = v
	}

	if v, ok := d.GetOkExists("ttl"); ok {
		data["ttl"] = v
	}

	log.Printf("[DEBUG] Writing %q", setPath)
	if _, err := client.Logical().Write(setPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", setPath, err)
	}
	d.SetId(setPath)
	log.Printf("[DEBUG] Wrote %q", setPath)
	return readLibraryResource(d, meta)
}

func readLibraryResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	setPath := d.Id()
	log.Printf("[DEBUG] Reading %q", setPath)

	setName, err := adSecretBackendSetNameFromPath(setPath)
	if err != nil {
		return fmt.Errorf("invalid library ID %q: %s", setPath, err)
	}
	d.Set("name", setName)

	backend, err := adSecretBackendFromLibraryPath(setPath)
	if err != nil {
		return fmt.Errorf("invalid library ID %q: %s", setPath, err)
	}
	d.Set("backend", backend)

	resp, err := client.Logical().Read(setPath)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", setPath)
		d.SetId("")
		return nil
	} else if err != nil {
		return fmt.Errorf("error reading %q: %s", setPath, err)
	}
	log.Printf("[DEBUG] Read %q", setPath)

	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", setPath)
		d.SetId("")
		return nil
	}

	if val, ok := resp.Data["service_account_names"]; ok {
		if err := d.Set("service_account_names", val); err != nil {
			return fmt.Errorf("error setting state key 'service_account_names': %s", err)
		}
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

	if val, ok := resp.Data["disable_check_in_enforcement"]; ok {
		if err := d.Set("disable_check_in_enforcement", val); err != nil {
			return fmt.Errorf("error setting state key 'disable_check_in_enforcement': %s", err)
		}
	}

	return nil
}

func updateLibraryResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	setPath := d.Id()
	log.Printf("[DEBUG] Updating %q", setPath)

	data := map[string]interface{}{}
	if raw, ok := d.GetOk("service_account_names"); ok {
		data["service_account_names"] = raw
	}

	if raw, ok := d.GetOk("max_ttl"); ok {
		data["ttl"] = raw
	}

	if raw, ok := d.GetOk("ttl"); ok {
		data["ttl"] = raw
	}

	if raw, ok := d.GetOk("disable_check_in_enforcement"); ok {
		data["disable_check_in_enforcement"] = raw
	}

	if _, err := client.Logical().Write(setPath, data); err != nil {
		return fmt.Errorf("error updating library %q: %s", setPath, err)
	}
	log.Printf("[DEBUG] Updated %q", setPath)
	return readLibraryResource(d, meta)
}

func deleteLibraryResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	setPath := d.Id()
	log.Printf("[DEBUG] Deleting %q", setPath)

	if _, err := client.Logical().Delete(setPath); err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting %q: %s", setPath, err)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", setPath)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted library %q", setPath)
	return nil
}

func adSecretBackendSetNameFromPath(path string) (string, error) {
	if !adSecretBackendSetNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no name found")
	}
	res := adSecretBackendSetNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for name", len(res))
	}
	return res[1], nil
}

func adSecretBackendFromLibraryPath(path string) (string, error) {
	if !adSecretBackendFromLibraryPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := adSecretBackendFromLibraryPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
