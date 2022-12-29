package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var (
	gcpSecretImpersonatedAccountBackendFromPathRegex = regexp.MustCompile("^(.+)/impersonated-account/.+$")
	gcpSecretImpersonatedAccountNameFromPathRegex    = regexp.MustCompile("^.+/impersonated-account/(.+)$")
)

func gcpSecretImpersonatedAccountResource() *schema.Resource {
	return &schema.Resource{
		Create: gcpSecretImpersonatedAccountCreate,
		Read:   gcpSecretImpersonatedAccountRead,
		Update: gcpSecretImpersonatedAccountUpdate,
		Delete: gcpSecretImpersonatedAccountDelete,
		Exists: gcpSecretImpersonatedAccountExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where the GCP secrets engine is mounted.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"impersonated_account": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the Impersonated Account to create",
				ForceNew:    true,
			},
			"service_account_email": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Email of the GCP service account.",
			},
			"token_scopes": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:    true,
				Description: "List of OAuth scopes to assign to `access_token` secrets generated under this impersonated account (`access_token` impersonated accounts only) ",
			},
			"service_account_project": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Project of the GCP Service Account managed by this impersonated account",
			},
		},
	}
}

func gcpSecretImpersonatedAccountCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	backend := d.Get("backend").(string)
	impersonatedAccount := d.Get("impersonated_account").(string)

	path := gcpSecretImpersonatedAccountPath(backend, impersonatedAccount)

	log.Printf("[DEBUG] Writing GCP Secrets backend impersonated account %q", path)

	data := map[string]interface{}{}
	gcpSecretImpersonatedAccountUpdateFields(d, data)
	d.SetId(path)
	_, err = client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing GCP Secrets backend impersonated account %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote GCP Secrets backend impersonated account %q", path)

	return gcpSecretImpersonatedAccountRead(d, meta)
}

func gcpSecretImpersonatedAccountRead(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Id()

	backend, err := gcpSecretImpersonatedAccountBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP secrets backend impersonated account: %s", path, err)
	}

	impersonatedAccount, err := gcpSecretImpersonatedAccountNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP Secrets backend impersonated account: %s", path, err)
	}

	log.Printf("[DEBUG] Reading GCP Secrets backend impersonated account %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading GCP Secrets backend impersonated account %q: %s", path, err)
	}

	log.Printf("[DEBUG] Read GCP Secrets backend impersonated account %q", path)
	if resp == nil {
		log.Printf("[WARN] GCP Secrets backend impersonated account %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set("backend", backend); err != nil {
		return err
	}
	if err := d.Set("impersonated_account", impersonatedAccount); err != nil {
		return err
	}

	for _, k := range []string{"token_scopes", "service_account_email", "service_account_project"} {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for GCP Secrets backend impersonated account %q: %q", k, path, err)
			}
		}
	}

	return nil
}

func gcpSecretImpersonatedAccountUpdate(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Id()

	data := map[string]interface{}{}
	gcpSecretImpersonatedAccountUpdateFields(d, data)

	log.Printf("[DEBUG] Updating GCP Secrets backend impersonated account %q", path)

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating GCP Secrets backend impersonated account %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated GCP Secrets backend impersonated account %q", path)

	return gcpSecretImpersonatedAccountRead(d, meta)
}

func gcpSecretImpersonatedAccountDelete(d *schema.ResourceData, meta interface{}) error {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return err
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting GCP secrets backend impersonated account %q", path)
	_, err = client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting GCP secrets backend impersonated account %q", path)
	}
	log.Printf("[DEBUG] Deleted GCP secrets backend impersonated account %q", path)

	return nil
}

func gcpSecretImpersonatedAccountUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk("service_account_email"); ok {
		data["service_account_email"] = v.(string)
	}

	if v, ok := d.GetOk("token_scopes"); ok {
		data["token_scopes"] = v.(*schema.Set).List()
	}
}

func gcpSecretImpersonatedAccountExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return false, err
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}

func gcpSecretImpersonatedAccountPath(backend, impersonatedAccount string) string {
	return strings.Trim(backend, "/") + "/impersonated-account/" + strings.Trim(impersonatedAccount, "/")
}

func gcpSecretImpersonatedAccountBackendFromPath(path string) (string, error) {
	if !gcpSecretImpersonatedAccountBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := gcpSecretImpersonatedAccountBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func gcpSecretImpersonatedAccountNameFromPath(path string) (string, error) {
	if !gcpSecretImpersonatedAccountNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no impersonated account found")
	}
	res := gcpSecretImpersonatedAccountNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}
