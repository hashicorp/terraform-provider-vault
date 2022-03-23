package vault

import (
	"fmt"
	"log"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const identityOIDCProviderPathPrefix = "identity/oidc/provider"

func identityOIDCProviderResource() *schema.Resource {
	return &schema.Resource{
		Create: identityOIDCProviderCreateUpdate,
		Update: identityOIDCProviderCreateUpdate,
		Read:   identityOIDCProviderRead,
		Delete: identityOIDCProviderDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Description: "The name of the provider.",
				Required:    true,
			},
			"issuer": {
				Type:     schema.TypeString,
				ForceNew: true,
				Description: "Specifies what will be used as the 'scheme://host:port' component for the 'iss' claim of ID tokens." +
					"This value is computed using the issuer_host and https_enabled schema fields.",
				Computed: true,
				// TODO confirm if this is needed
				Optional: true,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					oldURLParsed, err := url.Parse(old)
					if err != nil {
						return false
					}

					newURLParsed, err := url.Parse(new)
					if err != nil {
						return false
					}

					if oldURLParsed.Host == newURLParsed.Host &&
						oldURLParsed.Scheme == newURLParsed.Scheme {
						return true
					}

					return false
				},
			},
			"https_enabled": {
				Type:        schema.TypeBool,
				Description: "Specifies whether the issuer host is on a https server.",
				Default:     true,
				Optional:    true,
			},
			"issuer_host": {
				Type:        schema.TypeString,
				Description: "The host for the issuer. Can be either host or host:port.",
				Optional:    true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if value != "" {
						// prefix value with either 'https' or 'http' for URL parsing
						// can use either since parsedUrl.Scheme is irrelevant here
						parsedUrl, err := url.Parse(fmt.Sprintf("https://%s", value))
						if err != nil {
							errs = append(errs, err)
						}

						if parsedUrl.Path != "" {
							errs = append(errs, fmt.Errorf("issuer_host cannot contain URL path"))
						}

						if parsedUrl.Host == "" {
							errs = append(errs, fmt.Errorf("issuer_host must either be a host or host:port string"))
						}
					}

					return nil, errs
				},
			},
			"allowed_client_ids": {
				Type: schema.TypeSet,
				Description: "The client IDs that are permitted to use the provider. If empty, no clients are allowed. " +
					"If \"*\", all clients are allowed.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
			"scopes_supported": {
				Type:        schema.TypeSet,
				Description: "The scopes available for requesting on the provider.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
			},
		},
	}
}

func identityOIDCProviderConfigData(d *schema.ResourceData) map[string]interface{} {
	nonBooleanFields := []string{"issuer_host", "allowed_client_ids", "scopes_supported"}
	configData := map[string]interface{}{}

	if v, ok := d.GetOkExists("https_enabled"); ok {
		configData["https_enabled"] = v.(bool)
	}

	for _, k := range nonBooleanFields {
		if v, ok := d.GetOk(k); ok {
			if k == "allowed_client_ids" || k == "scopes_supported" {
				configData[k] = v.(*schema.Set).List()
				continue
			}
			configData[k] = v
		}
	}

	// Construct issuer URL if issuer_host provided
	if v, ok := configData["issuer_host"]; ok {
		scheme := "https"
		if !configData["https_enabled"].(bool) {
			scheme = "http"
		}

		configData["issuer"] = fmt.Sprintf("%s://%s", scheme, v.(string))
	}

	return configData
}

func getOIDCProviderPath(name string) string {
	return fmt.Sprintf("%s/%s", identityOIDCProviderPathPrefix, name)
}

func identityOIDCProviderCreateUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)
	path := getOIDCProviderPath(name)

	configData := identityOIDCProviderConfigData(d)
	providerRequestData := map[string]interface{}{}

	providerAPIFields := []string{"issuer", "allowed_client_ids", "scopes_supported"}
	for _, k := range providerAPIFields {
		if v, ok := configData[k]; ok {
			providerRequestData[k] = v
		}
	}

	_, err := client.Logical().Write(path, providerRequestData)
	if err != nil {
		return fmt.Errorf("error writing OIDC Provider %s, err=%w", path, err)
	}

	log.Printf("[DEBUG] Wrote OIDC Provider to %s", path)

	d.SetId(path)

	return identityOIDCProviderRead(d, meta)
}

func identityOIDCProviderRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading OIDC Provider for %s", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading OIDC Provider for %s: %s", path, err)
	}

	log.Printf("[DEBUG] Read OIDC Provider for %s", path)
	if resp == nil {
		log.Printf("[WARN] OIDC Provider %s not found, removing from state", path)
		d.SetId("")

		return nil
	}

	for _, k := range []string{"issuer", "allowed_client_ids", "scopes_supported"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key %q on OIDC Provider %q, err=%w", k, path, err)
		}
	}

	return nil
}

func identityOIDCProviderDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting OIDC Provider %s", path)

	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting OIDC Provider %q", path)
	}

	log.Printf("[DEBUG] Deleted OIDC Provider %q", path)

	return nil
}
