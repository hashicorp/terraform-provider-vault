package jwt

// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

const configEndpoint = "/auth/jwt/config"

func ConfigResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"path": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for a back-end, for example, the path given in "$ vault auth enable -path=my-aws aws".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		"bound_issuer": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The value against which to match the 'iss' claim in a JWT. Optional.`,
		},
		"default_role": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The default role to use if none is provided during login. If not set, a role is required during login.`,
		},
		"jwks_ca_pem": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The CA certificate or chain of certificates, in PEM format, to use to validate connections to the JWKS URL. If not set, system certificates are used.`,
		},
		"jwks_url": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `JWKS URL to use to authenticate signatures. Cannot be used with "oidc_discovery_url" or "jwt_validation_pubkeys".`,
		},
		"jwt_supported_algs": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: `A list of supported signing algorithms. Defaults to RS256.`,
		},
		"jwt_validation_pubkeys": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: `A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with "jwks_url" or "oidc_discovery_url".`,
		},
		"oidc_client_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The OAuth Client ID configured with your OIDC provider.`,
		},
		"oidc_client_secret": {
			Type:        schema.TypeString,
			Optional:    true,
			Sensitive:   true,
			Description: `The OAuth Client Secret configured with your OIDC provider.`,
		},
		"oidc_discovery_ca_pem": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The CA certificate or chain of certificates, in PEM format, to use to validate connections to the OIDC Discovery URL. If not set, system certificates are used.`,
		},
		"oidc_discovery_url": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `OIDC Discovery URL, without any .well-known component (base path). Cannot be used with "jwks_url" or "jwt_validation_pubkeys".`,
		},
		"oidc_response_mode": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `The response mode to be used in the OAuth2 request. Allowed values are 'query' and 'form_post'.`,
		},
		"oidc_response_types": {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Optional:    true,
			Description: `The response types to request. Allowed values are 'code' and 'id_token'. Defaults to 'code'.`,
		},
	}
	return &schema.Resource{
		Create: createConfigResource,
		Update: updateConfigResource,
		Read:   readConfigResource,
		Exists: resourceConfigExists,
		Delete: deleteConfigResource,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}
func createConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, configEndpoint, d)
	log.Printf("[DEBUG] Creating %q", vaultPath)

	data := map[string]interface{}{}
	if v, ok := d.GetOkExists("bound_issuer"); ok {
		data["bound_issuer"] = v
	}
	if v, ok := d.GetOkExists("default_role"); ok {
		data["default_role"] = v
	}
	if v, ok := d.GetOkExists("jwks_ca_pem"); ok {
		data["jwks_ca_pem"] = v
	}
	if v, ok := d.GetOkExists("jwks_url"); ok {
		data["jwks_url"] = v
	}
	if v, ok := d.GetOkExists("jwt_supported_algs"); ok {
		data["jwt_supported_algs"] = v
	}
	if v, ok := d.GetOkExists("jwt_validation_pubkeys"); ok {
		data["jwt_validation_pubkeys"] = v
	}
	if v, ok := d.GetOkExists("oidc_client_id"); ok {
		data["oidc_client_id"] = v
	}
	if v, ok := d.GetOkExists("oidc_client_secret"); ok {
		data["oidc_client_secret"] = v
	}
	if v, ok := d.GetOkExists("oidc_discovery_ca_pem"); ok {
		data["oidc_discovery_ca_pem"] = v
	}
	if v, ok := d.GetOkExists("oidc_discovery_url"); ok {
		data["oidc_discovery_url"] = v
	}
	if v, ok := d.GetOkExists("oidc_response_mode"); ok {
		data["oidc_response_mode"] = v
	}
	if v, ok := d.GetOkExists("oidc_response_types"); ok {
		data["oidc_response_types"] = v
	}

	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", vaultPath, err)
	}
	d.SetId(vaultPath)
	log.Printf("[DEBUG] Wrote %q", vaultPath)
	return readConfigResource(d, meta)
}

func readConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Reading %q", vaultPath)

	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Read %q", vaultPath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}
	pathParams, err := util.PathParameters(configEndpoint, vaultPath)
	if err != nil {
		return err
	}
	for paramName, paramVal := range pathParams {
		if err := d.Set(paramName, paramVal); err != nil {
			return fmt.Errorf("error setting state %q, %q: %s", paramName, paramVal, err)
		}
	}
	if val, ok := resp.Data["bound_issuer"]; ok {
		if err := d.Set("bound_issuer", val); err != nil {
			return fmt.Errorf("error setting state key 'bound_issuer': %s", err)
		}
	}
	if val, ok := resp.Data["default_role"]; ok {
		if err := d.Set("default_role", val); err != nil {
			return fmt.Errorf("error setting state key 'default_role': %s", err)
		}
	}
	if val, ok := resp.Data["jwks_ca_pem"]; ok {
		if err := d.Set("jwks_ca_pem", val); err != nil {
			return fmt.Errorf("error setting state key 'jwks_ca_pem': %s", err)
		}
	}
	if val, ok := resp.Data["jwks_url"]; ok {
		if err := d.Set("jwks_url", val); err != nil {
			return fmt.Errorf("error setting state key 'jwks_url': %s", err)
		}
	}
	if val, ok := resp.Data["jwt_supported_algs"]; ok {
		if err := d.Set("jwt_supported_algs", val); err != nil {
			return fmt.Errorf("error setting state key 'jwt_supported_algs': %s", err)
		}
	}
	if val, ok := resp.Data["jwt_validation_pubkeys"]; ok {
		if err := d.Set("jwt_validation_pubkeys", val); err != nil {
			return fmt.Errorf("error setting state key 'jwt_validation_pubkeys': %s", err)
		}
	}
	if val, ok := resp.Data["oidc_client_id"]; ok {
		if err := d.Set("oidc_client_id", val); err != nil {
			return fmt.Errorf("error setting state key 'oidc_client_id': %s", err)
		}
	}
	if val, ok := resp.Data["oidc_client_secret"]; ok {
		if err := d.Set("oidc_client_secret", val); err != nil {
			return fmt.Errorf("error setting state key 'oidc_client_secret': %s", err)
		}
	}
	if val, ok := resp.Data["oidc_discovery_ca_pem"]; ok {
		if err := d.Set("oidc_discovery_ca_pem", val); err != nil {
			return fmt.Errorf("error setting state key 'oidc_discovery_ca_pem': %s", err)
		}
	}
	if val, ok := resp.Data["oidc_discovery_url"]; ok {
		if err := d.Set("oidc_discovery_url", val); err != nil {
			return fmt.Errorf("error setting state key 'oidc_discovery_url': %s", err)
		}
	}
	if val, ok := resp.Data["oidc_response_mode"]; ok {
		if err := d.Set("oidc_response_mode", val); err != nil {
			return fmt.Errorf("error setting state key 'oidc_response_mode': %s", err)
		}
	}
	if val, ok := resp.Data["oidc_response_types"]; ok {
		if err := d.Set("oidc_response_types", val); err != nil {
			return fmt.Errorf("error setting state key 'oidc_response_types': %s", err)
		}
	}
	return nil
}

func updateConfigResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Updating %q", vaultPath)

	data := map[string]interface{}{}
	if raw, ok := d.GetOk("bound_issuer"); ok {
		data["bound_issuer"] = raw
	}
	if raw, ok := d.GetOk("default_role"); ok {
		data["default_role"] = raw
	}
	if raw, ok := d.GetOk("jwks_ca_pem"); ok {
		data["jwks_ca_pem"] = raw
	}
	if raw, ok := d.GetOk("jwks_url"); ok {
		data["jwks_url"] = raw
	}
	if raw, ok := d.GetOk("jwt_supported_algs"); ok {
		data["jwt_supported_algs"] = raw
	}
	if raw, ok := d.GetOk("jwt_validation_pubkeys"); ok {
		data["jwt_validation_pubkeys"] = raw
	}
	if raw, ok := d.GetOk("oidc_client_id"); ok {
		data["oidc_client_id"] = raw
	}
	if raw, ok := d.GetOk("oidc_client_secret"); ok {
		data["oidc_client_secret"] = raw
	}
	if raw, ok := d.GetOk("oidc_discovery_ca_pem"); ok {
		data["oidc_discovery_ca_pem"] = raw
	}
	if raw, ok := d.GetOk("oidc_discovery_url"); ok {
		data["oidc_discovery_url"] = raw
	}
	if raw, ok := d.GetOk("oidc_response_mode"); ok {
		data["oidc_response_mode"] = raw
	}
	if raw, ok := d.GetOk("oidc_response_types"); ok {
		data["oidc_response_types"] = raw
	}
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Updated %q", vaultPath)
	return readConfigResource(d, meta)
}

func deleteConfigResource(_ *schema.ResourceData, _ interface{}) error {
	// Terraform requires the delete is implemented whenever create is implemented,
	// but this endpoint doesn't support delete. Thus, we've simply stubbed out delete
	// here.
	return nil
}

func resourceConfigExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", vaultPath)

	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", vaultPath)
	return resp != nil, nil
}
