// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const fieldUseAnnotationsAsAliasMetadata = "use_annotations_as_alias_metadata"

var (
	kubernetesAuthBackendConfigFromPathRegex = regexp.MustCompile("^auth/(.+)/config$")
	// overrideKubernetesFieldsMap maps resource IDs to a slice of strings containing
	// field names that should be unset/overridden on resource update. Typically only
	// computed fields might need to be unset. map[resource.ID+"."+fieldName] =
	// overrideValue
	overrideKubernetesFieldsMap = sync.Map{}
	vaultVersion193             = version.Must(version.NewSemver("1.9.3"))
)

func kubernetesAuthBackendConfigResource() *schema.Resource {
	s := map[string]*schema.Schema{
		consts.FieldKubernetesHost: {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.",
		},
		consts.FieldKubernetesCACert: {
			Type:        schema.TypeString,
			Description: "PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.",
			Optional:    true,
			Computed:    true,
		},
		"token_reviewer_jwt": {
			Type:        schema.TypeString,
			Description: "A service account JWT (or other token) used as a bearer token to access the TokenReview API to validate other JWTs during login. If not set the JWT used for login will be used to access the API.",
			Default:     "",
			Optional:    true,
			Sensitive:   true,
		},
		consts.FieldPEMKeys: {
			Type:        schema.TypeList,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "Optional list of PEM-formatted public keys or certificates used to verify the signatures of Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every installation of Kubernetes exposes these keys.",
			Optional:    true,
		},
		consts.FieldBackend: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the kubernetes backend to configure.",
			ForceNew:    true,
			Default:     "kubernetes",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldIssuer: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Optional JWT issuer. If no issuer is specified, kubernetes.io/serviceaccount will be used as the default issuer.",
		},
		consts.FieldDisableISSValidation: {
			Type:        schema.TypeBool,
			Computed:    true,
			Optional:    true,
			Description: "Optional disable JWT issuer validation. Allows to skip ISS validation.",
		},
		consts.FieldDisableLocalCAJWT: {
			Type:        schema.TypeBool,
			Computed:    true,
			Optional:    true,
			Description: "Optional disable defaulting to the local CA cert and service account JWT when running in a Kubernetes pod.",
		},
		fieldUseAnnotationsAsAliasMetadata: {
			Type:        schema.TypeBool,
			Computed:    true,
			Optional:    true,
			Description: "Use annotations from the client token's associated service account as alias metadata for the Vault entity.",
		},
	}
	return &schema.Resource{
		Create: kubernetesAuthBackendConfigCreate,
		Read:   provider.ReadWrapper(kubernetesAuthBackendConfigRead),
		Update: kubernetesAuthBackendConfigUpdate,
		Delete: kubernetesAuthBackendConfigDelete,
		Exists: kubernetesAuthBackendConfigExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		CustomizeDiff: func(ctx context.Context, diff *schema.ResourceDiff, m interface{}) error {
			if !diff.Get(consts.FieldDisableLocalCAJWT).(bool) && diff.Id() != "" {
				// on Vault 1.9.3+ the K8S CA certificate is no longer stored in the Vault
				// configuration when Vault is running in K8s and FieldDisableLocalCAJWT is
				// false. Unfortunately, the change did not consider the Vault schema upgrade
				// path and would leave a stale CA certificate in Vault config. See
				// https://github.com/hashicorp/vault-plugin-auth-kubernetes/pull/122 for more
				// details
				//
				// This bit if code will ensure the following cases are handled:
				// - CA certificate in Vault config but unset in TF
				// - CA certificate in Vault config and set to "" in TF
				//
				// If any of the above cases are detected the CA certificate configured in Vault
				// will be unset upon TF apply.
				meta, ok := m.(*provider.ProviderMeta)
				if !ok {
					return fmt.Errorf("invalid type %T", m)
				}

				if s[consts.FieldKubernetesCACert].Computed && meta.GetVaultVersion().GreaterThanOrEqual(vaultVersion193) {
					val, valExists := diff.GetRawConfig().AsValueMap()[consts.FieldKubernetesCACert]
					o, n := diff.GetChange(consts.FieldKubernetesCACert)
					if (valExists && val.IsNull() && n.(string) != "") || (o.(string) != "" && n.(string) == "") {
						// trigger a diff, since we want to unset the previously computed value.
						if err := diff.SetNew(consts.FieldKubernetesCACert, ""); err != nil {
							return err
						}
						overrideKubernetesFieldsMap.Store(diff.Id()+"."+consts.FieldKubernetesCACert, "")
					}
				}
			}

			return nil
		},

		Schema: s,
	}
}

func kubernetesAuthBackendConfigPath(backend string) string {
	return "auth/" + strings.Trim(backend, "/") + "/config"
}

func kubernetesAuthBackendConfigCreate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)

	path := kubernetesAuthBackendConfigPath(backend)
	log.Printf("[DEBUG] Writing Kubernetes auth backend config %q", path)

	data := map[string]interface{}{}

	if v, ok := d.GetOk(consts.FieldKubernetesCACert); ok {
		data[consts.FieldKubernetesCACert] = v
	}

	if v, ok := d.GetOk("token_reviewer_jwt"); ok {
		data["token_reviewer_jwt"] = v.(string)
	}

	if v, ok := d.GetOkExists(consts.FieldPEMKeys); ok {
		var pemKeys []string
		for _, pemKey := range v.([]interface{}) {
			pemKeys = append(pemKeys, pemKey.(string))
		}
		data[consts.FieldPEMKeys] = strings.Join(pemKeys, ",")
	}
	data[consts.FieldKubernetesHost] = d.Get(consts.FieldKubernetesHost).(string)

	if v, ok := d.GetOk(consts.FieldIssuer); ok {
		data[consts.FieldIssuer] = v.(string)
	}

	if v := d.Get(consts.FieldDisableISSValidation); v != nil {
		data[consts.FieldDisableISSValidation] = v
	}

	if v, ok := d.GetOk(consts.FieldDisableLocalCAJWT); ok {
		data[consts.FieldDisableLocalCAJWT] = v
	}

	if provider.IsAPISupported(meta, provider.VaultVersion116) {
		if v := d.Get(fieldUseAnnotationsAsAliasMetadata); v != nil {
			data[fieldUseAnnotationsAsAliasMetadata] = v
		}
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing Kubernetes auth backend config %q: %s", path, err)
	}

	d.SetId(path)
	// NOTE: Since reading the auth/<backend>/config does
	// not return the `token_reviewer_jwt`,
	// set it from data after successfully storing it in Vault.
	if err := d.Set("token_reviewer_jwt", data["token_reviewer_jwt"]); err != nil {
		return err
	}

	log.Printf("[DEBUG] Wrote Kubernetes auth backend config %q", path)

	return kubernetesAuthBackendConfigRead(d, meta)
}

func kubernetesAuthBackendConfigBackendFromPath(path string) (string, error) {
	if !kubernetesAuthBackendConfigFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := kubernetesAuthBackendConfigFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func kubernetesAuthBackendConfigRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	backend, err := kubernetesAuthBackendConfigBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for Kubernetes auth backend config: %s", path, err)
	}

	log.Printf("[DEBUG] Reading Kubernetes auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Kubernetes auth backend config %q: %s", path, err)
	}

	log.Printf("[DEBUG] Read Kubernetes auth backend config %q", path)
	if resp == nil {
		log.Printf("[WARN] Kubernetes auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := d.Set("backend", backend); err != nil {
		return err
	}

	params := []string{
		consts.FieldKubernetesCACert,
		consts.FieldKubernetesHost,
		consts.FieldIssuer,
		consts.FieldDisableISSValidation,
		consts.FieldDisableLocalCAJWT,
		consts.FieldPEMKeys,
		fieldUseAnnotationsAsAliasMetadata,
	}

	for _, k := range params {
		if k == fieldUseAnnotationsAsAliasMetadata && !provider.IsAPISupported(meta, provider.VaultVersion116) {
			continue
		}
		v := resp.Data[k]
		if err := d.Set(k, v); err != nil {
			return err
		}
	}

	return nil
}

func kubernetesAuthBackendConfigUpdate(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()

	log.Printf("[DEBUG] Updating Kubernetes auth backend config %q", path)

	data := map[string]interface{}{}
	setData := func(param string, val interface{}) {
		if override, ok := overrideKubernetesFieldsMap.LoadAndDelete(d.Id() + "." + param); ok {
			val = override
		}
		data[param] = val
	}

	if v, ok := d.GetOk(consts.FieldKubernetesCACert); ok {
		setData(consts.FieldKubernetesCACert, v)
	}

	if v, ok := d.GetOk("token_reviewer_jwt"); ok {
		setData("token_reviewer_jwt", v.(string))
	}

	if v, ok := d.GetOkExists(consts.FieldPEMKeys); ok {
		var pemKeys []string
		for _, pemKey := range v.([]interface{}) {
			pemKeys = append(pemKeys, pemKey.(string))
		}
		setData(consts.FieldPEMKeys, strings.Join(pemKeys, ","))
	}
	setData(consts.FieldKubernetesHost, d.Get(consts.FieldKubernetesHost).(string))

	if v, ok := d.GetOk(consts.FieldIssuer); ok {
		setData(consts.FieldIssuer, v.(string))
	}

	if v, ok := d.GetOkExists(consts.FieldDisableISSValidation); ok {
		setData(consts.FieldDisableISSValidation, v)
	}

	if v, ok := d.GetOk(consts.FieldDisableLocalCAJWT); ok {
		setData(consts.FieldDisableLocalCAJWT, v)
	}

	if provider.IsAPISupported(meta, provider.VaultVersion116) {
		if v := d.Get(fieldUseAnnotationsAsAliasMetadata); v != nil {
			data[fieldUseAnnotationsAsAliasMetadata] = v
		}
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating Kubernetes auth backend config %q: %s", path, err)
	}

	// NOTE: Only `SetId` after it's successfully written in Vault
	d.SetId(path)

	log.Printf("[DEBUG] Updated Kubernetes auth backend config %q", path)

	return kubernetesAuthBackendConfigRead(d, meta)
}

func kubernetesAuthBackendConfigDelete(d *schema.ResourceData, meta interface{}) error {
	path := d.Id()
	log.Printf("[DEBUG] Deleted Kubernetes auth backend config %q", path)
	d.SetId("")
	return nil
}

func kubernetesAuthBackendConfigExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if Kubernetes auth backend config %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if Kubernetes auth backend config %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if Kubernetes auth backend config %q exists", path)

	return resp != nil, nil
}
