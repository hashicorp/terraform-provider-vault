package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func pkiSecretBackendConfigEstDataSource() *schema.Resource {
	return &schema.Resource{
		Description: "Reads Vault PKI EST configuration",
		ReadContext: provider.ReadContextWrapper(readPKISecretBackendConfigEst),
		Schema: map[string]*schema.Schema{
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path where PKI engine is mounted",
			},
			consts.FieldEnabled: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Is the EST feature enabled",
			},
			consts.FieldDefaultMount: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Is this mount providing the cluster's default EST mount",
			},
			consts.FieldDefaultPathPolicy: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The behavior of the default_mount when enabled",
			},
			consts.FieldLabelToPathPolicy: {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "A pairing of EST label to the configured EST behavior for it",
			},
			consts.FieldAuthenticators: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Lists the mount accessors EST should delegate authentication requests towards",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cert": {
							Type:        schema.TypeMap,
							Optional:    true,
							Description: "The accessor and cert_role properties for cert auth backends",
						},
						"userpass": {
							Type:        schema.TypeMap,
							Optional:    true,
							Description: "The accessor property for user pass auth backends",
						},
					},
				},
			},
			consts.FieldEnableSentinelParsing: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Are fields from the provided CSR parsed out for Sentinel policies",
			},
		},
	}
}

func readPKISecretBackendConfigEst(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := verifyPkiEstFeatureSupported(meta); err != nil {
		return diag.FromErr(err)
	}

	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	backend := d.Get(consts.FieldBackend).(string)
	path := pkiSecretBackendConfigEstPath(backend)

	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading from Vault: %s", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", path)
	if resp == nil {
		return diag.FromErr(fmt.Errorf("no key found at %q", path))
	}

	d.SetId(path)

	keyComputedFields := []string{
		consts.FieldEnabled,
		consts.FieldDefaultMount,
		consts.FieldDefaultPathPolicy,
		consts.FieldLabelToPathPolicy,
		consts.FieldEnableSentinelParsing,
	}

	for _, k := range keyComputedFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.FromErr(err)
		}
	}

	authenticators := resp.Data[consts.FieldAuthenticators]
	if err := d.Set(consts.FieldAuthenticators, []interface{}{authenticators}); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

// verifyPkiEstFeatureSupported verifies that we are talking to a Vault enterprise edition
// and its version 1.16.0 or higher, returns nil if the above is met, otherwise an error
func verifyPkiEstFeatureSupported(meta interface{}) error {
	currentVersion := meta.(*provider.ProviderMeta).GetVaultVersion()

	minVersion := provider.VaultVersion116
	if !provider.IsAPISupported(meta, minVersion) {
		return fmt.Errorf("feature not enabled on current Vault version. min version required=%s; "+
			"current vault version=%s", minVersion, currentVersion)
	}

	if !provider.IsEnterpriseSupported(meta) {
		return errors.New("feature requires Vault Enterprise")
	}
	return nil
}

func pkiSecretBackendConfigEstPath(backend string) string {
	return strings.Trim(backend, "/") + "/config/est"
}
