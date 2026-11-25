// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	secretsImportSourcesPath = "sys/import/sources"

	fieldDestinationMount = "destination_mount"
	fieldImportFilter     = "filter"
	fieldAuthMode         = "auth_mode"
	fieldImportCreatedAt  = "created_at"
	fieldImportUpdatedAt  = "updated_at"
	fieldSessionToken     = "session_token"

	importSourceTypeAWS   = "aws-sm"
	importSourceTypeAzure = "azure-kv"
	importSourceTypeGCP   = "gcp-sm"
)

// POC: set this to the Vault release that ships sys/import/sources.
var secretsImportMinVersion = provider.VaultVersion220

var secretsImportRoleARNRegex = regexp.MustCompile(`^arn:aws[a-zA-Z-]*:iam::\d{12}:role/.+$`)

// secretsImportCommonFields are shared by every source type.
var secretsImportCommonFields = []string{
	consts.FieldIdentityTokenAudience,
	consts.FieldIdentityTokenKey,
	consts.FieldIdentityTokenTTL,
	fieldDestinationMount,
	fieldImportFilter,
}

var secretsImportComputedFields = []string{
	fieldAuthMode,
	fieldImportCreatedAt,
	fieldImportUpdatedAt,
}

// secretsImportSource describes one source type (one Terraform resource).
type secretsImportSource struct {
	sourceType string
	// fields are the type-specific connection fields.
	fields map[string]*schema.Schema
	// staticFields are the static credential fields. Vault masks them on read,
	// so they are never refreshed from Vault.
	staticFields []string
	// wifRequires lists the fields that identity_token_audience requires.
	wifRequires []string
}

func secretsImportAWSSourceResource() *schema.Resource {
	return secretsImportSource{
		sourceType: importSourceTypeAWS,
		fields: map[string]*schema.Schema{
			consts.FieldRoleArn: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "IAM role to assume. Without identity_token_audience, the role is assumed " +
					"using the Vault server's host credentials (or the static keys, if set).",
				ValidateFunc: validation.StringMatch(secretsImportRoleARNRegex,
					"must be an IAM role ARN, e.g. arn:aws:iam::123456789012:role/name"),
			},
			consts.FieldExternalID: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "External ID that must match the trust policy of role_arn.",
				RequiredWith:  []string{consts.FieldRoleArn},
				ConflictsWith: []string{consts.FieldIdentityTokenAudience},
			},
			consts.FieldRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Region to import secrets from.",
			},
			consts.FieldAccessKeyID: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				Description:   "Static access key ID. Fallback only; prefer host credentials, role_arn or WIF.",
				RequiredWith:  []string{consts.FieldSecretAccessKey},
				ConflictsWith: []string{consts.FieldIdentityTokenAudience},
			},
			consts.FieldSecretAccessKey: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				Description:   "Static secret access key. Fallback only; prefer host credentials, role_arn or WIF.",
				RequiredWith:  []string{consts.FieldAccessKeyID},
				ConflictsWith: []string{consts.FieldIdentityTokenAudience},
			},
			fieldSessionToken: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				Description:   "Session token for temporary static credentials.",
				RequiredWith:  []string{consts.FieldAccessKeyID, consts.FieldSecretAccessKey},
				ConflictsWith: []string{consts.FieldIdentityTokenAudience},
			},
		},
		staticFields: []string{consts.FieldAccessKeyID, consts.FieldSecretAccessKey, fieldSessionToken},
		wifRequires:  []string{consts.FieldRoleArn},
	}.resource()
}

func secretsImportGCPSourceResource() *schema.Resource {
	return secretsImportSource{
		sourceType: importSourceTypeGCP,
		fields: map[string]*schema.Schema{
			consts.FieldProjectID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Project to import secrets from.",
			},
			consts.FieldServiceAccountEmail: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Service account to impersonate with workload identity federation.",
			},
			consts.FieldCredentials: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				Description:   "Static service account key JSON. Fallback only; prefer host credentials or WIF.",
				ConflictsWith: []string{consts.FieldIdentityTokenAudience},
			},
		},
		staticFields: []string{consts.FieldCredentials},
		wifRequires:  []string{consts.FieldServiceAccountEmail},
	}.resource()
}

func secretsImportAzureSourceResource() *schema.Resource {
	return secretsImportSource{
		sourceType: importSourceTypeAzure,
		fields: map[string]*schema.Schema{
			fieldKeyVaultURI: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "URI of the Key Vault to import secrets from.",
			},
			consts.FieldTenantID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Tenant ID of the app registration.",
			},
			consts.FieldClientID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Client ID of the app registration or user-assigned managed identity.",
			},
			consts.FieldClientSecret: {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				Description:   "Static client secret. Fallback only; prefer host credentials or WIF.",
				RequiredWith:  []string{consts.FieldTenantID, consts.FieldClientID},
				ConflictsWith: []string{consts.FieldIdentityTokenAudience},
			},
		},
		staticFields: []string{consts.FieldClientSecret},
		wifRequires:  []string{consts.FieldTenantID, consts.FieldClientID},
	}.resource()
}

func (s secretsImportSource) resource() *schema.Resource {
	sch := map[string]*schema.Schema{
		consts.FieldName: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Unique name of the import source within its type.",
		},
		consts.FieldIdentityTokenAudience: {
			Type:     schema.TypeString,
			Optional: true,
			Description: "Audience expected by the cloud provider's identity federation. When set, Vault " +
				"authenticates with workload identity federation.",
			RequiredWith: s.wifRequires,
		},
		consts.FieldIdentityTokenKey: {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Identity token key used to sign the workload identity token.",
			RequiredWith: []string{consts.FieldIdentityTokenAudience},
		},
		consts.FieldIdentityTokenTTL: {
			Type:         schema.TypeInt,
			Optional:     true,
			Computed:     true,
			Description:  "TTL of the workload identity token, in seconds.",
			RequiredWith: []string{consts.FieldIdentityTokenAudience},
		},
		fieldDestinationMount: {
			Type:         schema.TypeString,
			Required:     true,
			Description:  "Path of the KV v2 mount secrets are imported into.",
			ValidateFunc: provider.ValidateNoLeadingTrailingSlashes,
		},
		fieldImportFilter: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "go-bexpr filter selecting which source secrets to import.",
		},
		fieldAuthMode: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "How Vault authenticates to the cloud provider, derived from the configured fields.",
		},
		fieldImportCreatedAt: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Time the source was created.",
		},
		fieldImportUpdatedAt: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Time the source was last updated.",
		},
	}
	for k, v := range s.fields {
		sch[k] = v
	}

	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(s.write, secretsImportMinVersion),
		ReadContext:   provider.ReadContextWrapper(s.read),
		UpdateContext: s.write,
		DeleteContext: s.delete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: sch,
	}
}

func secretsImportSourcePath(sourceType, name string) string {
	return fmt.Sprintf("%s/%s/%s", secretsImportSourcesPath, sourceType, name)
}

func (s secretsImportSource) configFields() []string {
	fields := append([]string{}, secretsImportCommonFields...)
	for k := range s.fields {
		fields = append(fields, k)
	}
	return fields
}

func (s secretsImportSource) isStatic(field string) bool {
	for _, f := range s.staticFields {
		if f == field {
			return true
		}
	}
	return false
}

// requestData returns the fields to send to Vault. On update, changed fields are
// always sent so that removing an attribute from the configuration clears it.
func (s secretsImportSource) requestData(d *schema.ResourceData) map[string]interface{} {
	data := map[string]interface{}{}
	for _, k := range s.configFields() {
		if v, ok := d.GetOk(k); ok {
			data[k] = v
		} else if !d.IsNewResource() && d.HasChange(k) {
			data[k] = v
		}
	}
	return data
}

func (s secretsImportSource) write(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	path := secretsImportSourcePath(s.sourceType, name)

	log.Printf("[DEBUG] Writing secrets import source to %q", path)
	resp, err := client.Logical().WriteWithContext(ctx, path, s.requestData(d))
	if err != nil {
		return diag.Errorf("error writing secrets import source to %q: %s", path, err)
	}

	if d.IsNewResource() {
		d.SetId(name)
	}

	var diags diag.Diagnostics
	if resp != nil {
		for _, w := range resp.Warnings {
			diags = append(diags, diag.Diagnostic{Severity: diag.Warning, Summary: w})
		}
	}
	return append(diags, s.read(ctx, d, meta)...)
}

func (s secretsImportSource) read(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := secretsImportSourcePath(s.sourceType, d.Id())
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error reading secrets import source from %q: %s", path, err)
	}
	if resp == nil {
		log.Printf("[WARN] No secrets import source found at %q; removing from state.", path)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldName, d.Id()); err != nil {
		return diag.FromErr(err)
	}
	for _, k := range append(s.configFields(), secretsImportComputedFields...) {
		if s.isStatic(k) {
			continue
		}
		v, ok := resp.Data[k]
		if !ok {
			continue
		}
		if err := d.Set(k, v); err != nil {
			return diag.Errorf("error setting state key %q: %s", k, err)
		}
	}

	return nil
}

func (s secretsImportSource) delete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := secretsImportSourcePath(s.sourceType, d.Id())
	log.Printf("[DEBUG] Deleting secrets import source at %q", path)
	if _, err := client.Logical().DeleteWithContext(ctx, path); err != nil {
		return diag.Errorf("error deleting secrets import source at %q: %s", path, err)
	}

	return nil
}
