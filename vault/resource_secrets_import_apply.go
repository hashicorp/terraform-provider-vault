// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	fieldTriggers       = "triggers"
	fieldFailOnError    = "fail_on_error"
	fieldAppliedAt      = "applied_at"
	fieldScannedCount   = "scanned_count"
	fieldImported       = "imported"
	fieldImportedCount  = "imported_count"
	fieldWouldImport    = "would_import"
	fieldWouldImportCnt = "would_import_count"
	fieldIgnored        = "ignored"
	fieldFailed         = "failed"
	fieldFailedCount    = "failed_count"

	importOperationPlan  = "plan"
	importOperationApply = "apply"
)

// secretsImportApplyResource imports secrets once when created. Changing the
// source or any value in triggers replaces the resource, which imports again.
// Destroying it only removes it from state; imported secrets stay in Vault.
func secretsImportApplyResource() *schema.Resource {
	s := secretsImportResultSchema(fieldImported, fieldImportedCount, "imported")
	addSecretsImportSourceRefSchema(s, true, "apply")
	s[fieldTriggers] = &schema.Schema{
		Type:        schema.TypeMap,
		Optional:    true,
		ForceNew:    true,
		Elem:        &schema.Schema{Type: schema.TypeString},
		Description: "Arbitrary values that cause the import to run again when changed.",
	}
	s[fieldFailOnError] = &schema.Schema{
		Type:     schema.TypeBool,
		Optional: true,
		ForceNew: true,
		Default:  true,
		Description: "Return an error when any secret fails to import. The resource is then " +
			"tainted, so the next apply imports again.",
	}
	s[fieldAppliedAt] = &schema.Schema{
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Time the import ran.",
	}

	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(secretsImportApplyCreate, secretsImportMinVersion),
		ReadContext:   secretsImportApplyRead,
		DeleteContext: secretsImportApplyDelete,
		Schema:        s,
	}
}

// secretsImportResultSchema returns the computed attributes shared by the plan
// data source and the apply resource. listField and countField name the
// attributes holding the destination paths (would_import or imported).
func secretsImportResultSchema(listField, countField, verb string) map[string]*schema.Schema {
	return map[string]*schema.Schema{
		fieldAuthMode: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "How Vault authenticated to the cloud provider.",
		},
		fieldDestinationMount: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "KV v2 mount the secrets are imported into.",
		},
		fieldScannedCount: {
			Type:        schema.TypeInt,
			Computed:    true,
			Description: "Number of secrets found in the source.",
		},
		listField: {
			Type:        schema.TypeList,
			Computed:    true,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: fmt.Sprintf("Destination paths of the secrets %s.", verb),
		},
		countField: {
			Type:        schema.TypeInt,
			Computed:    true,
			Description: fmt.Sprintf("Number of secrets %s.", verb),
		},
		fieldIgnored: {
			Type:        schema.TypeList,
			Computed:    true,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "Source secrets not selected by the source's filter.",
		},
		fieldFailed: {
			Type:        schema.TypeMap,
			Computed:    true,
			Elem:        &schema.Schema{Type: schema.TypeString},
			Description: "Destination paths that failed to import, mapped to the error.",
		},
		fieldFailedCount: {
			Type:        schema.TypeInt,
			Computed:    true,
			Description: "Number of secrets that failed to import.",
		},
	}
}

// addSecretsImportSourceRefSchema adds the type and name attributes that identify
// the import source to plan or apply.
func addSecretsImportSourceRefSchema(s map[string]*schema.Schema, forceNew bool, verb string) {
	s[consts.FieldType] = &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ForceNew:     forceNew,
		Description:  fmt.Sprintf("Type of the import source to %s: aws-sm, azure-kv or gcp-sm.", verb),
		ValidateFunc: validation.StringInSlice([]string{importSourceTypeAWS, importSourceTypeAzure, importSourceTypeGCP}, false),
	}
	s[consts.FieldName] = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    forceNew,
		Description: fmt.Sprintf("Name of the import source to %s.", verb),
	}
}

// importResult is the response of sys/import/sources/:type/:name/plan and /apply.
type importResult struct {
	AuthMode         string
	DestinationMount string
	ScannedCount     int
	Secrets          []string
	Ignored          []string
	Failed           map[string]string
}

func parseImportResponse(data map[string]interface{}, operation string) (*importResult, error) {
	secretsKey := fieldImported
	if operation == importOperationPlan {
		secretsKey = fieldWouldImport
	}

	res := &importResult{
		AuthMode:         toString(data[fieldAuthMode]),
		DestinationMount: toString(data[fieldDestinationMount]),
		Secrets:          toStringSlice(data[secretsKey]),
		Ignored:          toStringSlice(data[fieldIgnored]),
		Failed:           map[string]string{},
	}

	var err error
	if res.ScannedCount, err = toInt(data[fieldScannedCount]); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", fieldScannedCount, err)
	}
	if failed, ok := data[fieldFailed].(map[string]interface{}); ok {
		for k, v := range failed {
			res.Failed[k] = toString(v)
		}
	}

	return res, nil
}

// runSecretsImport calls plan (GET) or apply (POST) on the import source and
// parses the result.
func runSecretsImport(ctx context.Context, client *api.Client, sourceType, name, operation string) (*importResult, error) {
	path := fmt.Sprintf("%s/%s", secretsImportSourcePath(sourceType, name), operation)
	source := sourceType + "/" + name

	log.Printf("[DEBUG] Running secrets import %s at %q", operation, path)
	var (
		resp *api.Secret
		err  error
	)
	if operation == importOperationPlan {
		resp, err = client.Logical().ReadWithContext(ctx, path)
	} else {
		resp, err = client.Logical().WriteWithContext(ctx, path, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("error running secrets import %s for source %q: %w", operation, source, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response running secrets import %s for source %q", operation, source)
	}

	return parseImportResponse(resp.Data, operation)
}

func setImportResult(d *schema.ResourceData, res *importResult, listField, countField string) error {
	for k, v := range map[string]interface{}{
		fieldAuthMode:         res.AuthMode,
		fieldDestinationMount: res.DestinationMount,
		fieldScannedCount:     res.ScannedCount,
		listField:             res.Secrets,
		countField:            len(res.Secrets),
		fieldIgnored:          res.Ignored,
		fieldFailed:           res.Failed,
		fieldFailedCount:      len(res.Failed),
	} {
		if err := d.Set(k, v); err != nil {
			return fmt.Errorf("error setting state key %q: %w", k, err)
		}
	}
	return nil
}

func secretsImportApplyCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	sourceType := d.Get(consts.FieldType).(string)
	name := d.Get(consts.FieldName).(string)
	res, err := runSecretsImport(ctx, client, sourceType, name, importOperationApply)
	if err != nil {
		return diag.FromErr(err)
	}

	appliedAt := time.Now().UTC().Format(time.RFC3339)
	d.SetId(fmt.Sprintf("%s/%s/%s", sourceType, name, appliedAt))
	if err := d.Set(fieldAppliedAt, appliedAt); err != nil {
		return diag.FromErr(err)
	}
	if err := setImportResult(d, res, fieldImported, fieldImportedCount); err != nil {
		return diag.FromErr(err)
	}

	if len(res.Failed) == 0 {
		return nil
	}

	failures := make([]string, 0, len(res.Failed))
	for p, msg := range res.Failed {
		failures = append(failures, fmt.Sprintf("%s: %s", p, msg))
	}
	sort.Strings(failures)
	severity := diag.Warning
	if d.Get(fieldFailOnError).(bool) {
		severity = diag.Error
	}
	return diag.Diagnostics{{
		Severity: severity,
		Summary: fmt.Sprintf("%d of %d secrets failed to import from source %q",
			len(res.Failed), len(res.Failed)+len(res.Secrets), sourceType+"/"+name),
		Detail: strings.Join(failures, "\n"),
	}}
}

// secretsImportApplyRead keeps the recorded result. The source's last_apply only
// holds the latest run, so it is not used to refresh this resource.
func secretsImportApplyRead(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	return nil
}

func secretsImportApplyDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	log.Printf("[DEBUG] Removing secrets import apply %q from state; imported secrets are kept", d.Id())
	return nil
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toStringSlice(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case nil:
		return 0, nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case float64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, fmt.Errorf("unexpected type %T", v)
	}
}
