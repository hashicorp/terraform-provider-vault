// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package util

import (
	fwdiag "github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const metadataWarningSummary = "Vault reported a warning while writing metadata"

// MetadataWriteWarnings returns the warnings on a Vault write response when the
// request carried metadata. Vault returns 200 with a warning when the object
// write succeeded but the metadata write did not, so the warning is the only
// signal that metadata is stale. Requests without metadata return nil so that
// unrelated plugin warnings are not newly surfaced.
func MetadataWriteWarnings(resp *api.Secret, data map[string]interface{}) []string {
	if resp == nil || len(resp.Warnings) == 0 {
		return nil
	}
	if _, ok := data[consts.FieldMetadata]; !ok {
		return nil
	}
	return resp.Warnings
}

// MetadataWriteDiags returns Terraform warning diagnostics for the warnings
// reported by MetadataWriteWarnings.
func MetadataWriteDiags(resp *api.Secret, data map[string]interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	for _, w := range MetadataWriteWarnings(resp, data) {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  metadataWarningSummary,
			Detail:   w,
		})
	}
	return diags
}

// MetadataWriteFrameworkDiags is MetadataWriteDiags for Plugin Framework resources.
func MetadataWriteFrameworkDiags(resp *api.Secret, data map[string]interface{}) fwdiag.Diagnostics {
	var diags fwdiag.Diagnostics
	for _, w := range MetadataWriteWarnings(resp, data) {
		diags.AddWarning(metadataWarningSummary, w)
	}
	return diags
}
