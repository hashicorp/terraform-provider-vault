// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// secretsImportPlanDataSource previews an import source. Data sources are read
// during terraform plan, so the preview shows up before anything is imported.
func secretsImportPlanDataSource() *schema.Resource {
	s := secretsImportResultSchema(fieldWouldImport, fieldWouldImportCnt, "that would be imported")
	addSecretsImportSourceRefSchema(s, false, "preview")

	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(secretsImportPlanDataSourceRead),
		Schema:      s,
	}
}

func secretsImportPlanDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if !provider.IsAPISupported(meta, secretsImportMinVersion) {
		return diag.Errorf("feature not enabled on current Vault version. min version required=%s", secretsImportMinVersion)
	}

	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	sourceType := d.Get(consts.FieldType).(string)
	name := d.Get(consts.FieldName).(string)
	res, err := runSecretsImport(ctx, client, sourceType, name, importOperationPlan)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(sourceType + "/" + name)
	if err := setImportResult(d, res, fieldWouldImport, fieldWouldImportCnt); err != nil {
		return diag.FromErr(err)
	}

	return nil
}
