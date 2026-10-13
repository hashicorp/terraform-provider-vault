package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kvSecretV2MetadataDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
			const includeData = false

			return kvSecretV2DataSourceRead(ctx, d, meta, includeData)
		}),
		Schema: kvSecretV2DataSourceMetadataFields,
	}
}
