// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	syncutil "github.com/hashicorp/terraform-provider-vault/internal/sync"
)

const (
	fieldProjectID              = "project_id"
	fieldTeamID                 = "team_id"
	fieldDeploymentEnvironments = "deployment_environments"
	vercelSyncType              = "vercel-project"
)

var vercelSyncWriteFields = []string{
	fieldAccessToken,
	fieldProjectID,
	fieldTeamID,
	fieldDeploymentEnvironments,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
}

var vercelSyncReadFields = []string{
	fieldProjectID,
	fieldTeamID,
	fieldDeploymentEnvironments,
	consts.FieldGranularity,
	consts.FieldSecretNameTemplate,
}

func vercelSecretsSyncDestinationResource() *schema.Resource {
	return provider.MustAddSecretsSyncCommonSchema(&schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(vercelSecretsSyncDestinationCreateUpdate, provider.VaultVersion116),
		UpdateContext: vercelSecretsSyncDestinationCreateUpdate,
		ReadContext:   provider.ReadContextWrapper(vercelSecretsSyncDestinationRead),
		DeleteContext: vercelSecretsSyncDestinationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Unique name of the Vercel destination.",
				ForceNew:    true,
			},
			fieldAccessToken: {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
				Description: "Vercel API access token with the permissions to manage " +
					"environment variables.",
			},
			fieldProjectID: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Project ID where to manage environment variables.",
				ForceNew:    true,
			},
			fieldTeamID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Team ID the project belongs to.",
			},
			fieldDeploymentEnvironments: {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Required: true,
				Description: "Deployment environments where the environment " +
					"variables are available. Accepts 'development', " +
					"'preview' & 'production'.",
			},
		},
	})
}

func vercelSecretsSyncDestinationCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationCreateUpdate(ctx, d, meta, vercelSyncType, vercelSyncWriteFields, vercelSyncReadFields)
}

func vercelSecretsSyncDestinationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationRead(ctx, d, meta, vercelSyncType, vercelSyncReadFields, map[string]string{
		consts.FieldGranularity: consts.FieldGranularityLevel,
	})
}

func vercelSecretsSyncDestinationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return syncutil.SyncDestinationDelete(ctx, d, meta, vercelSyncType)
}
