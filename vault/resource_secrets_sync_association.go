// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	syncutil "github.com/hashicorp/terraform-provider-vault/internal/sync"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

const (
	fieldSecretName = "secret_name"
	fieldSyncStatus = "sync_status"
	fieldUpdatedAt  = "updated_at"
	fieldSubkey     = "sub_key"
)

func secretsSyncAssociationResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(secretsSyncAssociationWrite, provider.VaultVersion116),
		ReadContext:   provider.ReadContextWrapper(secretsSyncAssociationRead),
		DeleteContext: secretsSyncAssociationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: func(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				// Check if user is trying to use traditional ID-based import
				if d.Id() != "" {
					return nil, fmt.Errorf("traditional ID-based import is not supported. Please use identity-based import with the following format:\n\n"+
						"import {\n"+
						"  to = vault_secrets_sync_association.example\n"+
						"  identity = {\n"+
						"    type        = \"destination-type\"  # e.g., \"gh\", \"aws-sm\", \"vercel-project\"\n"+
						"    name        = \"destination-name\"  # e.g., \"my-destination\"\n"+
						"    mount       = \"mount-path\"        # e.g., \"kvv2\"\n"+
						"    secret_name = \"secret-name\"       # e.g., \"my-secret\"\n"+
						"  }\n"+
						"}\n\n"+
						"For your import ID %q, use:\n"+
						"  type        = Extract from your ID\n"+
						"  name        = Extract from your ID\n"+
						"  mount       = Extract from your ID\n"+
						"  secret_name = Extract from your ID", d.Id())
				}

				// Only support identity-based import
				identity, err := d.Identity()
				if err != nil {
					return nil, fmt.Errorf("error getting identity: %s", err)
				}

				// Get all fields from identity
				destType := identity.Get(consts.FieldType).(string)
				name := identity.Get(consts.FieldName).(string)
				mount := identity.Get(consts.FieldMount).(string)
				secretName := identity.Get(fieldSecretName).(string)

				// Validate that all required fields are provided
				if destType == "" || name == "" || mount == "" || secretName == "" {
					return nil, fmt.Errorf("all identity fields are required: type, name, mount, and secret_name must be provided")
				}

				// Set all identity fields to state
				if err := d.Set(consts.FieldType, destType); err != nil {
					return nil, err
				}
				if err := d.Set(consts.FieldName, name); err != nil {
					return nil, err
				}
				if err := d.Set(consts.FieldMount, mount); err != nil {
					return nil, err
				}
				if err := d.Set(fieldSecretName, secretName); err != nil {
					return nil, err
				}

				// Set the ID
				d.SetId(fmt.Sprintf("%s/dest/%s/mount/%s/secret/%s", destType, name, mount, secretName))

				return []*schema.ResourceData{d}, nil
			},
		},

		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the destination.",
				ForceNew:    true,
			},
			consts.FieldType: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Type of sync destination.",
				ForceNew:    true,
			},
			consts.FieldMount: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the mount where the secret is located.",
			},
			fieldSecretName: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Specifies the name of the secret to synchronize.",
			},
			consts.FieldMetadata: {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Metadata for each subkey of the associated secret.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						fieldSyncStatus: {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Sync status of the particular subkey.",
						},
						fieldUpdatedAt: {
							Type:     schema.TypeString,
							Computed: true,
							Description: "Duration string stating when the secret was " +
								"last updated for this subkey.",
						},
						fieldSubkey: {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "Subkey of the associated secret.",
						},
					},
				},
			},
		},
		Identity: &schema.ResourceIdentity{
			SchemaFunc: func() map[string]*schema.Schema {
				return map[string]*schema.Schema{
					consts.FieldType: {
						Type:              schema.TypeString,
						RequiredForImport: true,
					},
					consts.FieldName: {
						Type:              schema.TypeString,
						RequiredForImport: true,
					},
					consts.FieldMount: {
						Type:              schema.TypeString,
						RequiredForImport: true,
					},
					fieldSecretName: {
						Type:              schema.TypeString,
						RequiredForImport: true,
					},
				}
			},
		},
	}
}

func secretsSyncAssociationWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	name := d.Get(consts.FieldName).(string)
	destType := d.Get(consts.FieldType).(string)
	secretName := d.Get(fieldSecretName).(string)
	mount := d.Get(consts.FieldMount).(string)

	path := secretsSyncAssociationSetPath(name, destType)

	data := map[string]interface{}{
		fieldSecretName:   secretName,
		consts.FieldMount: mount,
	}

	log.Printf("[DEBUG] Writing association to %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error setting secrets sync association %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote association to %q", path)

	// ex: gh/dest/gh-dest-1/mount/kv/secret/token
	// unique. each destination should only have one association for a particular accessor and secret
	id := fmt.Sprintf("%s/dest/%s/mount/%s/secret/%s", destType, name, mount, secretName)
	d.SetId(id)

	// Identity data will be set by the Read function
	return secretsSyncAssociationRead(ctx, d, meta)
}

func secretsSyncAssociationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	// Get fields from resource data instead of parsing ID
	typ := d.Get(consts.FieldType).(string)
	destName := d.Get(consts.FieldName).(string)
	mount := d.Get(consts.FieldMount).(string)
	secretName := d.Get(fieldSecretName).(string)

	if err := d.Set(fieldSecretName, secretName); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldName, destName); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldType, typ); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}

	// Update identity data during read
	identity, err := d.Identity()
	if err != nil {
		return diag.FromErr(err)
	}

	if err := identity.Set(consts.FieldType, typ); err != nil {
		return diag.FromErr(err)
	}

	if err := identity.Set(consts.FieldName, destName); err != nil {
		return diag.FromErr(err)
	}

	if err := identity.Set(consts.FieldMount, mount); err != nil {
		return diag.FromErr(err)
	}

	if err := identity.Set(fieldSecretName, secretName); err != nil {
		return diag.FromErr(err)
	}

	accessor, err := getMountAccessor(ctx, d, meta, mount)
	if err != nil {
		return diag.Errorf("could not obtain accessor from given mount; err=%s", err)
	}
	// List all associations for secret destination
	resp, err := client.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/%s", syncutil.SecretsSyncDestinationPath(destName, typ), "associations"))
	if err != nil {
		return diag.Errorf("error reading associations for destination %s of type %s", destName, typ)
	}

	model, err := getSyncAssociationModelFromResponse(resp)
	if err != nil {
		return diag.FromErr(err)
	}

	metadata := make([]map[string]interface{}, 0)
	for _, v := range model.AssociatedSecrets {
		if v.SecretName == secretName && v.Accessor == accessor {
			m := map[string]interface{}{
				fieldSubkey:     v.Subkey,
				fieldSyncStatus: v.SyncStatus,
				fieldUpdatedAt:  v.UpdatedAt,
			}

			metadata = append(metadata, m)
		}
	}

	if len(metadata) == 0 {
		log.Printf("[WARN] no associated secrets found for given mount accessor and secret name %s/%s, removing from state", accessor, secretName)
		d.SetId("")
		return nil
	}

	if err := d.Set(consts.FieldMetadata, metadata); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func secretsSyncAssociationDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	// Get fields from resource data instead of parsing ID
	destType := d.Get(consts.FieldType).(string)
	destName := d.Get(consts.FieldName).(string)
	mount := d.Get(consts.FieldMount).(string)
	secretName := d.Get(fieldSecretName).(string)

	path := secretsSyncAssociationDeletePath(destName, destType)

	data := map[string]interface{}{
		fieldSecretName:   secretName,
		consts.FieldMount: mount,
	}

	log.Printf("[DEBUG] Removing association from %q", path)
	_, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return diag.Errorf("error removing secrets sync association %q: %s", path, err)
	}
	log.Printf("[DEBUG] Removed association from %q", path)

	return nil
}

func secretsSyncAssociationSetPath(name, destType string) string {
	return fmt.Sprintf("sys/sync/destinations/%s/%s/associations/set", destType, name)
}

func secretsSyncAssociationDeletePath(name, destType string) string {
	return fmt.Sprintf("sys/sync/destinations/%s/%s/associations/remove", destType, name)
}

func getMountAccessor(ctx context.Context, d *schema.ResourceData, meta interface{}, mount string) (string, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return "", e
	}

	log.Printf("[DEBUG] Reading mount %s from Vault", mount)

	m, err := mountutil.GetMount(ctx, client, mount)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			return "", fmt.Errorf("expected mount at %s; no mount found: %w", mount, err)
		}
		return "", err
	}

	return m.Accessor, nil
}

type syncAssociationModel struct {
	AssociatedSecrets map[string]syncAssociationData `json:"associated_secrets"`
}

type syncAssociationData struct {
	Accessor   string `json:"accessor"`
	SecretName string `json:"secret_name"`
	SyncStatus string `json:"sync_status"`
	UpdatedAt  string `json:"updated_at"`
	Subkey     string `json:"sub_key"`
}

func getSyncAssociationModelFromResponse(resp *api.Secret) (*syncAssociationModel, error) {
	// convert resp data to JSON
	b, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("error converting vault response to JSON; err=%s", err)
	}

	// convert JSON to struct
	var model *syncAssociationModel
	err = json.Unmarshal(b, &model)
	if err != nil {
		return nil, fmt.Errorf("error converting JSON to sync association model; err=%s", err)
	}

	return model, nil
}
