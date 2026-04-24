// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	syncutil "github.com/hashicorp/terraform-provider-vault/internal/sync"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

var syncAssociationFieldsFromIDRegex = regexp.MustCompile("^(.+)/dest/(.+)/mount/(.+)/secret/(.+)$")

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
			StateContext: schema.ImportStatePassthroughContext,
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

	// Length-based ID format: {len1},{len2},{len3},{len4}:{destType}:{name}:{mount}:{secretName}
	// Example: 7,8,2,5:aws-kms:my-mount:kv:token
	id := fmt.Sprintf("%d,%d,%d,%d:%s:%s:%s:%s",
		len(destType), len(name), len(mount), len(secretName),
		destType, name, mount, secretName)
	d.SetId(id)

	return secretsSyncAssociationRead(ctx, d, meta)
}

func secretsSyncAssociationRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	id := d.Id()
	fields, err := syncAssociationFieldsFromID(id)
	if err != nil {
		return diag.FromErr(err)
	}

	typ := fields[0]
	destName := fields[1]
	mount := fields[2]
	secretName := fields[3]

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

	id := d.Id()
	fields, err := syncAssociationFieldsFromID(id)
	if err != nil {
		return diag.FromErr(err)
	}

	destType := fields[0]
	destName := fields[1]
	mount := fields[2]
	secretName := fields[3]

	path := secretsSyncAssociationDeletePath(destName, destType)

	data := map[string]interface{}{
		fieldSecretName:   secretName,
		consts.FieldMount: mount,
	}

	log.Printf("[DEBUG] Removing association from %q", path)
	_, err = client.Logical().WriteWithContext(ctx, path, data)
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

// isLengthBasedIDFormat checks if ID uses length-based format (starts with digit).
func isLengthBasedIDFormat(id string) bool {
	return len(id) > 0 && id[0] >= '0' && id[0] <= '9'
}

// parseLengthBasedID parses length-based ID format.
// Format: {len1},{len2},{len3},{len4}:{destType}:{name}:{mount}:{secretName}
// Returns: [destType, name, mount, secretName]
func parseLengthBasedID(id string) ([]string, error) {
	// Find the first colon that separates lengths from values
	colonIdx := strings.Index(id, ":")
	if colonIdx == -1 {
		return nil, fmt.Errorf("invalid length-based ID format: expected format {len1},{len2},{len3},{len4}:{values}")
	}

	lengthsPart := id[:colonIdx]
	valuesPart := id[colonIdx+1:] // Skip the first colon

	// Parse the lengths
	lengthStrs := strings.Split(lengthsPart, ",")
	if len(lengthStrs) != 4 {
		return nil, fmt.Errorf("invalid length-based ID format: expected 4 length values, got %d", len(lengthStrs))
	}

	lengths := make([]int, 4)
	for i, lenStr := range lengthStrs {
		length, err := strconv.Atoi(lenStr)
		if err != nil {
			return nil, fmt.Errorf("invalid length value at position %d: %s", i, err)
		}
		if length < 0 {
			return nil, fmt.Errorf("invalid length value at position %d: length cannot be negative", i)
		}
		lengths[i] = length
	}

	// Extract values using the lengths, skipping colon separators
	fields := make([]string, 4)
	pos := 0
	for i := 0; i < 4; i++ {
		// Skip colon separator before each field (except the first)
		if i > 0 {
			if pos >= len(valuesPart) || valuesPart[pos] != ':' {
				return nil, fmt.Errorf("invalid length-based ID format: expected ':' separator at position %d", pos)
			}
			pos++ // Skip the colon
		}

		if pos+lengths[i] > len(valuesPart) {
			return nil, fmt.Errorf("invalid length-based ID format: length %d at position %d exceeds remaining string length", lengths[i], i)
		}

		fields[i] = valuesPart[pos : pos+lengths[i]]
		pos += lengths[i]
	}

	// Verify we've consumed the entire values part
	if pos != len(valuesPart) {
		return nil, fmt.Errorf("invalid length-based ID format: unexpected trailing data after parsing all fields")
	}

	return fields, nil
}

// syncAssociationFieldsFromID parses ID and returns [destType, name, mount, secretName].
// Supports both old and new formats for backward compatibility.
func syncAssociationFieldsFromID(id string) ([]string, error) {
	if isLengthBasedIDFormat(id) {
		return parseLengthBasedID(id)
	}

	// Old format fallback
	if !syncAssociationFieldsFromIDRegex.MatchString(id) {
		return nil, fmt.Errorf("regex did not match")
	}
	res := syncAssociationFieldsFromIDRegex.FindStringSubmatch(id)
	// 5 matches
	// full string itself
	// 4 desired fields
	if len(res) != 5 {
		return nil, fmt.Errorf("unexpected number of matches (%d) for fields; "+""+
			"format=:type/dest/:destination/mount/:mount/secret/:secretName", len(res))
	}
	return res[1:], nil
}
