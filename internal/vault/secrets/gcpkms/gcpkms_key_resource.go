// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package gcpkms

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var idRe = regexp.MustCompile(`^([^/]+)/keys/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &GCPKMSSecretBackendKeyResource{}

// NewGCPKMSSecretBackendKeyResource returns the implementation for this resource
func NewGCPKMSSecretBackendKeyResource() resource.Resource {
	return &GCPKMSSecretBackendKeyResource{}
}

// GCPKMSSecretBackendKeyResource implements the methods that define this resource
type GCPKMSSecretBackendKeyResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// GCPKMSSecretBackendKeyModel describes the Terraform resource data model
type GCPKMSSecretBackendKeyModel struct {
	base.BaseModelLegacy

	Mount                   types.String `tfsdk:"mount"`
	Name                    types.String `tfsdk:"name"`
	KeyRing                 types.String `tfsdk:"key_ring"`
	CryptoKey               types.String `tfsdk:"crypto_key"`
	Purpose                 types.String `tfsdk:"purpose"`
	Algorithm               types.String `tfsdk:"algorithm"`
	ProtectionLevel         types.String `tfsdk:"protection_level"`
	Labels                  types.Map    `tfsdk:"labels"`
	RotationPeriod          types.String `tfsdk:"rotation_period"`
	RotationScheduleSeconds types.Int64  `tfsdk:"rotation_schedule_seconds"`
	LatestVersion           types.Int64  `tfsdk:"latest_version"`
	PrimaryVersion          types.Int64  `tfsdk:"primary_version"`
	NextRotationTimeSeconds types.Int64  `tfsdk:"next_rotation_time_seconds"`
}

func (r *GCPKMSSecretBackendKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gcpkms_secret_backend_key"
}

func (r *GCPKMSSecretBackendKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the GCP KMS secrets engine is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the key.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyRing: schema.StringAttribute{
				MarkdownDescription: "GCP KMS key ring resource ID (e.g., 'projects/my-project/locations/us-central1/keyRings/my-ring'). Required.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldCryptoKey: schema.StringAttribute{
				MarkdownDescription: "Name of the crypto key to use in GCP KMS. If the crypto key does not exist," +
					"Vault will try to create it. This defaults to the Vault key name if unspecified.",
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldPurpose: schema.StringAttribute{
				MarkdownDescription: "Purpose of the key. Valid values: ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldAlgorithm: schema.StringAttribute{
				MarkdownDescription: "Algorithm to use for the key.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldProtectionLevel: schema.StringAttribute{
				MarkdownDescription: "Protection level of the key. Valid values: SOFTWARE, HSM. Defaults to SOFTWARE.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldLabels: schema.MapAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Labels to apply to the key.",
				Optional:            true,
			},
			consts.FieldRotationPeriod: schema.StringAttribute{
				MarkdownDescription: "Rotation period for the key as a duration string (e.g., '72h', '2592000s' for 30 days). " +
					"Can be updated after creation.",
				Optional: true,
			},
			consts.FieldRotationScheduleSeconds: schema.Int64Attribute{
				MarkdownDescription: "Rotation period in seconds as returned by the Vault API. Populated from the API response; " +
					"use rotation_period to configure the desired rotation schedule.",
				Computed: true,
			},
			consts.FieldLatestVersion: schema.Int64Attribute{
				MarkdownDescription: "Latest version of the crypto key.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldPrimaryVersion: schema.Int64Attribute{
				MarkdownDescription: "Primary version of the crypto key.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldNextRotationTimeSeconds: schema.Int64Attribute{
				MarkdownDescription: "Unix timestamp of the next scheduled rotation of the crypto key. Only set for symmetric keys with a rotation_period.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Manages a GCP KMS key in Vault.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *GCPKMSSecretBackendKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GCPKMSSecretBackendKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Mount.ValueString()
	name := data.Name.ValueString()
	keyPath := buildKeyPath(backend, name)

	// Build the key configuration from the model
	keyData, diags := buildKeyConfigFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("[DEBUG] Creating GCP KMS key at %q with data: %+v", keyPath, keyData)
	if _, err := cli.Logical().WriteWithContext(ctx, keyPath, keyData); err != nil {
		resp.Diagnostics.AddError(
			"Error creating GCP KMS key",
			fmt.Sprintf("Error creating GCP KMS key at path %q: %s", keyPath, err),
		)
		return
	}

	// Set initial state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the key to get computed values
	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}
	r.Read(ctx, readReq, &readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

func (r *GCPKMSSecretBackendKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GCPKMSSecretBackendKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Mount.ValueString()
	name := data.Name.ValueString()
	keyPath := buildKeyPath(backend, name)

	// Set ID
	data.ID = types.StringValue(keyPath)

	log.Printf("[DEBUG] Reading GCP KMS key from %q", keyPath)
	secret, err := cli.Logical().ReadWithContext(ctx, keyPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading GCP KMS key",
			fmt.Sprintf("Error reading GCP KMS key from path %q: %s", keyPath, err),
		)
		return
	}

	if secret == nil {
		log.Printf("[WARN] GCP KMS key not found at %q, removing from state", keyPath)
		resp.State.RemoveResource(ctx)
		return
	}

	// Update model from API response
	if v, ok := secret.Data[consts.FieldPurpose].(string); ok {
		data.Purpose = types.StringValue(v)
	}
	if v, ok := secret.Data[consts.FieldAlgorithm].(string); ok {
		data.Algorithm = types.StringValue(v)
	}
	if v, ok := secret.Data[consts.FieldProtectionLevel].(string); ok {
		data.ProtectionLevel = types.StringValue(v)
	}

	// Vault returns purpose in lowercase (e.g. "asymmetric_sign"), but users may configure
	// it in any case (e.g. "ASYMMETRIC_SIGN"). Use case-insensitive comparison throughout.
	isAsymmetric := false
	if purpose, ok := secret.Data[consts.FieldPurpose].(string); ok {
		p := strings.ToLower(purpose)
		isAsymmetric = p == "asymmetric_sign" || p == "asymmetric_decrypt"
	}

	if isAsymmetric {
		// Asymmetric keys do not support rotation, so these fields are always null.
		data.RotationScheduleSeconds = types.Int64Null()
		data.NextRotationTimeSeconds = types.Int64Null()
		// primary_version is returned by the API as a string (e.g. "1").
		if version, ok := getInt64FromData(secret.Data, consts.FieldPrimaryVersion); ok {
			data.PrimaryVersion = types.Int64Value(version)
			data.LatestVersion = types.Int64Value(version)
		} else if data.PrimaryVersion.IsNull() || data.PrimaryVersion.IsUnknown() {
			data.PrimaryVersion = types.Int64Value(1)
			data.LatestVersion = types.Int64Value(1)
		}
	} else {
		// rotation_period: preserve the user's configured value exactly (e.g. "72h").
		// Only populate from the API when state is null/unknown (i.e. during import).
		if data.RotationPeriod.IsNull() || data.RotationPeriod.IsUnknown() {
			if seconds, ok := getInt64FromData(secret.Data, consts.FieldRotationScheduleSeconds); ok && seconds > 0 {
				data.RotationPeriod = types.StringValue(fmt.Sprintf("%ds", seconds))
			}
		}

		// rotation_schedule_seconds: always reflect the canonical seconds value from Vault.
		if seconds, ok := getInt64FromData(secret.Data, consts.FieldRotationScheduleSeconds); ok {
			data.RotationScheduleSeconds = types.Int64Value(seconds)
		} else {
			data.RotationScheduleSeconds = types.Int64Null()
		}

		// next_rotation_time_seconds: always refresh from API for symmetric keys.
		if ts, ok := getInt64FromData(secret.Data, consts.FieldNextRotationTimeSeconds); ok {
			data.NextRotationTimeSeconds = types.Int64Value(ts)
		} else {
			data.NextRotationTimeSeconds = types.Int64Null()
		}

		// primary_version / latest_version
		if version, ok := getInt64FromData(secret.Data, consts.FieldPrimaryVersion); ok {
			data.PrimaryVersion = types.Int64Value(version)
			data.LatestVersion = types.Int64Value(version)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GCPKMSSecretBackendKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state GCPKMSSecretBackendKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := plan.Mount.ValueString()
	name := plan.Name.ValueString()
	keyPath := buildKeyPath(backend, name)

	// Check what fields have changed
	rotationChanged := !plan.RotationPeriod.Equal(state.RotationPeriod)
	labelsChanged := !plan.Labels.Equal(state.Labels)

	// For GCP KMS updates, Vault requires key_ring for validation but rejects
	// other immutable fields (purpose, algorithm, protection_level)
	// Only rotation_period and labels can be updated
	updateData := make(map[string]interface{})

	// Include key_ring from state (required by Vault for validation)
	if !state.KeyRing.IsNull() && !state.KeyRing.IsUnknown() {
		updateData[consts.FieldKeyRing] = state.KeyRing.ValueString()
	}

	// Only include mutable fields
	if !plan.RotationPeriod.IsNull() && !plan.RotationPeriod.IsUnknown() {
		updateData[consts.FieldRotationPeriod] = plan.RotationPeriod.ValueString()
	}

	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		var labels map[string]string
		resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &labels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateData[consts.FieldLabels] = labels
	} else if plan.Labels.IsNull() {
		// If labels is explicitly set to null, send empty map to clear labels
		updateData[consts.FieldLabels] = map[string]string{}
	}

	// Only perform update if there are actual changes to mutable fields
	hasChanges := rotationChanged || labelsChanged

	if hasChanges && len(updateData) > 0 {
		log.Printf("[DEBUG] Updating GCP KMS key at %q with data: %+v", keyPath, updateData)
		if _, err := cli.Logical().WriteWithContext(ctx, keyPath, updateData); err != nil {
			resp.Diagnostics.AddError(
				"Error updating GCP KMS key",
				fmt.Sprintf("Error updating GCP KMS key at path %q: %s", keyPath, err),
			)
			return
		}
	}

	// Set state from plan
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read to refresh computed values
	readReq := resource.ReadRequest{State: resp.State}
	readResp := resource.ReadResponse{State: resp.State}
	r.Read(ctx, readReq, &readResp)
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

func (r *GCPKMSSecretBackendKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GCPKMSSecretBackendKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Mount.ValueString()
	name := data.Name.ValueString()
	keyPath := buildKeyPath(backend, name)

	log.Printf("[DEBUG] Deleting GCP KMS key at %q", keyPath)
	if _, err := cli.Logical().DeleteWithContext(ctx, keyPath); err != nil {
		// Check if this is the known issue with asymmetric keys and rotation
		// This is a Vault backend bug where it tries to disable rotation on asymmetric keys during deletion
		// which GCP KMS doesn't allow. We can safely ignore this error because:
		// 1. The key is being deleted anyway (not just having rotation disabled)
		// 2. Asymmetric keys don't support rotation in the first place
		// 3. The resource will be removed from Terraform state regardless
		errStr := err.Error()
		if strings.Contains(errStr, "failed to disable rotation") &&
			strings.Contains(errStr, "rotation_period must not be set if purpose is ASYMMETRIC_") {
			log.Printf("[WARN] Ignoring rotation disable error for asymmetric key during deletion: %s", err)
			// Continue with removal from state despite the Vault error
			// The key reference is removed from Vault's tracking even if GCP deletion partially failed
			return
		}

		resp.Diagnostics.AddError(
			"Error deleting GCP KMS key",
			fmt.Sprintf("Error deleting GCP KMS key at path %q: %s", keyPath, err),
		)
		return
	}
}

func (r *GCPKMSSecretBackendKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Expected format: backend/keys/name
	matches := idRe.FindStringSubmatch(req.ID)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format 'backend/keys/name', got: %q", req.ID),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), matches[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), matches[2])...)
}

// buildKeyPath constructs the Vault API path for a GCP KMS key
func buildKeyPath(backend, name string) string {
	return fmt.Sprintf("%s/keys/%s", backend, name)
}

// buildKeyConfigFromModel extracts the key configuration data from the model
// and returns a map suitable for writing to Vault's GCP KMS key endpoint.
//
// According to Vault GCP KMS API:
// - key_ring: Required - GCP KMS key ring where the crypto key will be created/used
// - crypto_key: Optional - Name of the crypto key in GCP KMS. Defaults to the Vault key name if not specified
func buildKeyConfigFromModel(ctx context.Context, data *GCPKMSSecretBackendKeyModel) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	keyData := make(map[string]interface{})

	// key_ring is required
	if data.KeyRing.IsNull() || data.KeyRing.ValueString() == "" {
		diags.AddError(
			"Missing required field",
			"key_ring is required when creating a GCP KMS key",
		)
		return nil, diags
	}

	keyData[consts.FieldKeyRing] = data.KeyRing.ValueString()
	log.Printf("[DEBUG] buildKeyConfigFromModel - Using key_ring: %s", data.KeyRing.ValueString())

	// crypto_key is optional - if not specified, defaults to the Vault key name
	if !data.CryptoKey.IsNull() && data.CryptoKey.ValueString() != "" {
		keyData[consts.FieldCryptoKey] = data.CryptoKey.ValueString()
		log.Printf("[DEBUG] buildKeyConfigFromModel - Using custom crypto_key name: %s", data.CryptoKey.ValueString())
	}

	// Add optional fields for key creation
	if !data.Purpose.IsNull() && data.Purpose.ValueString() != "" {
		keyData[consts.FieldPurpose] = data.Purpose.ValueString()
	}
	if !data.Algorithm.IsNull() && data.Algorithm.ValueString() != "" {
		keyData[consts.FieldAlgorithm] = data.Algorithm.ValueString()
	}
	if !data.ProtectionLevel.IsNull() && data.ProtectionLevel.ValueString() != "" {
		keyData[consts.FieldProtectionLevel] = data.ProtectionLevel.ValueString()
	}
	if !data.RotationPeriod.IsNull() && data.RotationPeriod.ValueString() != "" {
		keyData[consts.FieldRotationPeriod] = data.RotationPeriod.ValueString()
	}
	if !data.Labels.IsNull() {
		var labels map[string]string
		diags.Append(data.Labels.ElementsAs(ctx, &labels, false)...)
		if diags.HasError() {
			return nil, diags
		}
		if len(labels) > 0 {
			keyData[consts.FieldLabels] = labels
		}
	}

	return keyData, diags
}

// getInt64FromData extracts an int64 value from a Vault API response map.
// Vault can return numeric values as float64 (JSON default), int64, or string.
func getInt64FromData(data map[string]interface{}, key string) (int64, bool) {
	v, exists := data[key]
	if !exists || v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case float64:
		return int64(val), true
	case int64:
		return val, true
	case int:
		return int64(val), true
	case json.Number:
		i, err := val.Int64()
		return i, err == nil
	case string:
		if val == "" {
			return 0, false
		}
		i, err := strconv.ParseInt(val, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}
