// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tune

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

const (
	// ttlSystemDefault is the Vault tune sentinel that resets a lease TTL.
	// An empty string leaves the stored TTL unchanged.
	ttlSystemDefault     = "system"
	lockoutThresholdZero = "0"
	lockoutDurationZero  = "0s"
)

// lockoutAuthTypes are the auth methods that accept user lockout tuning.
var lockoutAuthTypes = map[string]struct{}{
	consts.MountTypeApprole:  {},
	consts.MountTypeLDAP:     {},
	consts.MountTypeUserpass: {},
}

var (
	_ resource.Resource                = &authTuneResource{}
	_ resource.ResourceWithConfigure   = &authTuneResource{}
	_ resource.ResourceWithImportState = &authTuneResource{}
)

// NewAuthTuneResource returns the vault_auth_tune resource.
func NewAuthTuneResource() resource.Resource {
	return &authTuneResource{}
}

type authTuneResource struct {
	base.ResourceWithConfigure
}

type authTuneModel struct {
	base.BaseModel

	Path                      types.String      `tfsdk:"path"`
	DefaultLeaseTTL           types.String      `tfsdk:"default_lease_ttl"`
	MaxLeaseTTL               types.String      `tfsdk:"max_lease_ttl"`
	ListingVisibility         types.String      `tfsdk:"listing_visibility"`
	TokenType                 types.String      `tfsdk:"token_type"`
	PluginVersion             types.String      `tfsdk:"plugin_version"`
	AuditNonHMACRequestKeys   types.List        `tfsdk:"audit_non_hmac_request_keys"`
	AuditNonHMACResponseKeys  types.List        `tfsdk:"audit_non_hmac_response_keys"`
	PassthroughRequestHeaders types.List        `tfsdk:"passthrough_request_headers"`
	AllowedResponseHeaders    types.List        `tfsdk:"allowed_response_headers"`
	UserLockoutConfig         *userLockoutModel `tfsdk:"user_lockout_config"`
}

type userLockoutModel struct {
	LockoutThreshold    types.String `tfsdk:"lockout_threshold"`
	LockoutDuration     types.String `tfsdk:"lockout_duration"`
	LockoutCounterReset types.String `tfsdk:"lockout_counter_reset"`
	LockoutDisable      types.Bool   `tfsdk:"lockout_disable"`
}

type tuneSnapshot struct {
	defaultLeaseTTL           string
	defaultLeaseTTLPresent    bool
	maxLeaseTTL               string
	maxLeaseTTLPresent        bool
	listingVisibility         string
	listingVisibilityPresent  bool
	tokenType                 string
	tokenTypePresent          bool
	pluginVersion             string
	pluginVersionPresent      bool
	auditNonHMACRequestKeys   []string
	auditRequestKeysPresent   bool
	auditNonHMACResponseKeys  []string
	auditResponseKeysPresent  bool
	passthroughRequestHeaders []string
	passthroughHeadersPresent bool
	allowedResponseHeaders    []string
	allowedHeadersPresent     bool
	lockout                   lockoutSnapshot
	lockoutPresent            bool
}

type lockoutSnapshot struct {
	threshold           string
	thresholdPresent    bool
	duration            string
	durationPresent     bool
	counterReset        string
	counterResetPresent bool
	disable             bool
	disablePresent      bool
}

func (r *authTuneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auth_tune"
}

func (r *authTuneResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Tunes an existing auth mount without managing the mount itself. " +
			"Create this resource only when a tune setting is needed. Arguments left unset are not sent to Vault and are not stored from the tune API, so Vault defaults do not appear in plans. " +
			"Removing an argument clears that setting. Destroying the resource clears every setting it managed. " +
			"Changing `path` replaces this resource and does not move the auth mount. " +
			"Do not combine this resource with a `tune` block on the auth method resource that manages the same mount.",
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					validators.PathValidator(),
				},
				MarkdownDescription: "Path of the auth mount to tune, without a leading `auth/`. This is the same value as `vault_auth_backend.path`.",
			},
			consts.FieldDefaultLeaseTTL: schema.StringAttribute{
				Optional:            true,
				Validators:          []validator.String{validators.DurationValidator()},
				MarkdownDescription: "Default lease TTL for the mount. Remove this argument to reset the mount to the system default.",
			},
			consts.FieldMaxLeaseTTL: schema.StringAttribute{
				Optional:            true,
				Validators:          []validator.String{validators.DurationValidator()},
				MarkdownDescription: "Maximum lease TTL for the mount. Remove this argument to reset the mount to the system default.",
			},
			consts.FieldAuditNonHMACRequestKeys: schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Keys that will not be HMAC'd by audit devices in the request data object.",
			},
			consts.FieldAuditNonHMACResponseKeys: schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Keys that will not be HMAC'd by audit devices in the response data object.",
			},
			consts.FieldListingVisibility: schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf("unauth", "hidden"),
				},
				MarkdownDescription: "Whether to show this mount in the UI listing endpoint. Valid values are `unauth` and `hidden`.",
			},
			consts.FieldPassthroughRequestHeaders: schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Headers to pass from the request to the auth method.",
			},
			consts.FieldAllowedResponseHeaders: schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Headers an auth method may include in the response.",
			},
			consts.FieldTokenType: schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf("default-service", "default-batch", "service", "batch"),
				},
				MarkdownDescription: "Type of tokens the mount returns. Valid values are `default-service`, `default-batch`, `service`, and `batch`.",
			},
			consts.FieldPluginVersion: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Semantic version of the plugin to use, for example `v1.0.0`. A change does not take effect until the plugin is reloaded.",
			},
		},
		Blocks: map[string]schema.Block{
			consts.FieldUserLockoutConfig: schema.SingleNestedBlock{
				MarkdownDescription: "User lockout configuration. Supported on `approle`, `ldap`, and `userpass` auth mounts, and requires Vault 1.13.0 or later. " +
					"Other auth methods reject this block.",
				Attributes: map[string]schema.Attribute{
					consts.FieldLockoutThreshold: schema.StringAttribute{
						Optional:            true,
						MarkdownDescription: "Number of failed login attempts after which the user is locked out, as a string such as `15`.",
					},
					consts.FieldLockoutDuration: schema.StringAttribute{
						Optional:            true,
						Validators:          []validator.String{validators.DurationValidator()},
						MarkdownDescription: "How long a user stays locked out, as a duration such as `5m`.",
					},
					consts.FieldLockoutCounterReset: schema.StringAttribute{
						Optional:            true,
						Validators:          []validator.String{validators.DurationValidator()},
						MarkdownDescription: "How long with no failed attempts before the lockout counter resets, as a duration such as `5m`.",
					},
					consts.FieldLockoutDisable: schema.BoolAttribute{
						Optional:            true,
						MarkdownDescription: "Disables user lockout for this mount when true.",
					},
				},
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *authTuneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan authTuneModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.apply(ctx, &plan, &authTuneModel{}, errutil.VaultCreateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *authTuneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data authTuneModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	snap, remove, diags := readTune(ctx, vaultClient, data.Path.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if remove {
		tflog.Warn(ctx, "auth mount not found, removing tune from state", map[string]any{"path": data.Path.ValueString()})
		resp.State.RemoveResource(ctx)
		return
	}

	data.refresh(ctx, snap)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *authTuneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state authTuneModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.apply(ctx, &plan, &state, errutil.VaultUpdateErr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *authTuneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data authTuneModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mountPath := data.Path.ValueString()
	if _, err := mountutil.GetAuthMount(ctx, vaultClient, mountPath); err != nil {
		if mountutil.IsMountNotFoundError(err) {
			return
		}
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}

	cfg, diags := tuneConfig(ctx, &authTuneModel{}, &data, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if tuneInputEmpty(cfg) {
		return
	}

	if err := vaultClient.Sys().TuneMountAllowNilWithContext(ctx, authTuneAPIPath(mountPath), cfg); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

func (r *authTuneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mountPath, err := authTuneImportPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import identifier", err.Error())
		return
	}

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	vaultClient, err := client.GetClient(ctx, r.Meta(), ns)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	snap, missing, diags := readTune(ctx, vaultClient, mountPath)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if missing {
		resp.Diagnostics.AddError("Auth mount not found", fmt.Sprintf("No auth method is mounted at %q.", mountPath))
		return
	}

	model := snap.importedModel(mountPath, ns)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func authTuneImportPath(id string) (string, error) {
	mountPath := strings.TrimSpace(id)
	mountPath = strings.TrimPrefix(mountPath, "auth/")
	mountPath = strings.Trim(mountPath, "/")
	if mountPath == "" {
		return "", fmt.Errorf("import identifier cannot be empty")
	}
	return mountPath, nil
}

func (r *authTuneResource) apply(ctx context.Context, plan, prior *authTuneModel, vaultErr func(error) (string, string)) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return diags
	}

	mountPath := plan.Path.ValueString()
	mount, err := mountutil.GetAuthMount(ctx, vaultClient, mountPath)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			diags.AddError(
				"Auth mount not found",
				fmt.Sprintf("No auth method is mounted at %q. Enable it before tuning.", mountPath),
			)
			return diags
		}
		diags.AddError(vaultErr(err))
		return diags
	}

	if plan.UserLockoutConfig != nil {
		diags.Append(r.validateLockout(mount.Type)...)
		if diags.HasError() {
			return diags
		}
	}

	cfg, cfgDiags := tuneConfig(ctx, plan, prior, true)
	diags.Append(cfgDiags...)
	if diags.HasError() {
		return diags
	}

	if !tuneInputEmpty(cfg) {
		if err := vaultClient.Sys().TuneMountAllowNilWithContext(ctx, authTuneAPIPath(mountPath), cfg); err != nil {
			diags.AddError(vaultErr(err))
			return diags
		}
	}

	snap, remove, readDiags := readTune(ctx, vaultClient, mountPath)
	diags.Append(readDiags...)
	if diags.HasError() || remove {
		if remove {
			diags.AddError("Auth mount not found", fmt.Sprintf("Auth method at %q disappeared while tuning.", mountPath))
		}
		return diags
	}

	plan.refresh(ctx, snap)
	return diags
}

func (r *authTuneResource) validateLockout(mountType string) diag.Diagnostics {
	var diags diag.Diagnostics
	if r.Meta() == nil || !r.Meta().IsAPISupported(provider.VaultVersion113) {
		diags.AddError(
			"User lockout is not supported",
			fmt.Sprintf("user_lockout_config requires Vault %s or later.", provider.VaultVersion113),
		)
		return diags
	}
	if _, ok := lockoutAuthTypes[mountType]; !ok {
		diags.AddError(
			"User lockout is not supported for this auth method",
			fmt.Sprintf("Auth method %q does not accept user lockout tuning. Supported types are approle, ldap, and userpass.", mountType),
		)
	}
	return diags
}

func authTuneAPIPath(mountPath string) string {
	return "auth/" + strings.Trim(mountPath, "/")
}

func readTune(ctx context.Context, vaultClient *api.Client, mountPath string) (tuneSnapshot, bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	var snap tuneSnapshot

	if _, err := mountutil.GetAuthMount(ctx, vaultClient, mountPath); err != nil {
		if mountutil.IsMountNotFoundError(err) {
			return snap, true, diags
		}
		diags.AddError(errutil.VaultReadErr(err))
		return snap, false, diags
	}

	secret, err := vaultClient.Logical().ReadWithContext(ctx, "sys/mounts/"+authTuneAPIPath(mountPath)+"/tune")
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return snap, false, diags
	}
	if secret == nil || secret.Data == nil {
		diags.AddError(errutil.VaultReadResponseNil())
		return snap, false, diags
	}

	return parseTune(secret.Data), false, diags
}

func parseTune(data map[string]interface{}) tuneSnapshot {
	var snap tuneSnapshot
	snap.defaultLeaseTTL, snap.defaultLeaseTTLPresent = durationField(data, consts.FieldDefaultLeaseTTL)
	snap.maxLeaseTTL, snap.maxLeaseTTLPresent = durationField(data, consts.FieldMaxLeaseTTL)
	snap.listingVisibility, snap.listingVisibilityPresent = stringFieldFromMap(data, consts.FieldListingVisibility)
	snap.tokenType, snap.tokenTypePresent = stringFieldFromMap(data, consts.FieldTokenType)
	snap.pluginVersion, snap.pluginVersionPresent = stringFieldFromMap(data, consts.FieldPluginVersion)
	snap.auditNonHMACRequestKeys, snap.auditRequestKeysPresent = listFieldFromMap(data, consts.FieldAuditNonHMACRequestKeys)
	snap.auditNonHMACResponseKeys, snap.auditResponseKeysPresent = listFieldFromMap(data, consts.FieldAuditNonHMACResponseKeys)
	snap.passthroughRequestHeaders, snap.passthroughHeadersPresent = listFieldFromMap(data, consts.FieldPassthroughRequestHeaders)
	snap.allowedResponseHeaders, snap.allowedHeadersPresent = listFieldFromMap(data, consts.FieldAllowedResponseHeaders)
	snap.lockout, snap.lockoutPresent = parseLockout(data)
	return snap
}

func parseLockout(data map[string]interface{}) (lockoutSnapshot, bool) {
	source := data
	present := false
	if nested, ok := data[consts.FieldUserLockoutConfig].(map[string]interface{}); ok {
		source = nested
		present = true
	}

	var snap lockoutSnapshot
	if v, ok := firstPresent(source, "user_lockout_threshold", "lockout_threshold"); ok {
		snap.threshold, snap.thresholdPresent = scalarString(v), true
		present = true
	}
	if v, ok := firstPresent(source, "user_lockout_duration", "lockout_duration"); ok {
		snap.duration, snap.durationPresent = durationFromAPI(v), true
		present = true
	}
	if v, ok := firstPresent(source, "user_lockout_counter_reset_duration", "lockout_counter_reset_duration", "lockout_counter_reset"); ok {
		snap.counterReset, snap.counterResetPresent = durationFromAPI(v), true
		present = true
	}
	if v, ok := firstPresent(source, "user_lockout_disable", "lockout_disable", "disable_lockout"); ok {
		if b, ok := boolFromAPI(v); ok {
			snap.disable = b
			snap.disablePresent = true
			present = true
		}
	}
	return snap, present
}

func (snap tuneSnapshot) importedModel(mountPath, namespace string) authTuneModel {
	model := emptyAuthTuneModel()
	model.Path = types.StringValue(mountPath)
	if namespace != "" {
		model.Namespace = types.StringValue(namespace)
	}
	model.DefaultLeaseTTL = importedString(snap.defaultLeaseTTL, snap.defaultLeaseTTLPresent)
	model.MaxLeaseTTL = importedString(snap.maxLeaseTTL, snap.maxLeaseTTLPresent)
	model.ListingVisibility = importedString(snap.listingVisibility, snap.listingVisibilityPresent)
	model.TokenType = importedString(snap.tokenType, snap.tokenTypePresent)
	model.PluginVersion = importedString(snap.pluginVersion, snap.pluginVersionPresent)
	model.AuditNonHMACRequestKeys = importedList(snap.auditNonHMACRequestKeys, snap.auditRequestKeysPresent)
	model.AuditNonHMACResponseKeys = importedList(snap.auditNonHMACResponseKeys, snap.auditResponseKeysPresent)
	model.PassthroughRequestHeaders = importedList(snap.passthroughRequestHeaders, snap.passthroughHeadersPresent)
	model.AllowedResponseHeaders = importedList(snap.allowedResponseHeaders, snap.allowedHeadersPresent)
	model.UserLockoutConfig = snap.lockout.imported(snap.lockoutPresent)
	return model
}

func emptyAuthTuneModel() authTuneModel {
	return authTuneModel{
		BaseModel: base.BaseModel{
			Namespace: types.StringNull(),
		},
		DefaultLeaseTTL:           types.StringNull(),
		MaxLeaseTTL:               types.StringNull(),
		ListingVisibility:         types.StringNull(),
		TokenType:                 types.StringNull(),
		PluginVersion:             types.StringNull(),
		AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
		AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
		PassthroughRequestHeaders: types.ListNull(types.StringType),
		AllowedResponseHeaders:    types.ListNull(types.StringType),
	}
}

func importedString(value string, present bool) types.String {
	if !present || value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

func importedList(values []string, present bool) types.List {
	values = normalizeList(values)
	if !present || len(values) == 0 {
		return types.ListNull(types.StringType)
	}
	return stringList(values)
}

func (snap lockoutSnapshot) imported(present bool) *userLockoutModel {
	if !present {
		return nil
	}
	threshold := ""
	if snap.thresholdPresent && snap.threshold != "" && snap.threshold != lockoutThresholdZero {
		threshold = snap.threshold
	}
	duration := ""
	if snap.durationPresent && snap.duration != "" && snap.duration != lockoutDurationZero {
		duration = snap.duration
	}
	counterReset := ""
	if snap.counterResetPresent && snap.counterReset != "" && snap.counterReset != lockoutDurationZero {
		counterReset = snap.counterReset
	}
	disable := snap.disablePresent && snap.disable
	if threshold == "" && duration == "" && counterReset == "" && !disable {
		return nil
	}

	model := &userLockoutModel{
		LockoutThreshold:    types.StringNull(),
		LockoutDuration:     types.StringNull(),
		LockoutCounterReset: types.StringNull(),
		LockoutDisable:      types.BoolNull(),
	}
	if threshold != "" {
		model.LockoutThreshold = types.StringValue(threshold)
	}
	if duration != "" {
		model.LockoutDuration = types.StringValue(duration)
	}
	if counterReset != "" {
		model.LockoutCounterReset = types.StringValue(counterReset)
	}
	if disable {
		model.LockoutDisable = types.BoolValue(true)
	}
	return model
}

func (m *authTuneModel) refresh(ctx context.Context, snap tuneSnapshot) {
	m.DefaultLeaseTTL = refreshDuration(m.DefaultLeaseTTL, snap.defaultLeaseTTL, snap.defaultLeaseTTLPresent)
	m.MaxLeaseTTL = refreshDuration(m.MaxLeaseTTL, snap.maxLeaseTTL, snap.maxLeaseTTLPresent)
	m.ListingVisibility = refreshString(m.ListingVisibility, snap.listingVisibility, snap.listingVisibilityPresent)
	m.TokenType = refreshString(m.TokenType, snap.tokenType, snap.tokenTypePresent)
	m.PluginVersion = refreshString(m.PluginVersion, snap.pluginVersion, snap.pluginVersionPresent)
	m.AuditNonHMACRequestKeys = refreshList(ctx, m.AuditNonHMACRequestKeys, snap.auditNonHMACRequestKeys, snap.auditRequestKeysPresent)
	m.AuditNonHMACResponseKeys = refreshList(ctx, m.AuditNonHMACResponseKeys, snap.auditNonHMACResponseKeys, snap.auditResponseKeysPresent)
	m.PassthroughRequestHeaders = refreshList(ctx, m.PassthroughRequestHeaders, snap.passthroughRequestHeaders, snap.passthroughHeadersPresent)
	m.AllowedResponseHeaders = refreshList(ctx, m.AllowedResponseHeaders, snap.allowedResponseHeaders, snap.allowedHeadersPresent)
	if m.UserLockoutConfig == nil || !snap.lockoutPresent {
		return
	}
	m.UserLockoutConfig.LockoutThreshold = refreshString(m.UserLockoutConfig.LockoutThreshold, snap.lockout.threshold, snap.lockout.thresholdPresent)
	m.UserLockoutConfig.LockoutDuration = refreshDuration(m.UserLockoutConfig.LockoutDuration, snap.lockout.duration, snap.lockout.durationPresent)
	m.UserLockoutConfig.LockoutCounterReset = refreshDuration(m.UserLockoutConfig.LockoutCounterReset, snap.lockout.counterReset, snap.lockout.counterResetPresent)
	m.UserLockoutConfig.LockoutDisable = refreshBool(m.UserLockoutConfig.LockoutDisable, snap.lockout.disable, snap.lockout.disablePresent)
}

func tuneConfig(ctx context.Context, plan, prior *authTuneModel, clearing bool) (api.TuneMountConfigInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	cfg := api.TuneMountConfigInput{}

	cfg.DefaultLeaseTTL = stringPtr(plan.DefaultLeaseTTL, prior.DefaultLeaseTTL, clearing, ttlSystemDefault)
	cfg.MaxLeaseTTL = stringPtr(plan.MaxLeaseTTL, prior.MaxLeaseTTL, clearing, ttlSystemDefault)
	cfg.ListingVisibility = stringPtr(plan.ListingVisibility, prior.ListingVisibility, clearing, "")
	cfg.TokenType = stringPtr(plan.TokenType, prior.TokenType, clearing, "")
	cfg.PluginVersion = stringPtr(plan.PluginVersion, prior.PluginVersion, clearing, "")

	var listDiags diag.Diagnostics
	cfg.AuditNonHMACRequestKeys, listDiags = listPtr(ctx, plan.AuditNonHMACRequestKeys, prior.AuditNonHMACRequestKeys, clearing)
	diags.Append(listDiags...)
	cfg.AuditNonHMACResponseKeys, listDiags = listPtr(ctx, plan.AuditNonHMACResponseKeys, prior.AuditNonHMACResponseKeys, clearing)
	diags.Append(listDiags...)
	cfg.PassthroughRequestHeaders, listDiags = listPtr(ctx, plan.PassthroughRequestHeaders, prior.PassthroughRequestHeaders, clearing)
	diags.Append(listDiags...)
	cfg.AllowedResponseHeaders, listDiags = listPtr(ctx, plan.AllowedResponseHeaders, prior.AllowedResponseHeaders, clearing)
	diags.Append(listDiags...)

	cfg.UserLockoutConfig = lockoutPtr(plan.UserLockoutConfig, prior.UserLockoutConfig, clearing)
	return cfg, diags
}

func tuneInputEmpty(cfg api.TuneMountConfigInput) bool {
	return cfg.DefaultLeaseTTL == nil &&
		cfg.MaxLeaseTTL == nil &&
		cfg.ListingVisibility == nil &&
		cfg.TokenType == nil &&
		cfg.PluginVersion == nil &&
		cfg.AuditNonHMACRequestKeys == nil &&
		cfg.AuditNonHMACResponseKeys == nil &&
		cfg.PassthroughRequestHeaders == nil &&
		cfg.AllowedResponseHeaders == nil &&
		cfg.UserLockoutConfig == nil
}

func stringPtr(plan, prior types.String, clearing bool, clearValue string) *string {
	if !plan.IsNull() && !plan.IsUnknown() {
		v := plan.ValueString()
		return &v
	}
	if clearing && !prior.IsNull() && !prior.IsUnknown() {
		v := clearValue
		return &v
	}
	return nil
}

func listPtr(ctx context.Context, plan, prior types.List, clearing bool) (*[]string, diag.Diagnostics) {
	if !plan.IsNull() && !plan.IsUnknown() {
		var values []string
		diags := plan.ElementsAs(ctx, &values, false)
		if diags.HasError() {
			return nil, diags
		}
		if len(normalizeList(values)) == 0 {
			cleared := []string{""}
			return &cleared, diags
		}
		return &values, diags
	}
	if clearing && !prior.IsNull() && !prior.IsUnknown() {
		var priorValues []string
		diags := prior.ElementsAs(ctx, &priorValues, false)
		if diags.HasError() {
			return nil, diags
		}
		if len(normalizeList(priorValues)) > 0 {
			cleared := []string{""}
			return &cleared, diags
		}
	}
	return nil, nil
}

func lockoutPtr(plan, prior *userLockoutModel, clearing bool) *api.TuneUserLockoutConfigInput {
	if plan == nil && (!clearing || prior == nil) {
		return nil
	}

	priorModel := userLockoutModel{}
	if prior != nil {
		priorModel = *prior
	}
	// A removed block is nil. Fields removed from a block are null.
	// Neither is a known value, so each previously set field is cleared.
	planModel := userLockoutModel{}
	if plan != nil {
		planModel = *plan
	}

	cfg := &api.TuneUserLockoutConfigInput{
		LockoutThreshold:            stringPtr(planModel.LockoutThreshold, priorModel.LockoutThreshold, clearing, lockoutThresholdZero),
		LockoutDuration:             stringPtr(planModel.LockoutDuration, priorModel.LockoutDuration, clearing, lockoutDurationZero),
		LockoutCounterResetDuration: stringPtr(planModel.LockoutCounterReset, priorModel.LockoutCounterReset, clearing, lockoutDurationZero),
		DisableLockout:              boolPtr(planModel.LockoutDisable, priorModel.LockoutDisable, clearing),
	}
	if cfg.LockoutThreshold == nil && cfg.LockoutDuration == nil && cfg.LockoutCounterResetDuration == nil && cfg.DisableLockout == nil {
		return nil
	}
	return cfg
}

func boolPtr(plan, prior types.Bool, clearing bool) *bool {
	if !plan.IsNull() && !plan.IsUnknown() {
		v := plan.ValueBool()
		return &v
	}
	if clearing && !prior.IsNull() && !prior.IsUnknown() {
		v := false
		return &v
	}
	return nil
}

func refreshString(state types.String, apiValue string, present bool) types.String {
	if !present || state.IsNull() || state.IsUnknown() {
		return state
	}
	if apiValue == "" {
		return types.StringNull()
	}
	if state.ValueString() == apiValue {
		return state
	}
	return types.StringValue(apiValue)
}

func refreshDuration(state types.String, apiValue string, present bool) types.String {
	if !present || state.IsNull() || state.IsUnknown() {
		return state
	}
	if apiValue == "" {
		return types.StringNull()
	}
	if durationsEqual(state.ValueString(), apiValue) {
		return state
	}
	return types.StringValue(apiValue)
}

func refreshBool(state types.Bool, apiValue bool, present bool) types.Bool {
	if !present || state.IsNull() || state.IsUnknown() {
		return state
	}
	if state.ValueBool() == apiValue {
		return state
	}
	return types.BoolValue(apiValue)
}

func refreshList(ctx context.Context, state types.List, apiValues []string, present bool) types.List {
	if !present || state.IsNull() || state.IsUnknown() {
		return state
	}
	apiValues = normalizeList(apiValues)
	var current []string
	if diags := state.ElementsAs(ctx, &current, false); diags.HasError() {
		return state
	}
	if slices.Equal(normalizeList(current), apiValues) {
		return state
	}
	return stringList(apiValues)
}

func durationsEqual(a, b string) bool {
	da, errA := time.ParseDuration(a)
	db, errB := time.ParseDuration(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return da == db
}

func stringList(values []string) types.List {
	if len(values) == 0 {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}
	elems := make([]attr.Value, len(values))
	for i, v := range values {
		elems[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, elems)
}

func durationField(data map[string]interface{}, key string) (string, bool) {
	v, ok := data[key]
	if !ok || v == nil {
		return "", false
	}
	return durationFromAPI(v), true
}

func durationFromAPI(v interface{}) string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return lockoutDurationZero
		}
		if _, err := time.ParseDuration(t); err == nil {
			return t
		}
		if i, err := strconv.ParseInt(t, 10, 64); err == nil {
			return helper.FlattenVaultDuration(i)
		}
		return t
	case int:
		return helper.FlattenVaultDuration(t)
	case int64:
		return helper.FlattenVaultDuration(t)
	case float64:
		return helper.FlattenVaultDuration(int64(t))
	case json.Number:
		return helper.FlattenVaultDuration(t)
	default:
		return ""
	}
}

func stringFieldFromMap(data map[string]interface{}, key string) (string, bool) {
	v, ok := data[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

func listFieldFromMap(data map[string]interface{}, key string) ([]string, bool) {
	v, ok := data[key]
	if !ok || v == nil {
		return nil, false
	}
	switch t := v.(type) {
	case []string:
		return t, true
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				continue
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func scalarString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return strconv.FormatInt(i, 10)
		}
		return t.String()
	default:
		return ""
	}
}

func boolFromAPI(v interface{}) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(t)
		if err != nil {
			return false, false
		}
		return b, true
	default:
		return false, false
	}
}

func firstPresent(data map[string]interface{}, keys ...string) (interface{}, bool) {
	for _, key := range keys {
		if v, ok := data[key]; ok && v != nil {
			return v, true
		}
	}
	return nil, false
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
