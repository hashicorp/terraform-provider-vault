// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	fwvalidator "github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

const raftSnapshotAutoPath = "sys/storage/raft/snapshot-auto/config/%s"

// Ensure the implementation satisfies the expected interfaces
var (
	_ resource.ResourceWithConfigure      = &RaftSnapshotAgentConfigResource{}
	_ resource.ResourceWithModifyPlan     = &RaftSnapshotAgentConfigResource{}
)

const privateStateKeySecretsHash = "secrets_wo_hash"

// NewRaftSnapshotAgentConfigResource returns the implementation for this resource
func NewRaftSnapshotAgentConfigResource() resource.Resource {
	return &RaftSnapshotAgentConfigResource{}
}

// RaftSnapshotAgentConfigResource implements the methods that define this resource
type RaftSnapshotAgentConfigResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// RaftSnapshotAgentConfigModel describes the Terraform resource data model
type RaftSnapshotAgentConfigModel struct {
	base.BaseModelLegacy

	Name            types.String `tfsdk:"name"`
	IntervalSeconds types.Int64  `tfsdk:"interval_seconds"`
	Retain          types.Int64  `tfsdk:"retain"`
	PathPrefix      types.String `tfsdk:"path_prefix"`
	FilePrefix      types.String `tfsdk:"file_prefix"`
	StorageType     types.String `tfsdk:"storage_type"`
	AutoloadEnabled types.Bool   `tfsdk:"autoload_enabled"`
	LocalMaxSpace   types.Int64  `tfsdk:"local_max_space"`

	// AWS S3 fields
	AWSS3Bucket               types.String `tfsdk:"aws_s3_bucket"`
	AWSS3Region               types.String `tfsdk:"aws_s3_region"`
	AWSAccessKeyID            types.String `tfsdk:"aws_access_key_id"`
	AWSSecretAccessKey        types.String `tfsdk:"aws_secret_access_key"`
	AWSSecretAccessKeyWO      types.String `tfsdk:"aws_secret_access_key_wo"`
	SecretsWOVersion          types.Int64  `tfsdk:"secrets_wo_version"`
	AWSSessionToken           types.String `tfsdk:"aws_session_token"`
	AWSS3Endpoint             types.String `tfsdk:"aws_s3_endpoint"`
	AWSS3DisableTLS           types.Bool   `tfsdk:"aws_s3_disable_tls"`
	AWSS3ForcePathStyle       types.Bool   `tfsdk:"aws_s3_force_path_style"`
	AWSS3EnableKMS            types.Bool   `tfsdk:"aws_s3_enable_kms"`
	AWSS3ServerSideEncryption types.Bool   `tfsdk:"aws_s3_server_side_encryption"`
	AWSS3KMSKey               types.String `tfsdk:"aws_s3_kms_key"`

	// Google GCS fields
	GoogleGCSBucket         types.String `tfsdk:"google_gcs_bucket"`
	GoogleServiceAccountKey types.String `tfsdk:"google_service_account_key"`
	GoogleEndpoint          types.String `tfsdk:"google_endpoint"`
	GoogleDisableTLS        types.Bool   `tfsdk:"google_disable_tls"`

	// Azure fields
	AzureContainerName   types.String `tfsdk:"azure_container_name"`
	AzureAccountName     types.String `tfsdk:"azure_account_name"`
	AzureAccountKey      types.String `tfsdk:"azure_account_key"`
	AzureBlobEnvironment types.String `tfsdk:"azure_blob_environment"`
	AzureEndpoint        types.String `tfsdk:"azure_endpoint"`
	AzureClientID        types.String `tfsdk:"azure_client_id"`
	AzureAuthMode        types.String `tfsdk:"azure_auth_mode"`
}

// Metadata defines the resource name
func (r *RaftSnapshotAgentConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_raft_snapshot_agent_config"
}

// Schema defines this resource's schema
func (r *RaftSnapshotAgentConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the snapshot agent configuration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldIntervalSeconds: schema.Int64Attribute{
				Required:            true,
				MarkdownDescription: "Number of seconds between snapshots.",
			},
			consts.FieldRetain: schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(1),
				MarkdownDescription: "How many snapshots are to be kept.",
			},
			consts.FieldPathPrefix: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The directory or bucket prefix to to use.",
			},
			consts.FieldFilePrefix: schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("vault-snapshot"),
				MarkdownDescription: "The file or object name of snapshot files will start with this string.",
			},
			consts.FieldStorageType: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: `What storage service to send snapshots to. One of "local", "azure-blob", "aws-s3", or "google-gcs".`,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []fwvalidator.String{
					stringvalidator.OneOf("local", "azure-blob", "aws-s3", "google-gcs"),
				},
			},
			consts.FieldAutoloadEnabled: schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Have Vault automatically load the latest snapshot after it is written. " +
					"Note that this does not mean the snapshot is automatically applied to the cluster, " +
					"it is just loaded and available for recovery operations. " +
					`Requires Vault Enterprise 1.21.0+. Not supported with storage_type = "local".`,
			},
			consts.FieldLocalMaxSpace: schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The maximum space, in bytes, to use for snapshots.",
			},
			consts.FieldAWSS3Bucket: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "S3 bucket to write snapshots to.",
			},
			consts.FieldAWSS3Region: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "AWS region bucket is in.",
			},
			consts.FieldAWSAccessKeyID: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "AWS access key ID.",
			},
			consts.FieldAWSSecretAccessKey: schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "AWS secret access key.",
				DeprecationMessage: "Use aws_secret_access_key_wo instead, which is a write-only attribute that is never stored in state.",
				Validators: []fwvalidator.String{
					stringvalidator.ConflictsWith(
						path.MatchRoot(consts.FieldAWSSecretAccessKeyWO),
					),
				},
			},
			consts.FieldAWSSecretAccessKeyWO: schema.StringAttribute{
				Optional:  true,
				WriteOnly: true,
				Sensitive: true,
				MarkdownDescription: "AWS secret access key. Write-only: never stored in state. " +
					"If secrets_wo_version is not set, changes are automatically detected via a hash stored in private state.",
				Validators: []fwvalidator.String{
					stringvalidator.ConflictsWith(
						path.MatchRoot(consts.FieldAWSSecretAccessKey),
					),
				},
			},
			consts.FieldSecretsWOVersion: schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "Version number for write-only secret updates. " +
					"If not set, the provider automatically detects changes to write-only secrets " +
					"using a SHA-256 hash stored in private state. If set manually, you control " +
					"when the secret is updated by incrementing this value.",
			},
			consts.FieldAWSSessionToken: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "AWS session token.",
			},
			consts.FieldAWSS3Endpoint: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "AWS endpoint. This is typically only set when using a non-AWS S3 implementation like Minio.",
			},
			consts.FieldAWSS3DisableTLS: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "Disable TLS for the S3 endpoint. This should only be used for testing purposes.",
			},
			consts.FieldAWSS3ForcePathStyle: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "Use the endpoint/bucket URL style instead of bucket.endpoint.",
			},
			consts.FieldAWSS3EnableKMS: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "Use KMS to encrypt bucket contents.",
			},
			consts.FieldAWSS3ServerSideEncryption: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "Use AES256 to encrypt bucket contents.",
			},
			consts.FieldAWSS3KMSKey: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Use named KMS key, when aws_s3_enable_kms=true",
			},
			consts.FieldGoogleGCSBucket: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "GCS bucket to write snapshots to.",
			},
			consts.FieldGoogleServiceAccountKey: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Google service account key in JSON format.",
			},
			consts.FieldGoogleEndpoint: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "GCS endpoint. This is typically only set when using a non-Google GCS implementation like fake-gcs-server.",
			},
			consts.FieldGoogleDisableTLS: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				MarkdownDescription: "Disable TLS for the GCS endpoint.",
			},
			consts.FieldAzureContainerName: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure container name to write snapshots to.",
			},
			consts.FieldAzureAccountName: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure account name.",
			},
			consts.FieldAzureAccountKey: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure account key. Required when azure_auth_mode is 'shared'.",
			},
			consts.FieldAzureBlobEnvironment: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure blob environment.",
			},
			consts.FieldAzureEndpoint: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure blob storage endpoint. This is typically only set when using a non-Azure implementation like Azurite.",
			},
			consts.FieldAzureClientID: schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Azure client ID for authentication. Required when azure_auth_mode is 'managed'. " +
					"Requires Vault Enterprise 1.18.0+.",
			},
			consts.FieldAzureAuthMode: schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Azure authentication mode. Required for azure-blob storage. " +
					"Possible values are 'shared', 'managed', or 'environment'. " +
					"Requires Vault Enterprise 1.18.0+.",
			},
		},
		MarkdownDescription: "Manages Raft Snapshot Agent Configuration.",
	}

	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// ModifyPlan implements resource.ResourceWithModifyPlan to detect write-only secret changes.
func (r *RaftSnapshotAgentConfigResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip on destroy (no plan)
	if req.Plan.Raw.IsNull() {
		return
	}

	// Check if user manually set secrets_wo_version in config
	var configVersion *int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldSecretsWOVersion), &configVersion)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if configVersion != nil {
		// Manual mode: user controls the version, don't auto-detect
		return
	}

	// Auto mode: compare hashes to detect write-only value changes
	newHash := r.calculateSecretsHash(ctx, req.Config)
	if newHash == "" {
		// No write-only secrets set — resolve Computed unknown to null
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(consts.FieldSecretsWOVersion), types.Int64Null())...)
		return
	}

	// On Create (no prior state), set initial version to 1
	if req.State.Raw.IsNull() {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(consts.FieldSecretsWOVersion), int64(1))...)
		return
	}

	// On Update, compare hashes
	oldHashBytes, diags := req.Private.GetKey(ctx, privateStateKeySecretsHash)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	oldHash := ""
	if oldHashBytes != nil {
		if err := json.Unmarshal(oldHashBytes, &oldHash); err != nil {
			resp.Diagnostics.AddError("Failed to decode secrets hash", err.Error())
			return
		}
	}

	if newHash != oldHash {
		// Hash changed — increment version in plan
		var stateVersion types.Int64
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(consts.FieldSecretsWOVersion), &stateVersion)...)
		if resp.Diagnostics.HasError() {
			return
		}

		currentVersion := int64(0)
		if !stateVersion.IsNull() && !stateVersion.IsUnknown() {
			currentVersion = stateVersion.ValueInt64()
		}
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(consts.FieldSecretsWOVersion), currentVersion+1)...)
	}
}

// calculateSecretsHash computes a SHA-256 hash of all write-only secret values from config.
func (r *RaftSnapshotAgentConfigResource) calculateSecretsHash(ctx context.Context, config tfsdk.Config) string {
	var awsSecretWO *string
	config.GetAttribute(ctx, path.Root(consts.FieldAWSSecretAccessKeyWO), &awsSecretWO)

	if awsSecretWO == nil {
		return ""
	}

	h := sha256.New()
	if awsSecretWO != nil {
		h.Write([]byte("aws_secret_access_key_wo:" + *awsSecretWO))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Create is called during the terraform apply command
func (r *RaftSnapshotAgentConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RaftSnapshotAgentConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	name := data.Name.ValueString()
	vaultPath := fmt.Sprintf(raftSnapshotAutoPath, name)

	// Read write-only values from config
	woSecrets := r.readWriteOnlySecrets(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := r.buildConfig(data, woSecrets)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("[DEBUG] Configuring automatic snapshots: %q", name)
	if _, err = vaultClient.Logical().WriteWithContext(ctx, vaultPath, config); err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultCreateErr(fmt.Errorf("error writing %q: %s", vaultPath, err)),
		)
		return
	}
	log.Printf("[DEBUG] Configured automatic snapshots: %q", name)

	data.ID = types.StringValue(name)

	// Store hash in private state if using auto-managed mode
	r.storeSecretsHash(ctx, req.Config, resp.Private, &resp.Diagnostics)

	resp.Diagnostics.Append(r.readIntoModel(ctx, vaultClient, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands
func (r *RaftSnapshotAgentConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RaftSnapshotAgentConfigModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	diags := r.readIntoModel(ctx, vaultClient, &data)
	// If readIntoModel cleared the ID, the resource was not found
	if data.ID.ValueString() == "" {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command
func (r *RaftSnapshotAgentConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data RaftSnapshotAgentConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	name := data.Name.ValueString()
	vaultPath := fmt.Sprintf(raftSnapshotAutoPath, name)

	// Read write-only values from config
	woSecrets := r.readWriteOnlySecrets(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	config, diags := r.buildConfig(data, woSecrets)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("[DEBUG] Updating automatic snapshots: %q", name)
	if _, err = vaultClient.Logical().WriteWithContext(ctx, vaultPath, config); err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultUpdateErr(fmt.Errorf("error writing %q: %s", vaultPath, err)),
		)
		return
	}
	log.Printf("[DEBUG] Updated automatic snapshots: %q", name)

	data.ID = types.StringValue(name)

	// Update hash in private state
	r.storeSecretsHash(ctx, req.Config, resp.Private, &resp.Diagnostics)

	resp.Diagnostics.Append(r.readIntoModel(ctx, vaultClient, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command
func (r *RaftSnapshotAgentConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data RaftSnapshotAgentConfigModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	name := data.ID.ValueString()
	path := fmt.Sprintf(raftSnapshotAutoPath, name)

	log.Printf("[DEBUG] Removing Raft Snapshot Agent Config: %q", name)

	_, err = vaultClient.Logical().DeleteWithContext(ctx, path)
	if err != nil && util.Is404(err) {
		log.Printf("[WARN] %q not found, removing from state", name)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultDeleteErr(fmt.Errorf("error removing raft snapshot agent config from %q: %s", path, err)),
		)
		return
	}
	log.Printf("[DEBUG] Removed raft snapshot agent config: %q", name)
}

// writeOnlySecrets holds write-only secret values read from config.
type writeOnlySecrets struct {
	AWSSecretAccessKey string
}

// readWriteOnlySecrets reads write-only attribute values from the config.
func (r *RaftSnapshotAgentConfigResource) readWriteOnlySecrets(ctx context.Context, config tfsdk.Config, diags *diag.Diagnostics) writeOnlySecrets {
	var s writeOnlySecrets
	var awsSecretWO *string
	diags.Append(config.GetAttribute(ctx, path.Root(consts.FieldAWSSecretAccessKeyWO), &awsSecretWO)...)
	if awsSecretWO != nil {
		s.AWSSecretAccessKey = *awsSecretWO
	}
	return s
}

// storeSecretsHash calculates and stores the hash of write-only secrets in private state.
func (r *RaftSnapshotAgentConfigResource) storeSecretsHash(ctx context.Context, config tfsdk.Config, private privateStateSetter, diags *diag.Diagnostics) {
	// Check if user manually set the version (manual mode = no hash storage)
	var configVersion *int64
	diags.Append(config.GetAttribute(ctx, path.Root(consts.FieldSecretsWOVersion), &configVersion)...)
	if diags.HasError() || configVersion != nil {
		return
	}

	hash := r.calculateSecretsHash(ctx, config)
	if hash != "" {
		hashJSON, err := json.Marshal(hash)
		if err != nil {
			diags.AddError("Failed to encode secrets hash", err.Error())
			return
		}
		diags.Append(private.SetKey(ctx, privateStateKeySecretsHash, hashJSON)...)
	}
}

// privateStateSetter is an interface for setting private state keys,
// satisfied by both resource.CreateResponse.Private and resource.UpdateResponse.Private.
type privateStateSetter interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

// buildConfig constructs the Vault API request payload from the model
func (r *RaftSnapshotAgentConfigResource) buildConfig(data RaftSnapshotAgentConfigModel, wo writeOnlySecrets) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	storageType := data.StorageType.ValueString()

	config := map[string]interface{}{
		consts.FieldInterval:    data.IntervalSeconds.ValueInt64(),
		consts.FieldRetain:      data.Retain.ValueInt64(),
		consts.FieldPathPrefix:  data.PathPrefix.ValueString(),
		consts.FieldFilePrefix:  data.FilePrefix.ValueString(),
		consts.FieldStorageType: storageType,
	}

	// Add autoload_enabled if set and version is supported (Vault 1.21.0+)
	if provider.IsAPISupported(r.Meta(), provider.VaultVersion121) {
		if !data.AutoloadEnabled.IsNull() && !data.AutoloadEnabled.IsUnknown() {
			config[consts.FieldAutoloadEnabled] = data.AutoloadEnabled.ValueBool()
		}
	}

	if storageType == "local" {
		if !data.LocalMaxSpace.IsNull() && !data.LocalMaxSpace.IsUnknown() && data.LocalMaxSpace.ValueInt64() != 0 {
			config[consts.FieldLocalMaxSpace] = data.LocalMaxSpace.ValueInt64()
		} else {
			diags.AddError("Invalid Configuration", "specified local storage without setting local_max_space")
			return nil, diags
		}
	}

	if storageType == "aws-s3" {
		if !data.AWSS3Bucket.IsNull() && data.AWSS3Bucket.ValueString() != "" {
			config[consts.FieldAWSS3Bucket] = data.AWSS3Bucket.ValueString()
		} else {
			diags.AddError("Invalid Configuration", "specified aws-s3 storage without setting aws_s3_bucket")
			return nil, diags
		}
		if !data.AWSS3Region.IsNull() && data.AWSS3Region.ValueString() != "" {
			config[consts.FieldAWSS3Region] = data.AWSS3Region.ValueString()
		} else {
			diags.AddError("Invalid Configuration", "specified aws-s3 storage without setting aws_s3_region")
			return nil, diags
		}
		setStringIfSet(config, consts.FieldAWSAccessKeyID, data.AWSAccessKeyID)
		// Prefer write-only secret, fall back to legacy field
		if wo.AWSSecretAccessKey != "" {
			config[consts.FieldAWSSecretAccessKey] = wo.AWSSecretAccessKey
		} else {
			setStringIfSet(config, consts.FieldAWSSecretAccessKey, data.AWSSecretAccessKey)
		}
		setStringIfSet(config, consts.FieldAWSSessionToken, data.AWSSessionToken)
		setStringIfSet(config, consts.FieldAWSS3Endpoint, data.AWSS3Endpoint)
		setBoolIfSet(config, consts.FieldAWSS3DisableTLS, data.AWSS3DisableTLS)
		setBoolIfSet(config, consts.FieldAWSS3ForcePathStyle, data.AWSS3ForcePathStyle)
		setBoolIfSet(config, consts.FieldAWSS3EnableKMS, data.AWSS3EnableKMS)
		setBoolIfSet(config, consts.FieldAWSS3ServerSideEncryption, data.AWSS3ServerSideEncryption)
		setStringIfSet(config, consts.FieldAWSS3KMSKey, data.AWSS3KMSKey)
	}

	if storageType == "google-gcs" {
		if !data.GoogleGCSBucket.IsNull() && data.GoogleGCSBucket.ValueString() != "" {
			config[consts.FieldGoogleGCSBucket] = data.GoogleGCSBucket.ValueString()
		} else {
			diags.AddError("Invalid Configuration", "specified google-gcs storage without setting google_gcs_bucket")
			return nil, diags
		}
		setStringIfSet(config, consts.FieldGoogleServiceAccountKey, data.GoogleServiceAccountKey)
		setStringIfSet(config, consts.FieldGoogleEndpoint, data.GoogleEndpoint)
		setBoolIfSet(config, consts.FieldGoogleDisableTLS, data.GoogleDisableTLS)
	}

	if storageType == "azure-blob" {
		if !data.AzureContainerName.IsNull() && data.AzureContainerName.ValueString() != "" {
			config[consts.FieldAzureContainerName] = data.AzureContainerName.ValueString()
		} else {
			diags.AddError("Invalid Configuration", "specified azure-blob storage without setting azure_container_name")
			return nil, diags
		}
		setStringIfSet(config, consts.FieldAzureAccountName, data.AzureAccountName)
		setStringIfSet(config, consts.FieldAzureAccountKey, data.AzureAccountKey)
		setStringIfSet(config, consts.FieldAzureBlobEnvironment, data.AzureBlobEnvironment)
		setStringIfSet(config, consts.FieldAzureEndpoint, data.AzureEndpoint)

		// Add azure_client_id and azure_auth_mode if version is supported (Vault 1.18.0+)
		if provider.IsAPISupported(r.Meta(), provider.VaultVersion118) {
			setStringIfSet(config, consts.FieldAzureClientID, data.AzureClientID)
			setStringIfSet(config, consts.FieldAzureAuthMode, data.AzureAuthMode)
		}
	}

	return config, diags
}

// readIntoModel reads the config from Vault and populates the data model.
// If the resource is not found, the ID is cleared to signal removal from state.
func (r *RaftSnapshotAgentConfigResource) readIntoModel(ctx context.Context, vaultClient *api.Client, data *RaftSnapshotAgentConfigModel) diag.Diagnostics {
	var diags diag.Diagnostics

	name := data.ID.ValueString()
	configPath := fmt.Sprintf(raftSnapshotAutoPath, name)
	log.Printf("[DEBUG] Reading %q", configPath)

	resp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if resp == nil || (err != nil && util.Is404(err)) {
		log.Printf("[WARN] %q not found, removing from state", name)
		data.ID = types.StringValue("")
		return diags
	}
	if err != nil {
		diags.AddError(errutil.VaultReadErr(fmt.Errorf("error reading %q: %s", configPath, err)))
		return diags
	}

	data.Name = types.StringValue(name)
	data.ID = types.StringValue(name)

	readStringField(resp.Data, consts.FieldStorageType, &data.StorageType)
	readStringField(resp.Data, consts.FieldPathPrefix, &data.PathPrefix)
	readStringField(resp.Data, consts.FieldFilePrefix, &data.FilePrefix)
	readInt64Field(resp.Data, consts.FieldInterval, &data.IntervalSeconds)
	readInt64Field(resp.Data, consts.FieldRetain, &data.Retain)

	// Only read autoload_enabled if version is supported (Vault 1.21.0+)
	if provider.IsAPISupported(r.Meta(), provider.VaultVersion121) {
		readBoolField(resp.Data, consts.FieldAutoloadEnabled, &data.AutoloadEnabled)
	}

	readInt64Field(resp.Data, consts.FieldLocalMaxSpace, &data.LocalMaxSpace)

	// AWS fields
	readStringField(resp.Data, consts.FieldAWSS3Bucket, &data.AWSS3Bucket)
	readStringField(resp.Data, consts.FieldAWSS3Region, &data.AWSS3Region)
	readStringField(resp.Data, consts.FieldAWSAccessKeyID, &data.AWSAccessKeyID)
	// Only read the legacy secret field from API if the user set it in config.
	// When using aws_secret_access_key_wo, this field is null in plan and must stay null.
	if !data.AWSSecretAccessKey.IsNull() {
		readStringField(resp.Data, consts.FieldAWSSecretAccessKey, &data.AWSSecretAccessKey)
	}
	readStringField(resp.Data, consts.FieldAWSSessionToken, &data.AWSSessionToken)
	readStringField(resp.Data, consts.FieldAWSS3Endpoint, &data.AWSS3Endpoint)
	readComputedBoolField(resp.Data, consts.FieldAWSS3DisableTLS, &data.AWSS3DisableTLS)
	readComputedBoolField(resp.Data, consts.FieldAWSS3ForcePathStyle, &data.AWSS3ForcePathStyle)
	readComputedBoolField(resp.Data, consts.FieldAWSS3EnableKMS, &data.AWSS3EnableKMS)
	readComputedBoolField(resp.Data, consts.FieldAWSS3ServerSideEncryption, &data.AWSS3ServerSideEncryption)
	readStringField(resp.Data, consts.FieldAWSS3KMSKey, &data.AWSS3KMSKey)

	// Google fields
	readStringField(resp.Data, consts.FieldGoogleGCSBucket, &data.GoogleGCSBucket)
	readStringField(resp.Data, consts.FieldGoogleServiceAccountKey, &data.GoogleServiceAccountKey)

	// Vault returns 'false' for google_endpoint instead of null
	if val, ok := resp.Data[consts.FieldGoogleEndpoint]; ok && val != false {
		if s, ok := val.(string); ok {
			data.GoogleEndpoint = types.StringValue(s)
		}
	}

	readComputedBoolField(resp.Data, consts.FieldGoogleDisableTLS, &data.GoogleDisableTLS)

	// Azure fields
	readStringField(resp.Data, consts.FieldAzureContainerName, &data.AzureContainerName)
	readStringField(resp.Data, consts.FieldAzureAccountName, &data.AzureAccountName)
	readStringField(resp.Data, consts.FieldAzureAccountKey, &data.AzureAccountKey)
	readStringField(resp.Data, consts.FieldAzureBlobEnvironment, &data.AzureBlobEnvironment)
	readStringField(resp.Data, consts.FieldAzureEndpoint, &data.AzureEndpoint)

	// Only read azure_client_id and azure_auth_mode if version is supported (Vault 1.18.0+)
	if provider.IsAPISupported(r.Meta(), provider.VaultVersion118) {
		readStringField(resp.Data, consts.FieldAzureClientID, &data.AzureClientID)
		readStringField(resp.Data, consts.FieldAzureAuthMode, &data.AzureAuthMode)
	}

	return diags
}

// readStringField reads a string value from a Vault response data map into a types.String.
// If the target is currently null and the API returns an empty string, the null is preserved
// to avoid "inconsistent result after apply" errors for optional fields.
func readStringField(data map[string]interface{}, key string, target *types.String) {
	if val, ok := data[key]; ok {
		if s, ok := val.(string); ok {
			if s == "" && target.IsNull() {
				return
			}
			*target = types.StringValue(s)
		}
	}
}

// readInt64Field reads a numeric value from a Vault response data map into a types.Int64.
// Vault API returns json.Number for numeric fields.
// If the target is currently null and the API returns zero, the null is preserved.
func readInt64Field(data map[string]interface{}, key string, target *types.Int64) {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case json.Number:
			if i, err := v.Int64(); err == nil {
				if i == 0 && target.IsNull() {
					return
				}
				*target = types.Int64Value(i)
			}
		case float64:
			if int64(v) == 0 && target.IsNull() {
				return
			}
			*target = types.Int64Value(int64(v))
		}
	}
}

// readBoolField reads a bool value from a Vault response data map into a types.Bool.
// If the target is currently null and the API returns false, the null is preserved.
// Use this for Optional-only bool fields (e.g. autoload_enabled).
func readBoolField(data map[string]interface{}, key string, target *types.Bool) {
	if val, ok := data[key]; ok {
		if b, ok := val.(bool); ok {
			if !b && target.IsNull() {
				return
			}
			*target = types.BoolValue(b)
		}
	}
}

// readComputedBoolField reads a bool value from a Vault response data map into a types.Bool.
// Unlike readBoolField, this always sets the value, which is correct for Computed fields
// with a default (e.g. Optional + Computed + Default(false)). If the key is missing from
// the response (e.g. non-applicable storage type), it defaults to false.
func readComputedBoolField(data map[string]interface{}, key string, target *types.Bool) {
	if val, ok := data[key]; ok {
		if b, ok := val.(bool); ok {
			*target = types.BoolValue(b)
			return
		}
	}
	*target = types.BoolValue(false)
}

// setStringIfSet adds a string value to the config map if it's set (not null/unknown)
func setStringIfSet(config map[string]interface{}, key string, val types.String) {
	if !val.IsNull() && !val.IsUnknown() {
		config[key] = val.ValueString()
	}
}

// setBoolIfSet adds a bool value to the config map if it's set (not null/unknown)
func setBoolIfSet(config map[string]interface{}, key string, val types.Bool) {
	if !val.IsNull() && !val.IsUnknown() {
		config[key] = val.ValueBool()
	}
}
