// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	kerberos "github.com/hashicorp/vault-plugin-auth-kerberos"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var (
	_ ephemeral.EphemeralResource              = (*kerberosAuthBackendLoginEphemeral)(nil)
	_ ephemeral.EphemeralResourceWithConfigure = (*kerberosAuthBackendLoginEphemeral)(nil)
)

// NewKerberosAuthBackendLoginEphemeralResource is the constructor function for the ephemeral resource
// to be imported by the Terraform Plugin Framework provider
var NewKerberosAuthBackendLoginEphemeralResource = func() ephemeral.EphemeralResource {
	return &kerberosAuthBackendLoginEphemeral{}
}

type kerberosAuthBackendLoginEphemeral struct {
	base.EphemeralResourceWithConfigure
}

// kerberosPrivateData holds data that needs to be passed from Open to Close
type kerberosPrivateData struct {
	Accessor  string `json:"accessor"`
	Namespace string `json:"namespace"`
}

type kerberosAuthBackendLoginModel struct {
	base.BaseModelEphemeral

	// Input parameters
	Mount                  types.String `tfsdk:"mount"`
	KeytabPath             types.String `tfsdk:"keytab_path"`
	Krb5ConfPath           types.String `tfsdk:"krb5conf_path"`
	Username               types.String `tfsdk:"username"`
	Service                types.String `tfsdk:"service"`
	Realm                  types.String `tfsdk:"realm"`
	DisableFastNegotiation types.Bool   `tfsdk:"disable_fast_negotiation"`
	RemoveInstanceName     types.Bool   `tfsdk:"remove_instance_name"`

	// Output fields (Computed)
	ClientToken      types.String `tfsdk:"client_token"`
	Accessor         types.String `tfsdk:"accessor"`
	Policies         types.Set    `tfsdk:"policies"`
	TokenPolicies    types.Set    `tfsdk:"token_policies"`
	IdentityPolicies types.Set    `tfsdk:"identity_policies"`
	Metadata         types.Map    `tfsdk:"metadata"`
	LeaseDuration    types.Int64  `tfsdk:"lease_duration"`
	Renewable        types.Bool   `tfsdk:"renewable"`
	EntityID         types.String `tfsdk:"entity_id"`
	Orphan           types.Bool   `tfsdk:"orphan"`
}

func (e *kerberosAuthBackendLoginEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kerberos_auth_backend_login"
}

func (e *kerberosAuthBackendLoginEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Performs Kerberos authentication and returns a Vault token. This is an ephemeral resource - credentials and tokens are not persisted to state.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required:    true,
				Description: "Path where the Kerberos auth method is mounted. Defaults to 'kerberos'.",
			},
			consts.FieldKeytabPath: schema.StringAttribute{
				Required:    true,
				Description: "Path to the keytab file for authentication.",
			},
			consts.FieldKRB5ConfPath: schema.StringAttribute{
				Required:    true,
				Description: "Path to the krb5.conf configuration file.",
			},
			consts.FieldUsername: schema.StringAttribute{
				Required:    true,
				Description: "Username for the keytab entry. Must match a service account in LDAP.",
			},
			consts.FieldService: schema.StringAttribute{
				Required:    true,
				Description: "Service principal name for obtaining a service ticket.",
			},
			consts.FieldRealm: schema.StringAttribute{
				Required:    true,
				Description: "Kerberos realm name. Must match the UPNDomain in LDAP config.",
			},
			consts.FieldDisableFastNegotiation: schema.BoolAttribute{
				Optional:    true,
				Description: "Disable FAST negotiation. Default: false.",
			},
			consts.FieldRemoveInstanceName: schema.BoolAttribute{
				Optional:    true,
				Description: "Remove instance name from principal. Default: false.",
			},
			consts.FieldClientToken: schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The Vault token returned after successful authentication.",
			},
			consts.FieldAccessor: schema.StringAttribute{
				Computed:    true,
				Description: "The accessor for the token.",
			},
			consts.FieldPolicies: schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Set of policies attached to the token.",
			},
			consts.FieldTokenPolicies: schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Policies from the token configuration.",
			},
			consts.FieldIdentityPolicies: schema.SetAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Policies from identity.",
			},
			consts.FieldMetadata: schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Metadata associated with the token.",
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				Computed:    true,
				Description: "Token lease duration in seconds.",
			},
			consts.FieldRenewable: schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the token is renewable.",
			},
			consts.FieldEntityID: schema.StringAttribute{
				Computed:    true,
				Description: "The identifier of the entity in the identity store.",
			},
			consts.FieldOrphan: schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the token is orphaned.",
			},
		},
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (e *kerberosAuthBackendLoginEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var config kerberosAuthBackendLoginModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, e.Meta(), config.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := config.Mount.ValueString()
	if mount == "" {
		mount = "kerberos"
	}
	loginPath := fmt.Sprintf("auth/%s/login", mount)

	// Prepare Kerberos login configuration
	loginCfg := &kerberos.LoginCfg{
		Username:               config.Username.ValueString(),
		Service:                config.Service.ValueString(),
		Realm:                  config.Realm.ValueString(),
		KeytabPath:             config.KeytabPath.ValueString(),
		Krb5ConfPath:           config.Krb5ConfPath.ValueString(),
		DisableFASTNegotiation: config.DisableFastNegotiation.ValueBool(),
		RemoveInstanceName:     config.RemoveInstanceName.ValueBool(),
	}

	// Generate SPNEGO token
	tflog.Debug(ctx, "Generating SPNEGO token for Kerberos authentication")
	authHeaderVal, err := kerberos.GetAuthHeaderVal(loginCfg)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error generating Kerberos SPNEGO token",
			err.Error(),
		)
		return
	}

	// Clone the client to avoid mutating shared headers
	// This prevents the Kerberos Authorization header from leaking into
	// subsequent unrelated Vault requests on the cached client
	loginClient, err := c.Clone()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error cloning Vault client for Kerberos login",
			err.Error(),
		)
		return
	}

	// Set the Authorization header with the SPNEGO token on the cloned client
	loginClient.AddHeader(spnego.HTTPHeaderAuthRequest, authHeaderVal)

	// Perform login with empty body (authentication is in the header)
	// Use WriteWithContext to honor context cancellations and timeouts
	tflog.Debug(ctx, fmt.Sprintf("Performing Kerberos login at '%s'", loginPath))
	secret, err := loginClient.Logical().WriteWithContext(ctx, loginPath, map[string]interface{}{})
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error performing Kerberos login at %q", loginPath),
			err.Error(),
		)
		return
	}

	if secret == nil || secret.Auth == nil {
		resp.Diagnostics.AddError(
			"Kerberos login failed",
			"No authentication data returned from Vault",
		)
		return
	}

	// Populate output fields from auth response
	config.ClientToken = types.StringValue(secret.Auth.ClientToken)
	config.Accessor = types.StringValue(secret.Auth.Accessor)
	config.LeaseDuration = types.Int64Value(int64(secret.Auth.LeaseDuration))
	config.Renewable = types.BoolValue(secret.Auth.Renewable)
	config.EntityID = types.StringValue(secret.Auth.EntityID)

	if secret.Auth.Orphan {
		config.Orphan = types.BoolValue(true)
	} else {
		config.Orphan = types.BoolValue(false)
	}

	// Convert policies
	if len(secret.Auth.Policies) > 0 {
		policies, diags := types.SetValueFrom(ctx, types.StringType, secret.Auth.Policies)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		config.Policies = policies
	} else {
		config.Policies = types.SetNull(types.StringType)
	}

	// Convert token policies
	if len(secret.Auth.TokenPolicies) > 0 {
		tokenPolicies, diags := types.SetValueFrom(ctx, types.StringType, secret.Auth.TokenPolicies)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		config.TokenPolicies = tokenPolicies
	} else {
		config.TokenPolicies = types.SetNull(types.StringType)
	}

	// Convert identity policies
	if len(secret.Auth.IdentityPolicies) > 0 {
		identityPolicies, diags := types.SetValueFrom(ctx, types.StringType, secret.Auth.IdentityPolicies)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		config.IdentityPolicies = identityPolicies
	} else {
		config.IdentityPolicies = types.SetNull(types.StringType)
	}

	// Convert metadata
	if len(secret.Auth.Metadata) > 0 {
		metadata, diags := types.MapValueFrom(ctx, types.StringType, secret.Auth.Metadata)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		config.Metadata = metadata
	} else {
		config.Metadata = types.MapNull(types.StringType)
	}

	// Store the accessor and namespace in private state for use in Close method
	// Must be JSON-encoded as per Terraform Plugin Framework requirements
	if secret.Auth.Accessor != "" {
		privateData := kerberosPrivateData{
			Accessor:  secret.Auth.Accessor,
			Namespace: config.Namespace.ValueString(),
		}
		privateDataJSON, err := json.Marshal(privateData)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error encoding private data",
				err.Error(),
			)
			return
		}
		resp.Private.SetKey(ctx, "kerberos_data", privateDataJSON)
		tflog.Debug(ctx, fmt.Sprintf("Stored accessor and namespace in private state for token revocation: %s", secret.Auth.Accessor))
	}

	// Set the result after storing private state
	resp.Diagnostics.Append(resp.Result.Set(ctx, &config)...)
}

// Close revokes the Kerberos authentication token when the ephemeral resource is closed
func (e *kerberosAuthBackendLoginEphemeral) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	// Retrieve the private data from private state
	privateBytes, diags := req.Private.GetKey(ctx, "kerberos_data")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If no private data was stored (e.g., Open failed before setting it), nothing to clean up
	if len(privateBytes) == 0 {
		return
	}

	// Unmarshal the private data
	var privateData kerberosPrivateData
	if err := json.Unmarshal(privateBytes, &privateData); err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to unmarshal private data: %v", err))
		return
	}

	accessor := privateData.Accessor
	if accessor == "" {
		tflog.Debug(ctx, "No accessor found in private state, skipping token revocation")
		return
	}

	// Get the Vault client with the appropriate namespace from private data
	c, err := client.GetClient(ctx, e.Meta(), privateData.Namespace)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Revoke the token using its accessor
	tflog.Debug(ctx, fmt.Sprintf("Revoking Kerberos token with accessor: %s", accessor))
	err = c.Auth().Token().RevokeAccessor(accessor)
	if err != nil {
		// Log the error but don't fail the close operation
		// The token may have already expired or been revoked
		tflog.Warn(ctx, fmt.Sprintf("Failed to revoke token with accessor %s: %v", accessor, err))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully revoked Kerberos token with accessor: %s", accessor))
}
