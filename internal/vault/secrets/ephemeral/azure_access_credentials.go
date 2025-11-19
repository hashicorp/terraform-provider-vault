// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/pointerutil"
)

// https://learn.microsoft.com/en-us/graph/sdks/national-clouds
const (
	azurePublicCloudEnvName = "AZUREPUBLICCLOUD"
	azureChinaCloudEnvName  = "AZURECHINACLOUD"
	azureUSGovCloudEnvName  = "AZUREUSGOVERNMENTCLOUD"

	// Default values for credential validation
	defaultNumSecondsBetweenTests   = 1
	defaultMaxCredValidationSeconds = 300
	defaultNumSequentialSuccesses   = 8
)

var azureCloudConfigMap = map[string]cloud.Configuration{
	azureChinaCloudEnvName:  cloud.AzureChina,
	azurePublicCloudEnvName: cloud.AzurePublic,
	azureUSGovCloudEnvName:  cloud.AzureGovernment,
}

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &AzureAccessCredentialsEphemeralResource{}
var _ ephemeral.EphemeralResourceWithClose = &AzureAccessCredentialsEphemeralResource{}

// NewAzureAccessCredentialsEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewAzureAccessCredentialsEphemeralResource = func() ephemeral.EphemeralResource {
	return &AzureAccessCredentialsEphemeralResource{}
}

// AzureAccessCredentialsEphemeralResource implements the methods that define this resource
type AzureAccessCredentialsEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// AzureAccessCredentialsPrivateData stores data needed for cleanup in Close
type AzureAccessCredentialsPrivateData struct {
	LeaseID   string `json:"lease_id"`
	Namespace string `json:"namespace"`
}

// AzureAccessCredentialsModel describes the Terraform resource data model to match the
// resource schema.
type AzureAccessCredentialsModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Backend                  types.String `tfsdk:"backend"`
	Role                     types.String `tfsdk:"role"`
	ValidateCreds            types.Bool   `tfsdk:"validate_creds"`
	NumSequentialSuccesses   types.Int64  `tfsdk:"num_sequential_successes"`
	NumSecondsBetweenTests   types.Int64  `tfsdk:"num_seconds_between_tests"`
	MaxCredValidationSeconds types.Int64  `tfsdk:"max_cred_validation_seconds"`
	SubscriptionID           types.String `tfsdk:"subscription_id"`
	TenantID                 types.String `tfsdk:"tenant_id"`
	Environment              types.String `tfsdk:"environment"`

	// computed fields
	ClientID       types.String `tfsdk:"client_id"`
	ClientSecret   types.String `tfsdk:"client_secret"`
	LeaseID        types.String `tfsdk:"lease_id"`
	LeaseDuration  types.Int64  `tfsdk:"lease_duration"`
	LeaseStartTime types.String `tfsdk:"lease_start_time"`
	LeaseRenewable types.Bool   `tfsdk:"lease_renewable"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
func (r *AzureAccessCredentialsEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Azure Secret Backend to read credentials from.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "Azure Secret Role to read credentials from.",
				Required:            true,
			},
			consts.FieldValidateCreds: schema.BoolAttribute{
				MarkdownDescription: "Whether generated credentials should be validated before being returned.",
				Optional:            true,
			},
			consts.FieldNumSequentialSuccesses: schema.Int64Attribute{
				MarkdownDescription: "If 'validate_creds' is true, the number of sequential successes required to validate generated credentials.",
				Optional:            true,
			},
			consts.FieldNumSecondsBetweenTests: schema.Int64Attribute{
				MarkdownDescription: "If 'validate_creds' is true, the number of seconds to wait between each test of generated credentials.",
				Optional:            true,
			},
			consts.FieldMaxCredValidationSeconds: schema.Int64Attribute{
				MarkdownDescription: "If 'validate_creds' is true, the number of seconds after which to give up validating credentials.",
				Optional:            true,
			},
			consts.FieldSubscriptionID: schema.StringAttribute{
				MarkdownDescription: "The subscription ID to use during credential validation. Defaults to the subscription ID configured in the Vault backend.",
				Optional:            true,
			},
			consts.FieldTenantID: schema.StringAttribute{
				MarkdownDescription: "The tenant ID to use during credential validation. Defaults to the tenant ID configured in the Vault backend.",
				Optional:            true,
			},
			consts.FieldEnvironment: schema.StringAttribute{
				MarkdownDescription: "The Azure environment to use during credential validation. Defaults to the Azure Public Cloud. Some possible values: AzurePublicCloud, AzureUSGovernmentCloud.",
				Optional:            true,
			},
			consts.FieldClientID: schema.StringAttribute{
				MarkdownDescription: "The client id for credentials to query the Azure APIs.",
				Computed:            true,
			},
			consts.FieldClientSecret: schema.StringAttribute{
				MarkdownDescription: "The client secret for credentials to query the Azure APIs.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldLeaseID: schema.StringAttribute{
				MarkdownDescription: "Lease identifier assigned by vault.",
				Computed:            true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "Lease duration in seconds relative to the time in lease_start_time.",
				Computed:            true,
			},
			consts.FieldLeaseStartTime: schema.StringAttribute{
				MarkdownDescription: "Time at which the lease was read, using the clock of the system where Terraform was running.",
				Computed:            true,
			},
			consts.FieldLeaseRenewable: schema.BoolAttribute{
				MarkdownDescription: "True if the duration of this lease can be extended through renewal.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to read Azure access credentials from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *AzureAccessCredentialsEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_access_credentials"
}

func (r *AzureAccessCredentialsEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AzureAccessCredentialsModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	role := data.Role.ValueString()
	credsPath := backend + "/creds/" + role

	// Retry logic for reading credentials from Vault with exponential backoff
	// Azure can return rate limit errors generating credentials when multiple
	// requests are made during plan,apply,refresh in quick succession
	var secret *api.Secret
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 2 * time.Second
	bo.MaxInterval = 30 * time.Second
	bo.MaxElapsedTime = 5 * time.Minute

	err = backoff.RetryNotify(
		func() error {
			var readErr error
			secret, readErr = c.Logical().ReadWithContext(ctx, credsPath)
			if readErr != nil {
				errMsg := readErr.Error()
				// Check if this is a rate limit error from Azure
				if strings.Contains(errMsg, "concurrent requests being made") {
					// Retryable error
					return readErr
				}
				// Non-retryable error
				return backoff.Permanent(readErr)
			}
			return nil
		},
		bo,
		func(err error, duration time.Duration) {
			log.Printf("[WARN] Azure rate limit error reading credentials, retrying in %s: %s", duration, err)
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading from Vault",
			fmt.Sprintf("Error reading Azure credentials from path %q: %s", credsPath, err),
		)
		return
	}

	if secret == nil {
		resp.Diagnostics.AddError(
			"No role found",
			fmt.Sprintf("No role found at path %q", credsPath),
		)
		return
	}

	log.Printf("[DEBUG] Read %q from Vault", credsPath)

	clientID, ok := secret.Data["client_id"].(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid response from Vault",
			"client_id field not found or not a string in Vault response",
		)
		return
	}

	clientSecret, ok := secret.Data["client_secret"].(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Invalid response from Vault",
			"client_secret field not found or not a string in Vault response",
		)
		return
	}

	// Set the basic credential fields
	data.ClientID = types.StringValue(clientID)
	data.ClientSecret = types.StringValue(clientSecret)
	data.LeaseID = types.StringValue(secret.LeaseID)
	data.LeaseDuration = types.Int64Value(int64(secret.LeaseDuration))
	data.LeaseStartTime = types.StringValue(time.Now().Format(time.RFC3339))
	data.LeaseRenewable = types.BoolValue(secret.Renewable)

	// Store lease information in private data for cleanup in Close
	if secret.LeaseID != "" {
		privateData, err := json.Marshal(AzureAccessCredentialsPrivateData{
			LeaseID:   secret.LeaseID,
			Namespace: data.Namespace.ValueString(),
		})
		if err != nil {
			log.Printf("[WARN] Failed to marshal private data: %s", err)
		} else {
			resp.Private.SetKey(ctx, "lease_data", privateData)
		}
	}

	// If we're not supposed to validate creds, we're done
	if !data.ValidateCreds.ValueBool() {
		resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
		return
	}

	// Credential validation logic
	configPath := backend + "/config"
	var config *api.Secret
	getConfigData := func() (map[string]interface{}, error) {
		if config == nil {
			configSecret, err := c.Logical().ReadWithContext(ctx, configPath)
			if err != nil {
				return nil, fmt.Errorf("error reading from Vault: %w", err)
			}
			if configSecret == nil {
				return nil, fmt.Errorf("config not found at %q", configPath)
			}
			config = configSecret
		}
		return config.Data, nil
	}

	subscriptionID := data.SubscriptionID.ValueString()
	if subscriptionID == "" {
		configData, err := getConfigData()
		if err != nil {
			resp.Diagnostics.AddError("Error reading backend config", err.Error())
			return
		}
		if v, ok := configData["subscription_id"]; ok {
			subscriptionID = v.(string)
		}
	}

	if subscriptionID == "" {
		resp.Diagnostics.AddError(
			"Missing subscription_id",
			"subscription_id cannot be empty when validate_creds is true",
		)
		return
	}

	tenantID := data.TenantID.ValueString()
	if tenantID == "" {
		configData, err := getConfigData()
		if err != nil {
			resp.Diagnostics.AddError("Error reading backend config", err.Error())
			return
		}
		if v, ok := configData["tenant_id"]; ok {
			tenantID = v.(string)
		}
	}

	if tenantID == "" {
		resp.Diagnostics.AddError(
			"Missing tenant_id",
			"tenant_id cannot be empty when validate_creds is true",
		)
		return
	}

	environment := data.Environment.ValueString()
	if environment == "" {
		configData, err := getConfigData()
		if err != nil {
			resp.Diagnostics.AddError("Error reading backend config", err.Error())
			return
		}
		if v, ok := configData["environment"]; ok && v.(string) != "" {
			environment = v.(string)
		}
	}

	cloudConfig, err := getAzureCloudConfigFromName(environment)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Azure environment", err.Error())
		return
	}

	// Default validation parameters
	delay := time.Duration(defaultNumSecondsBetweenTests) * time.Second
	if !data.NumSecondsBetweenTests.IsNull() {
		delay = time.Duration(data.NumSecondsBetweenTests.ValueInt64()) * time.Second
	}

	maxValidationSeconds := int64(defaultMaxCredValidationSeconds)
	if !data.MaxCredValidationSeconds.IsNull() {
		maxValidationSeconds = data.MaxCredValidationSeconds.ValueInt64()
	}

	wantSuccessCount := int64(defaultNumSequentialSuccesses)
	if !data.NumSequentialSuccesses.IsNull() {
		wantSuccessCount = data.NumSequentialSuccesses.ValueInt64()
	}

	endTime := time.Now().Add(time.Duration(maxValidationSeconds) * time.Second)
	var successCount int64

	// Credential validation retry loop
	for {
		creds, err := azidentity.NewClientSecretCredential(
			tenantID, clientID, clientSecret, &azidentity.ClientSecretCredentialOptions{})
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to create credentials",
				fmt.Sprintf("Failed to create new credential during validation: %s", err),
			)
			return
		}

		providerClient, err := armresources.NewProvidersClient(subscriptionID, creds, &arm.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Cloud: cloudConfig,
			},
		})
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to create Azure client",
				fmt.Sprintf("Failed to create new provider client during validation: %s", err),
			)
			return
		}

		pager := providerClient.NewListPager(&armresources.ProvidersClientListOptions{
			Expand: pointerutil.StringPtr("metadata"),
		})

		hasError := false
		for pager.More() {
			var rawResponse *http.Response
			ctxWithResp := runtime.WithCaptureResponse(ctx, &rawResponse)

			_, err := pager.NextPage(ctxWithResp)
			if err != nil {
				hasError = true
				log.Printf("[WARN] Provider Client List request failed err=%s", err)
				break
			}

			log.Printf("[DEBUG] Provider Client List response %+v", rawResponse)
		}

		if !hasError {
			successCount++
			log.Printf("[DEBUG] Credential validation succeeded on try %d/%d", successCount, wantSuccessCount)
			if successCount >= wantSuccessCount {
				break
			}
		} else {
			log.Printf("[WARN] Credential validation failed, retrying in %s", delay)
			successCount = 0
		}

		if time.Now().After(endTime) {
			resp.Diagnostics.AddError(
				"Credential validation timeout",
				fmt.Sprintf("validation failed after max_cred_validation_seconds of %d, giving up; now=%s, endTime=%s",
					maxValidationSeconds, time.Now().String(), endTime.String()),
			)
			return
		}

		time.Sleep(delay)
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

// Close revokes the credentials lease when the ephemeral resource is no longer needed
func (r *AzureAccessCredentialsEphemeralResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	privateBytes, diags := req.Private.GetKey(ctx, "lease_data")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If no private data, nothing to clean up
	if len(privateBytes) == 0 {
		return
	}

	var privateData AzureAccessCredentialsPrivateData
	if err := json.Unmarshal(privateBytes, &privateData); err != nil {
		log.Printf("[WARN] Failed to unmarshal private data: %s", err)
		return
	}

	if privateData.LeaseID == "" {
		// No lease to revoke
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), privateData.Namespace)
	if err != nil {
		resp.Diagnostics.AddError("Error configuring Vault client for revoke", err.Error())
		return
	}

	// Attempt to revoke the lease
	err = c.Sys().Revoke(privateData.LeaseID)
	if err != nil {
		// Log but do not fail resource close
		log.Printf("[WARN] Failed to revoke lease %q: %s", privateData.LeaseID, err)
	} else {
		log.Printf("[DEBUG] Successfully revoked lease %q", privateData.LeaseID)
	}
}

func getAzureCloudConfigFromName(name string) (cloud.Configuration, error) {
	if name == "" {
		return cloud.AzurePublic, nil
	}
	if c, ok := azureCloudConfigMap[strings.ToUpper(name)]; !ok {
		return c, fmt.Errorf("unsupported Azure cloud name %q", name)
	} else {
		return c, nil
	}
}
