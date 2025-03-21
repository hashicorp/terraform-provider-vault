// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
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
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/pointerutil"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// https://learn.microsoft.com/en-us/graph/sdks/national-clouds
const (
	azurePublicCloudEnvName = "AZUREPUBLICCLOUD"
	azureChinaCloudEnvName  = "AZURECHINACLOUD"
	azureUSGovCloudEnvName  = "AZUREUSGOVERNMENTCLOUD"
)

var azureCloudConfigMap = map[string]cloud.Configuration{
	azureChinaCloudEnvName:  cloud.AzureChina,
	azurePublicCloudEnvName: cloud.AzurePublic,
	azureUSGovCloudEnvName:  cloud.AzureGovernment,
}

func azureAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		ReadContext: provider.ReadContextWrapper(azureAccessCredentialsDataSourceRead),

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Azure Secret Backend to read credentials from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Azure Secret Role to read credentials from.",
			},
			"validate_creds": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether generated credentials should be validated before being returned.",
				Default:     false,
			},
			"num_sequential_successes": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     8,
				Description: `If 'validate_creds' is true, the number of sequential successes required to validate generated credentials.`,
			},
			"num_seconds_between_tests": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1,
				Description: `If 'validate_creds' is true, the number of seconds to wait between each test of generated credentials.`,
			},
			"max_cred_validation_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     300,
				Description: `If 'validate_creds' is true, the number of seconds after which to give up validating credentials.`,
			},
			"client_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client id for credentials to query the Azure APIs.",
			},
			"client_secret": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client secret for credentials to query the Azure APIs.",
				Sensitive:   true,
			},
			consts.FieldLeaseID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},
			consts.FieldLeaseDuration: {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},
			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},
			consts.FieldLeaseRenewable: {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
			"subscription_id": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The subscription ID to use during credential validation. " +
					"Defaults to the subscription ID configured in the Vault backend",
			},
			"tenant_id": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The tenant ID to use during credential validation. " +
					"Defaults to the tenant ID configured in the Vault backend",
			},
			"environment": {
				Type:     schema.TypeString,
				Optional: true,
				Description: `The Azure environment to use during credential validation.
Defaults to the Azure Public Cloud.
Some possible values: AzurePublicCloud, AzureUSGovernmentCloud`,
			},
		},
	}
}

func azureAccessCredentialsDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	credsPath := backend + "/creds/" + role

	secret, err := client.Logical().Read(credsPath)
	if err != nil {
		return diag.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", credsPath)

	if secret == nil {
		return diag.Errorf("no role found at credsPath %q", credsPath)
	}

	clientID := secret.Data["client_id"].(string)
	clientSecret := secret.Data["client_secret"].(string)

	d.SetId(secret.LeaseID)
	_ = d.Set("client_id", secret.Data["client_id"])
	_ = d.Set("client_secret", secret.Data["client_secret"])
	_ = d.Set(consts.FieldLeaseID, secret.LeaseID)
	_ = d.Set(consts.FieldLeaseDuration, secret.LeaseDuration)
	_ = d.Set("lease_start_time", time.Now().Format(time.RFC3339))
	_ = d.Set(consts.FieldLeaseRenewable, secret.Renewable)

	// If we're not supposed to validate creds, or we don't have enough
	// information to do it, there's nothing further to do here.
	validateCreds := d.Get("validate_creds").(bool)
	if !validateCreds {
		// We're done.
		return nil
	}

	configPath := backend + "/config"
	// cache the config
	var config *api.Secret
	getConfigData := func() (map[string]interface{}, error) {
		if config == nil {
			c, err := client.Logical().Read(configPath)
			if err != nil {
				return nil, fmt.Errorf("error reading from Vault: %w", err)
			}
			if c == nil {
				return nil, fmt.Errorf("config not found at %q", configPath)
			}
			config = c
		}

		return config.Data, nil
	}

	subscriptionID := ""
	if v, ok := d.GetOk("subscription_id"); ok {
		subscriptionID = v.(string)
	} else {
		data, err := getConfigData()
		if err != nil {
			return diag.FromErr(e)
		}
		if v, ok := data["subscription_id"]; ok {
			subscriptionID = v.(string)
		}
	}

	if subscriptionID == "" {
		return diag.Errorf("subscription_id cannot be empty when validate_creds is true")
	}

	tenantID := ""
	if v, ok := d.GetOk("tenant_id"); ok {
		tenantID = v.(string)
	} else {
		data, err := getConfigData()
		if err != nil {
			return diag.FromErr(e)
		}
		if v, ok := data["tenant_id"]; ok {
			tenantID = v.(string)
		}
	}

	if tenantID == "" {
		return diag.Errorf("tenant_id cannot be empty when validate_creds is true")
	}

	var environment string
	if v, ok := d.GetOk("environment"); ok {
		environment = v.(string)
	} else {
		data, err := getConfigData()
		if err != nil {
			return diag.FromErr(e)
		}
		if v, ok := data["environment"]; ok && v.(string) != "" {
			environment = v.(string)
		}
	}

	cloudConfig, err := getAzureCloudConfigFromName(environment)
	if err != nil {
		return diag.FromErr(err)
	}

	delay := time.Duration(d.Get("num_seconds_between_tests").(int)) * time.Second
	maxValidationSeconds := d.Get("max_cred_validation_seconds").(int)
	endTime := time.Now().Add(time.Duration(maxValidationSeconds) * time.Second)
	wantSuccessCount := d.Get("num_sequential_successes").(int)
	var successCount int
	// begin validate_creds retry loop
	for {
		creds, err := azidentity.NewClientSecretCredential(
			tenantID, clientID, clientSecret, &azidentity.ClientSecretCredentialOptions{})
		if err != nil {
			return diag.Errorf("failed to create new credential during retry: %w", err)
		}

		providerClient, err := armresources.NewProvidersClient(subscriptionID, creds, &arm.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Cloud: cloudConfig,
			},
		})
		if err != nil {
			return diag.Errorf("failed to create new provider client during retry: %w", err)
		}

		pager := providerClient.NewListPager(&armresources.ProvidersClientListOptions{
			Expand: pointerutil.StringPtr("metadata"),
		})

		hasError := false
		for pager.More() {
			// capture raw response so we can get the status code
			var rawResponse *http.Response
			ctxWithResp := runtime.WithCaptureResponse(ctx, &rawResponse)

			_, err := pager.NextPage(ctxWithResp)
			if err != nil {
				hasError = true
				log.Printf("[WARN] Provider Client List request failed err=%s", err)
				// ensure we don't loop forever
				break
			}

			// log the response status code and headers
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
			return diag.Errorf(
				"validation failed after max_cred_validation_seconds of %d, giving up; now=%s, endTime=%s",
				maxValidationSeconds,
				time.Now().String(),
				endTime.String(),
			)
		}

		time.Sleep(delay)
	}

	return nil
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
