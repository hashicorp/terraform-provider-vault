// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/pointerutil"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func azureAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(azureAccessCredentialsDataSourceRead),

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
Defaults to the environment configured in the Vault backend.
Some possible values: AzurePublicCloud, AzureUSGovernmentCloud`,
			},
		},
	}
}

func azureAccessCredentialsDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	credsPath := backend + "/creds/" + role

	secret, err := client.Logical().Read(credsPath)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", credsPath)

	if secret == nil {
		return fmt.Errorf("no role found at credsPath %q", credsPath)
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
			return err
		}
		if v, ok := data["subscription_id"]; ok {
			subscriptionID = v.(string)
		}
	}

	if subscriptionID == "" {
		return fmt.Errorf("subscription_id cannot be empty when validate_creds is true")
	}

	tenantID := ""
	if v, ok := d.GetOk("tenant_id"); ok {
		tenantID = v.(string)
	} else {
		data, err := getConfigData()
		if err != nil {
			return err
		}
		if v, ok := data["tenant_id"]; ok {
			tenantID = v.(string)
		}
	}

	if tenantID == "" {
		return fmt.Errorf("tenant_id cannot be empty when validate_creds is true")
	}

	creds, err := azidentity.NewClientSecretCredential(
		tenantID, clientID, clientSecret, &azidentity.ClientSecretCredentialOptions{})
	if err != nil {
		return err
	}

	clientOptions := &arm.ClientOptions{}
	var environment string
	if v, ok := d.GetOk("environment"); ok {
		environment = v.(string)
	} else {
		data, err := getConfigData()
		if err != nil {
			return err
		}
		if v, ok := data["environment"]; ok && v.(string) != "" {
			environment = v.(string)
		}
	}

	if environment != "" {
		env, err := azure.EnvironmentFromName(environment)
		if err != nil {
			return err
		}

		switch env.Name {
		case "AzurePublicCloud":
			clientOptions.Endpoint = arm.AzurePublicCloud
		case "AzureChinaCloud":
			clientOptions.Endpoint = arm.AzureChina
		case "AzureUSGovernmentCloud":
			clientOptions.Endpoint = arm.AzureGovernment
		case "AzureGermanCloud":
			// AzureGermanCloud appears to have been removed,
			// keeping this here to handle the case where the secret engine has
			// been configured with this environment.
			clientOptions.Endpoint = arm.Endpoint(env.ResourceManagerEndpoint)
		}
	}

	providerClient := armresources.NewProvidersClient(subscriptionID, creds, clientOptions)
	ctx := context.Background()
	delay := time.Duration(d.Get("num_seconds_between_tests").(int)) * time.Second
	endTime := time.Now().Add(
		time.Duration(d.Get("max_cred_validation_seconds").(int)) * time.Second)
	wantSuccessCount := d.Get("num_sequential_successes").(int)
	var successCount int
	for {
		pager := providerClient.List(&armresources.ProvidersClientListOptions{
			Expand: pointerutil.StringPtr("metadata"),
		})

		for pager.NextPage(ctx) {
			pr := pager.PageResponse()
			if pr.RawResponse.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf("validation failed, unauthorized credentials from Vault, err=%w", pager.Err())
			}
			log.Printf("[DEBUG] Provider Client List response %+v", pr.RawResponse)
		}

		if pager.Err() == nil {
			successCount++
			log.Printf("[DEBUG] Credential validation succeeded try %d/%d", successCount, wantSuccessCount)
			if successCount >= wantSuccessCount {
				break
			}
		} else {
			if time.Now().After(endTime) {
				return fmt.Errorf("validation failed, giving up err=%w", pager.Err())
			}

			log.Printf("[WARN] Credential validation failed with %v, retrying in %s", pager.Err(), delay)
			successCount = 0
		}
		time.Sleep(delay)
	}

	return nil
}
