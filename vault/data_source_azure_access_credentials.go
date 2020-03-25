package vault

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2017-09-01/network"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func azureAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: azureAccessCredentialsDataSourceRead,

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
				Default:     7,
				Description: `If 'validate_creds' is true, the number of seconds to wait between each test of generated credentials.`,
			},
			"max_cred_validation_seconds": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     20 * 60, // 20 minutes
				Description: `If 'validate_creds' is true, the number of seconds after which to give up validating credentials.`,
			},
			"subscription_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `If 'validate_creds' is true, the subscription id to use to test whether the client ID and secret are valid.`,
			},
			"tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `If 'validate_creds' is true, the tenant id  to use to test whether the client ID and secret are valid.`,
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
			},
			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},
			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},
			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},
			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func azureAccessCredentialsDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	path := backend + "/creds/" + role

	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return fmt.Errorf("no role found at path %q", path)
	}

	clientID := secret.Data["client_id"].(string)
	clientSecret := secret.Data["client_secret"].(string)

	d.SetId(secret.LeaseID)
	_ = d.Set("client_id", secret.Data["client_id"])
	_ = d.Set("client_secret", secret.Data["client_secret"])
	_ = d.Set("lease_id", secret.LeaseID)
	_ = d.Set("lease_duration", secret.LeaseDuration)
	_ = d.Set("lease_start_time", time.Now().Format(time.RFC3339))
	_ = d.Set("lease_renewable", secret.Renewable)

	subscriptionID := d.Get("subscription_id").(string)
	tenantID := d.Get("tenant_id").(string)

	// If we're not supposed to validate creds, or we don't have enough
	// information to do it, there's nothing further to do here.
	validateCreds := d.Get("validate_creds").(bool)
	if !validateCreds {
		// We're done.
		return nil
	}
	if subscriptionID == "" || tenantID == "" {
		return fmt.Errorf(`if 'validate_creds' is true, both 'subscription_id' and 'tenant_id' must also be provided`)
	}

	// Let's, test the credentials before returning them.
	vnetClient := network.NewVirtualNetworksClient(subscriptionID)

	// You can't directly pass in a client ID and secret.
	// The closest thing you can do is provide them through the environment.
	revert, err := setEnv(auth.TenantID, tenantID)
	if err != nil {
		return err
	}
	defer revert()

	revert, err = setEnv(auth.ClientID, clientID)
	if err != nil {
		return err
	}
	defer revert()

	revert, err = setEnv(auth.ClientSecret, clientSecret)
	if err != nil {
		return err
	}
	defer revert()

	authorizer, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return err
	}
	vnetClient.Authorizer = authorizer

	credValidationTimeoutSecs := d.Get("max_cred_validation_seconds").(int)
	sequentialSuccessesRequired := d.Get("num_sequential_successes").(int)
	secBetweenTests := d.Get("num_seconds_between_tests").(int)

	startTime := time.Now()
	endTime := startTime.Add(time.Duration(credValidationTimeoutSecs) * time.Second)

	// This URL merely lists providers, and should return a 200 if the credentials
	// have propagated to the Azure server receiving the call.
	u := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers?api-version=2019-10-01", subscriptionID)

	// Please see this data source's documentation for an explanation of the
	// default parameters used here and why they were selected.
	sequentialSuccesses := 0
	overallSuccess := false
	for {
		if time.Now().After(endTime) {
			log.Printf("[DEBUG] giving up due to only having %d sequential successes and running out of time", sequentialSuccesses)
			break
		}
		log.Printf("[DEBUG] %d sequential successes obtained, waiting %d seconds to next test client ID and secret", sequentialSuccesses, secBetweenTests)
		time.Sleep(time.Duration(secBetweenTests) * time.Second)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return err
		}

		resp, err := vnetClient.Do(req)
		if err != nil {
			// We receive errors here if the credentials haven't propagated
			// because inside the Do call, there's a call that attempts to
			// refresh the token.
			sequentialSuccesses = 0
			continue
		}
		if err := resp.Body.Close(); err != nil {
			return err
		}
		sequentialSuccesses++
		if sequentialSuccesses == sequentialSuccessesRequired {
			overallSuccess = true
			break
		}
	}
	if !overallSuccess {
		// We hit the maximum number of retries without ever getting the
		// number of sequential successes we needed.
		return fmt.Errorf("despite trying for %d seconds, %d seconds apart, we were never able to get %d successes in a row",
			credValidationTimeoutSecs, secBetweenTests, sequentialSuccessesRequired)
	}
	return nil
}

func setEnv(envVar, newVal string) (revert func(), err error) {
	origVal := os.Getenv(envVar)
	if err := os.Setenv(envVar, newVal); err != nil {
		return nil, err
	}
	return func() {
		if err := os.Setenv(envVar, origVal); err != nil {
			log.Printf("[DEBUG] Unable to revert %s to original value due to %s", envVar, err)
		}
	}, nil
}
