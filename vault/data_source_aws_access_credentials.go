// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	// sequentialSuccessesRequired is the number of times the test of an eventually consistent
	// credential must succeed before we return it for use.
	sequentialSuccessesRequired = 5

	// sequentialSuccessTimeLimit is how long we'll wait for eventually consistent AWS creds
	// to propagate before giving up. In real life, we've seen it take up to 15 seconds, so
	// this is ample and if it's unsuccessful there's something else wrong.
	sequentialSuccessTimeLimit = time.Minute

	// retryTimeOut is how long we'll wait before timing out when we're retrying credentials.
	// This corresponds to Vault's default 30-second request timeout.
	retryTimeOut = 30 * time.Second

	// propagationBuffer is the added buffer of time we'll wait after N sequential successes
	// before returning credentials for use.
	propagationBuffer = 5 * time.Second

	// AWS error codes used in credential validation
	awsErrorAccessDenied       = "AccessDenied"
	awsErrorValidationError    = "ValidationError"
	awsErrorInvalidClientToken = "InvalidClientTokenId"
)

func awsAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(awsAccessCredentialsDataSourceRead),

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS Secret Backend to read credentials from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS Secret Role to read credentials from.",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "creds",
				Description: "Type of credentials to read. Must be either 'creds' for Access Key and Secret Key, or 'sts' for STS.",
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if value != "sts" && value != "creds" {
						errs = append(errs, fmt.Errorf("type must be creds or sts"))
					}
					return nil, errs
				},
			},
			"role_arn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ARN to use if multiple are available in the role. Required if the role has multiple ARNs.",
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Region the read credentials belong to. Defaults to us-east-1 if unset.",
			},
			"access_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS access key ID read from Vault.",
				Sensitive:   true,
			},
			"secret_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS secret key read from Vault.",
				Sensitive:   true,
			},
			"security_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS security token read from Vault. (Only returned if type is 'sts').",
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
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User specified Time-To-Live for the STS token. Uses the Role defined default_sts_ttl when not specified",
			},
		},
	}
}

func awsAccessCredentialsDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	credType := d.Get("type").(string)
	role := d.Get("role").(string)
	path := backend + "/" + credType + "/" + role

	arn := d.Get("role_arn").(string)
	data := map[string][]string{
		"role_arn": {arn},
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = []string{v.(string)}
	}

	log.Printf("[DEBUG] Reading %q from Vault with data %#v", path, data)
	secret, err := client.Logical().ReadWithData(path, data)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return fmt.Errorf("no role found at path %q", path)
	}

	accessKey := secret.Data["access_key"].(string)
	secretKey := secret.Data["secret_key"].(string)
	var securityToken string
	if secret.Data["security_token"] != nil {
		securityToken = secret.Data["security_token"].(string)
	}

	d.SetId(secret.LeaseID)
	d.Set("access_key", secret.Data["access_key"])
	d.Set("secret_key", secret.Data["secret_key"])
	d.Set("security_token", secret.Data["security_token"])
	d.Set(consts.FieldLeaseID, secret.LeaseID)
	d.Set(consts.FieldLeaseDuration, secret.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format(time.RFC3339))
	d.Set(consts.FieldLeaseRenewable, secret.Renewable)

	optFns := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, securityToken),
		),
		config.WithHTTPClient(cleanhttp.DefaultClient()),
	}

	region := d.Get("region").(string)
	if region == "" {
		region = "us-east-1"
	}
	optFns = append(optFns, config.WithRegion(region))

	cfg, err := config.LoadDefaultConfig(context.TODO(), optFns...)
	if err != nil {
		return fmt.Errorf("error creating AWS config: %s", err)
	}

	iamconn := iam.NewFromConfig(cfg)
	stsconn := sts.NewFromConfig(cfg)

	if credType == "sts" {
		log.Printf("[DEBUG] Checking if AWS sts token %q is valid", secret.LeaseID)

		// Create a cancellable context with timeout for the STS call
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if _, err := stsconn.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
			return err
		}
		return nil
	}

	sequentialSuccesses := 0

	validateCreds := func() *retry.RetryError {
		log.Printf("[DEBUG] Checking if AWS creds %q are valid", secret.LeaseID)

		// Create a cancellable context with timeout for each IAM validation call
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if _, err := iamconn.GetUser(ctx, nil); err != nil && isAWSAuthError(err) {
			sequentialSuccesses = 0
			log.Printf("[DEBUG] AWS auth error checking if creds %q are valid, is retryable", secret.LeaseID)
			wrappedErr := fmt.Errorf("AWS credentials validation failed (retryable): %w", err)
			return retry.RetryableError(wrappedErr)
		} else if err != nil {
			log.Printf("[DEBUG] Error checking if creds %q are valid: %s", secret.LeaseID, err)
			return retry.NonRetryableError(err)
		}
		sequentialSuccesses++
		log.Printf("[DEBUG] Checked if AWS creds %q are valid", secret.LeaseID)
		return nil
	}

	start := time.Now()
	for sequentialSuccesses < sequentialSuccessesRequired {
		if time.Since(start) > sequentialSuccessTimeLimit {
			return fmt.Errorf("unable to get %d sequential successes within %.f seconds", sequentialSuccessesRequired, sequentialSuccessTimeLimit.Seconds())
		}
		if err := retry.Retry(retryTimeOut, validateCreds); err != nil {
			return fmt.Errorf("error checking if credentials are valid: %s", err)
		}
	}

	log.Printf("[DEBUG] Waiting an additional %.f seconds for new credentials to propagate...", propagationBuffer.Seconds())
	time.Sleep(propagationBuffer)
	return nil
}

func isAWSAuthError(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case awsErrorAccessDenied, awsErrorValidationError, awsErrorInvalidClientToken:
		return true
	default:
		return false
	}
}
