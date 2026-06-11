// Copyright IBM Corp. 2016, 2026
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
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
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
		ReadContext: provider.ReadContextWrapper(awsAccessCredentialsDataSourceRead),

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

func awsAccessCredentialsDataSourceRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	backend := d.Get("backend").(string)
	credType := d.Get("type").(string)
	role := d.Get("role").(string)
	path := backend + "/" + credType + "/" + role

	arn := d.Get("role_arn").(string)
	// If the ARN is empty and only one is specified in the role definition, this should work without issue
	data := map[string][]string{
		"role_arn": {arn},
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = []string{v.(string)}
	}

	log.Printf("[DEBUG] Reading %q from Vault with data %#v", path, data)
	secret, err := client.Logical().ReadWithData(path, data)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading AWS credentials from Vault: %w", err))
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return diag.FromErr(fmt.Errorf("no role found at path %q", path))
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

	// Default to us-east-1 when no region is provided, since IAM and STS are global services
	// and require a region to be set in the AWS SDK v2 configuration.
	region := d.Get("region").(string)
	if region == "" {
		region = "us-east-1"
	}
	optFns = append(optFns, config.WithRegion(region))

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return diag.FromErr(fmt.Errorf("failed to load AWS SDK configuration: %w", err))
	}

	iamconn := iam.NewFromConfig(cfg)
	stsconn := sts.NewFromConfig(cfg)

	// Different types of AWS credentials have different behavior around consistency.
	// See https://www.vaultproject.io/docs/secrets/aws/index.html#usage for more.
	if credType == "sts" {
		// STS credentials are immediately consistent. Let's ensure they're working.
		log.Printf("[DEBUG] Checking if AWS sts token %q is valid", secret.LeaseID)

		// Use a bounded timeout for STS validation.
		// GetCallerIdentity is typically sub‑second but can be delayed by network
		// latency or throttling; 10 seconds provides sufficient headroom while
		// preventing indefinite hangs in the provider.

		stsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if _, err := stsconn.GetCallerIdentity(stsCtx, &sts.GetCallerIdentityInput{}); err != nil {
			return diag.FromErr(fmt.Errorf("error validating STS credentials: %w", err))
		}
		return nil
	}

	// Other types of credentials are eventually consistent. Let's check credential
	// validity and slow down to give credentials time to propagate before we return
	// them. We'll wait for at least 5 sequential successes before giving creds back
	// to the user.
	sequentialSuccesses := 0

	// validateCreds is a retry function, which will be retried until it succeeds.
	validateCreds := func() *retry.RetryError {
		log.Printf("[DEBUG] Checking if AWS creds %q are valid", secret.LeaseID)

		// Use a timeout context to bound each individual IAM validation attempt.
		iamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if _, err := iamconn.GetUser(iamCtx, nil); err != nil && isAWSAuthError(err) {
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
			return diag.FromErr(fmt.Errorf(
				"AWS credentials did not become consistent after %d successful validations within %.f seconds",
				sequentialSuccessesRequired,
				sequentialSuccessTimeLimit.Seconds(),
			))
		}
		if err := retry.Retry(retryTimeOut, validateCreds); err != nil {
			return diag.FromErr(fmt.Errorf("AWS credentials validation failed after retries: %w", err))
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
