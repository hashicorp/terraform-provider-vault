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
	sequentialSuccessesRequired = 5
	sequentialSuccessTimeLimit  = time.Minute
	retryTimeOut                = 30 * time.Second
	propagationBuffer           = 5 * time.Second
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
				Description: "Region the read credentials belong to.",
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

	// CHANGED: replaced aws.Config + session.NewSession with config.LoadDefaultConfig
	optFns := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, securityToken),
		),
		config.WithHTTPClient(cleanhttp.DefaultClient()),
	}

	region := d.Get("region").(string)
	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), optFns...)
	if err != nil {
		return fmt.Errorf("error creating AWS config: %s", err)
	}

	// CHANGED: replaced iam.New(sess) and sts.New(sess) with NewFromConfig
	iamconn := iam.NewFromConfig(cfg)
	stsconn := sts.NewFromConfig(cfg)

	if credType == "sts" {
		log.Printf("[DEBUG] Checking if AWS sts token %q is valid", secret.LeaseID)
		// CHANGED: added context.TODO() as first argument
		if _, err := stsconn.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{}); err != nil {
			return err
		}
		return nil
	}

	sequentialSuccesses := 0

	validateCreds := func() *retry.RetryError {
		log.Printf("[DEBUG] Checking if AWS creds %q are valid", secret.LeaseID)
		// CHANGED: added context.TODO() as first argument
		if _, err := iamconn.GetUser(context.TODO(), nil); err != nil && isAWSAuthError(err) {
			sequentialSuccesses = 0
			log.Printf("[DEBUG] AWS auth error checking if creds %q are valid, is retryable", secret.LeaseID)
			return retry.RetryableError(err)
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

// CHANGED: replaced awserr.Error pattern with smithy.APIError + errors.As
func isAWSAuthError(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied":
		return true
	case "ValidationError":
		return true
	case "InvalidClientTokenId":
		return true
	default:
		return false
	}
}
