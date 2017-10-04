package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"

	"github.com/hashicorp/vault/api"
)

func awsSecretDataSource() *schema.Resource {
	return &schema.Resource{
		Read: awsSecretDataSourceRead,

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
					return
				},
			},
			"access_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS access key ID read from Vault.",
			},

			"secret_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS secret key read from Vault.",
			},

			"security_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS security token read from Vault. (Only returned if type is 'sts'.)",
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

func awsSecretDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	credType := d.Get("type").(string)
	role := d.Get("role").(string)
	path := backend + "/" + credType + "/" + role

	log.Printf("[DEBUG] Reading %q from Vault", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return fmt.Errorf("No role found at %q; are you sure you're using the right backend and role?", path)
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
	d.Set("lease_id", secret.LeaseID)
	d.Set("lease_duration", secret.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format(time.RFC3339))
	d.Set("lease_renewable", secret.Renewable)

	awsConfig := &aws.Config{
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, securityToken),
		HTTPClient:  cleanhttp.DefaultClient(),
	}
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return fmt.Errorf("Error creating AWS session: %s", err)
	}

	iamconn := iam.New(sess)
	stsconn := sts.New(sess)

	for successes := 0; successes < 3; successes++ {
		err = resource.Retry(1*time.Minute, func() *resource.RetryError {
			if credType == "creds" {
				log.Printf("[DEBUG] Checking if AWS creds %q are valid", secret.LeaseID)
				_, err := iamconn.GetUser(nil)
				if err != nil && isAWSAuthError(err) {
					log.Printf("[DEBUG] AWS auth error checking if creds %q are valid, is retryable", secret.LeaseID)
					return resource.RetryableError(err)
				} else if err != nil {
					log.Printf("[DEBUG] Error checking if creds %q are valid: %s", secret.LeaseID, err)
					return resource.NonRetryableError(err)
				}
				log.Printf("[DEBUG] Checked if AWS creds %q are valid", secret.LeaseID)
			} else {
				log.Printf("[DEBUG] Checking if AWS sts token %q is valid", secret.LeaseID)
				_, err := stsconn.GetCallerIdentity(&sts.GetCallerIdentityInput{})
				if err != nil && isAWSAuthError(err) {
					return resource.RetryableError(err)
				} else if err != nil {
					return resource.NonRetryableError(err)
				}
				log.Printf("[DEBUG] Checked if AWS sts token %q is valid", secret.LeaseID)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("Error checking if credentials are valid: %s", err)
		}
	}
	return nil
}

func isAWSAuthError(err error) bool {
	awsErr, ok := err.(awserr.Error)
	if !ok {
		return false
	}
	switch awsErr.Code() {
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
