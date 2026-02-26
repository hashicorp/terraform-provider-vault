// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(&opts); err != nil {
			return options{}, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments
type Option func(*options) error

// options = how options are represented
type options struct {
	withSharedCredentials    bool
	withAwsConfig            *aws.Config
	withUsername             string
	withAccessKey            string
	withSecretKey            string
	withLogger               hclog.Logger
	withStsEndpointResolver  sts.EndpointResolverV2
	withIamEndpointResolver  iam.EndpointResolverV2
	withMaxRetries           *int
	withRegion               string
	withRoleArn              string
	withRoleSessionName      string
	withRoleExternalId       string
	withRoleTags             map[string]string
	withWebIdentityTokenFile string
	withWebIdentityToken     string
	withHttpClient           *http.Client
	withValidityCheckTimeout time.Duration
	withIAMAPIFunc           IAMAPIFunc
	withSTSAPIFunc           STSAPIFunc
	withCredentialsProvider  aws.CredentialsProvider
}

func getDefaultOptions() options {
	return options{
		withSharedCredentials: true,
	}
}

// WithRoleArn allows passing a role arn to use when
// creating either a web identity role provider
// or a ec2-instance role provider.
func WithRoleArn(with string) Option {
	return func(o *options) error {
		o.withRoleArn = with
		return nil
	}
}

// WithRoleSessionName allows passing a session name to use when
// creating either a web identity role provider
// or a ec2-instance role provider.
// If set, the RoleARN must be set.
func WithRoleSessionName(with string) Option {
	return func(o *options) error {
		o.withRoleSessionName = with
		return nil
	}
}

// WithRoleExternalId allows passing a external id to use when
// creating a ec2-instance role provider.
// If not set, the role will be assumed in the same account.
// If set, the RoleARN must be set.
func WithRoleExternalId(with string) Option {
	return func(o *options) error {
		o.withRoleExternalId = with
		return nil
	}
}

// WithRoleTags allows passing tags to use when
// creating a ec2-instance role provider.
// If set, the RoleARN must be set.
func WithRoleTags(with map[string]string) Option {
	return func(o *options) error {
		o.withRoleTags = with
		return nil
	}
}

// WithWebIdentityTokenFile allows passing a web identity token file to use for
// the assumed role. If set, the RoleARN must be set.
func WithWebIdentityTokenFile(with string) Option {
	return func(o *options) error {
		o.withWebIdentityTokenFile = with
		return nil
	}
}

// WithWebIdentityToken allows passing a web identity token to use for the
// assumed role. If set, the RoleARN must be set.
func WithWebIdentityToken(with string) Option {
	return func(o *options) error {
		o.withWebIdentityToken = with
		return nil
	}
}

// WithSharedCredentials allows controlling whether shared credentials are used
func WithSharedCredentials(with bool) Option {
	return func(o *options) error {
		o.withSharedCredentials = with
		return nil
	}
}

// WithAwsConfig allows controlling the configuration passed into the client
func WithAwsConfig(with *aws.Config) Option {
	return func(o *options) error {
		o.withAwsConfig = with
		return nil
	}
}

// WithUsername allows passing the user name to use for an operation
func WithUsername(with string) Option {
	return func(o *options) error {
		o.withUsername = with
		return nil
	}
}

// WithAccessKey allows passing an access key to use for operations
func WithAccessKey(with string) Option {
	return func(o *options) error {
		o.withAccessKey = with
		return nil
	}
}

// WithSecretKey allows passing a secret key to use for operations
func WithSecretKey(with string) Option {
	return func(o *options) error {
		o.withSecretKey = with
		return nil
	}
}

// WithStsEndpointResolver allows passing a custom STS endpoint resolver
func WithStsEndpointResolver(with sts.EndpointResolverV2) Option {
	return func(o *options) error {
		o.withStsEndpointResolver = with
		return nil
	}
}

// WithIamEndppointResolver allows passing a custom IAM endpoint resolver
func WithIamEndpointResolver(with iam.EndpointResolverV2) Option {
	return func(o *options) error {
		o.withIamEndpointResolver = with
		return nil
	}
}

// WithRegion allows passing a custom region
func WithRegion(with string) Option {
	return func(o *options) error {
		o.withRegion = with
		return nil
	}
}

// WithLogger allows passing a logger to use
func WithLogger(with hclog.Logger) Option {
	return func(o *options) error {
		o.withLogger = with
		return nil
	}
}

// WithMaxRetries allows passing custom max retries to set
func WithMaxRetries(with *int) Option {
	return func(o *options) error {
		o.withMaxRetries = with
		return nil
	}
}

// WithHttpClient allows passing a custom client to use
func WithHttpClient(with *http.Client) Option {
	return func(o *options) error {
		o.withHttpClient = with
		return nil
	}
}

// WithValidityCheckTimeout allows passing a timeout for operations that can wait
// on success.
func WithValidityCheckTimeout(with time.Duration) Option {
	return func(o *options) error {
		o.withValidityCheckTimeout = with
		return nil
	}
}

// WithIAMAPIFunc allows passing in an IAM interface constructor for mocking
// the AWS IAM API.
func WithIAMAPIFunc(with IAMAPIFunc) Option {
	return func(o *options) error {
		o.withIAMAPIFunc = with
		return nil
	}
}

// WithSTSAPIFunc allows passing in a STS interface constructor for mocking the
// AWS STS API.
func WithSTSAPIFunc(with STSAPIFunc) Option {
	return func(o *options) error {
		o.withSTSAPIFunc = with
		return nil
	}
}

// WithCredentialsProvider allows passing in a CredentialsProvider interface
// constructor for mocking the AWS Credential Provider.
func WithCredentialsProvider(with aws.CredentialsProvider) Option {
	return func(o *options) error {
		o.withCredentialsProvider = with
		return nil
	}
}
