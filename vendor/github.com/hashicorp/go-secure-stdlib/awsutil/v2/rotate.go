// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// RotateKeys takes the access key and secret key from this credentials config
// and first creates a new access/secret key, then deletes the old access key.
// If deletion of the old access key is successful, the new access key/secret
// key are written into the credentials config and nil is returned. On any
// error, the old credentials are not overwritten. This ensures that any
// generated new secret key never leaves this function in case of an error, even
// though it will still result in an extraneous access key existing; we do also
// try to delete the new one to clean up, although it's unlikely that will work
// if the old one could not be deleted.
//
// Supported options: WithSharedCredentials, WithAwsConfig
// WithUsername, WithValidityCheckTimeout, WithIAMAPIFunc,
// WithSTSAPIFunc
//
// Note that WithValidityCheckTimeout here, when non-zero, controls the
// WithValidityCheckTimeout option on access key creation. See CreateAccessKey
// for more details.
func (c *CredentialsConfig) RotateKeys(ctx context.Context, opt ...Option) error {
	if c.AccessKey == "" || c.SecretKey == "" {
		return errors.New("cannot rotate credentials when either access_key or secret_key is empty")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return fmt.Errorf("error reading options in RotateKeys: %w", err)
	}

	cfg := opts.withAwsConfig
	if cfg == nil {
		cfg, err = c.GenerateCredentialChain(ctx, opt...)
		if err != nil {
			return fmt.Errorf("error calling GenerateCredentialChain: %w", err)
		}
	}

	opt = append(opt, WithAwsConfig(cfg))
	createAccessKeyRes, err := c.CreateAccessKey(ctx, opt...)
	if err != nil {
		return fmt.Errorf("error calling CreateAccessKey: %w", err)
	}

	err = c.DeleteAccessKey(ctx, c.AccessKey, append(opt, WithUsername(*createAccessKeyRes.AccessKey.UserName))...)
	if err != nil {
		return fmt.Errorf("error deleting old access key: %w", err)
	}

	c.AccessKey = *createAccessKeyRes.AccessKey.AccessKeyId
	c.SecretKey = *createAccessKeyRes.AccessKey.SecretAccessKey

	return nil
}

// CreateAccessKey creates a new access/secret key pair.
//
// Supported options: WithSharedCredentials, WithAwsConfig,
// WithUsername, WithValidityCheckTimeout, WithIAMAPIFunc,
// WithSTSAPIFunc
//
// When WithValidityCheckTimeout is non-zero, it specifies a timeout to wait on
// the created credentials to be valid and ready for use.
func (c *CredentialsConfig) CreateAccessKey(ctx context.Context, opt ...Option) (*iam.CreateAccessKeyOutput, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading options in CreateAccessKey: %w", err)
	}

	client, err := c.IAMClient(ctx, opt...)
	if err != nil {
		return nil, fmt.Errorf("error loading IAM client: %w", err)
	}

	var getUserInput iam.GetUserInput
	if opts.withUsername != "" {
		getUserInput.UserName = aws.String(opts.withUsername)
	} // otherwise, empty input means get current user
	getUserRes, err := client.GetUser(ctx, &getUserInput)
	if err != nil {
		return nil, fmt.Errorf("error calling iam.GetUser: %w", err)
	}
	if getUserRes == nil {
		return nil, fmt.Errorf("nil response from iam.GetUser")
	}
	if getUserRes.User == nil {
		return nil, fmt.Errorf("nil user returned from iam.GetUser")
	}
	if getUserRes.User.UserName == nil {
		return nil, fmt.Errorf("nil UserName returned from iam.GetUser")
	}

	createAccessKeyInput := iam.CreateAccessKeyInput{
		UserName: getUserRes.User.UserName,
	}
	createAccessKeyRes, err := client.CreateAccessKey(ctx, &createAccessKeyInput)
	if err != nil {
		return nil, fmt.Errorf("error calling iam.CreateAccessKey: %w", err)
	}
	if createAccessKeyRes == nil {
		return nil, fmt.Errorf("nil response from iam.CreateAccessKey")
	}
	if createAccessKeyRes.AccessKey == nil {
		return nil, fmt.Errorf("nil access key in response from iam.CreateAccessKey")
	}
	if createAccessKeyRes.AccessKey.AccessKeyId == nil || createAccessKeyRes.AccessKey.SecretAccessKey == nil {
		return nil, fmt.Errorf("nil AccessKeyId or SecretAccessKey returned from iam.CreateAccessKey")
	}

	// Check the credentials to make sure they are usable. We only do
	// this if withValidityCheckTimeout is non-zero to ensue that we don't
	// immediately fail due to eventual consistency.
	if opts.withValidityCheckTimeout != 0 {
		newStaticCreds, err := NewCredentialsConfig(
			WithAccessKey(*createAccessKeyRes.AccessKey.AccessKeyId),
			WithSecretKey(*createAccessKeyRes.AccessKey.SecretAccessKey),
			WithRegion(c.Region),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create credential config with new static credential: %w", err)
		}

		if _, err := newStaticCreds.GetCallerIdentity(
			ctx,
			WithValidityCheckTimeout(opts.withValidityCheckTimeout),
			WithSTSAPIFunc(opts.withSTSAPIFunc),
		); err != nil {
			return nil, fmt.Errorf("error verifying new credentials: %w", err)
		}
	}

	return createAccessKeyRes, nil
}

// DeleteAccessKey deletes an access key.
//
// Supported options: WithSharedCredentials, WithAwsConfig, WithUserName, WithIAMAPIFunc
func (c *CredentialsConfig) DeleteAccessKey(ctx context.Context, accessKeyId string, opt ...Option) error {
	opts, err := getOpts(opt...)
	if err != nil {
		return fmt.Errorf("error reading options in RotateKeys: %w", err)
	}

	client, err := c.IAMClient(ctx, opt...)
	if err != nil {
		return fmt.Errorf("error loading IAM client: %w", err)
	}

	deleteAccessKeyInput := iam.DeleteAccessKeyInput{
		AccessKeyId: aws.String(accessKeyId),
	}
	if opts.withUsername != "" {
		deleteAccessKeyInput.UserName = aws.String(opts.withUsername)
	}

	_, err = client.DeleteAccessKey(ctx, &deleteAccessKeyInput)
	if err != nil {
		return fmt.Errorf("error deleting old access key: %w", err)
	}

	return nil
}

// GetCallerIdentity runs sts.GetCallerIdentity for the current set
// credentials. This can be used to check that credentials are valid,
// in addition to checking details about the effective logged in
// account and user ID.
//
// Supported options: WithSharedCredentials, WithAwsConfig, WithValidityCheckTimeout
func (c *CredentialsConfig) GetCallerIdentity(ctx context.Context, opt ...Option) (*sts.GetCallerIdentityOutput, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading options in GetCallerIdentity: %w", err)
	}

	client, err := c.STSClient(ctx, opt...)
	if err != nil {
		return nil, fmt.Errorf("error loading STS client: %w", err)
	}

	delay := time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.withValidityCheckTimeout)
	defer cancel()
	for {
		cid, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil {
			return cid, nil
		}
		select {
		case <-time.After(delay):
			// pass

		case <-timeoutCtx.Done():
			// Format our error based on how we were called.
			if opts.withValidityCheckTimeout == 0 {
				// There was no timeout, just return the error unwrapped.
				return nil, err
			}

			// Otherwise, return the error wrapped in a timeout error.
			return nil, fmt.Errorf("timeout after %s waiting for success: %w", opts.withValidityCheckTimeout, err)
		}
	}
}
