// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// IAMAPIFunc is a factory function for returning an IAM interface,
// useful for supplying mock interfaces for testing IAM.
type IAMAPIFunc func(awsConfig *aws.Config) (IAMClient, error)

// IAMClient represents an iam.Client
type IAMClient interface {
	CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
}

// STSAPIFunc is a factory function for returning a STS interface,
// useful for supplying mock interfaces for testing STS.
type STSAPIFunc func(awsConfig *aws.Config) (STSClient, error)

// STSClient represents an sts.Client
type STSClient interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// IAMClient returns an IAM client.
//
// Supported options: WithAwsConfig, WithIAMAPIFunc, WithIamEndpointResolver.
//
// If WithIAMAPIFunc is supplied, the included function is used as
// the IAM client constructor instead. This can be used for Mocking
// the IAM API.
func (c *CredentialsConfig) IAMClient(ctx context.Context, opt ...Option) (IAMClient, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading options: %w", err)
	}

	cfg := opts.withAwsConfig
	if cfg == nil {
		cfg, err = c.GenerateCredentialChain(ctx, opt...)
		if err != nil {
			return nil, fmt.Errorf("error calling GenerateCredentialChain: %w", err)
		}
	}

	if opts.withIAMAPIFunc != nil {
		return opts.withIAMAPIFunc(cfg)
	}

	var iamOpts []func(*iam.Options)
	if c.IAMEndpointResolver != nil {
		iamOpts = append(iamOpts, iam.WithEndpointResolverV2(c.IAMEndpointResolver))
	}

	return iam.NewFromConfig(*cfg, iamOpts...), nil
}

// STSClient returns a STS client.
//
// Supported options: WithAwsConfig, WithSTSAPIFunc, WithStsEndpointResolver.
//
// If WithSTSAPIFunc is supplied, the included function is used as
// the STS client constructor instead. This can be used for Mocking
// the STS API.
func (c *CredentialsConfig) STSClient(ctx context.Context, opt ...Option) (STSClient, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading options: %w", err)
	}

	cfg := opts.withAwsConfig
	if cfg == nil {
		cfg, err = c.GenerateCredentialChain(ctx, opt...)
		if err != nil {
			return nil, fmt.Errorf("error calling GenerateCredentialChain: %w", err)
		}
	}

	if opts.withSTSAPIFunc != nil {
		return opts.withSTSAPIFunc(cfg)
	}

	var stsOpts []func(*sts.Options)
	if c.STSEndpointResolver != nil {
		stsOpts = append(stsOpts, sts.WithEndpointResolverV2(c.STSEndpointResolver))
	}

	return sts.NewFromConfig(*cfg, stsOpts...), nil
}
