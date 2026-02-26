// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	awserr "github.com/aws/smithy-go"
)

var (
	_ awserr.APIError         = (*MockAWSErr)(nil)
	_ aws.CredentialsProvider = (*MockCredentialsProvider)(nil)
	_ IAMClient               = (*MockIAM)(nil)
	_ STSClient               = (*MockSTS)(nil)
)

// MockAWSErr is used to mock API error types for tests
type MockAWSErr struct {
	Code    string
	Message string
	Fault   awserr.ErrorFault
}

// ErrorCode returns the error code
func (e *MockAWSErr) ErrorCode() string {
	return e.Code
}

// Error returns the error message
func (e *MockAWSErr) Error() string {
	return e.Message
}

// ErrorFault returns one of the following values:
// FaultClient, FaultServer, FaultUnknown
func (e *MockAWSErr) ErrorFault() awserr.ErrorFault {
	return e.Fault
}

// ErrorMessage returns the error message
func (e *MockAWSErr) ErrorMessage() string {
	return e.Message
}

// MockAWSThrottleErr returns a mocked aws error that mimics a throttling exception.
func MockAWSThrottleErr() error {
	return &MockAWSErr{
		Code:    "ThrottlingException",
		Message: "Throttling Exception",
		Fault:   awserr.FaultServer,
	}
}

// MockOptionErr provides a mock option error for use with testing.
func MockOptionErr(withErr error) Option {
	return func(_ *options) error {
		return withErr
	}
}

// MockCredentialsProvider provides a way to mock the aws.CredentialsProvider
type MockCredentialsProvider struct {
	aws.CredentialsProvider

	aws.Credentials
	error
}

// MockCredentialsProviderOption is a function for setting
// the various fields on a MockCredentialsProvider object.
type MockCredentialsProviderOption func(m *MockCredentialsProvider)

// WithCredentials sets the output for the Retrieve method.
func WithCredentials(o aws.Credentials) MockCredentialsProviderOption {
	return func(m *MockCredentialsProvider) {
		m.Credentials = o
	}
}

// WithCredentials sets the output for the Retrieve method.
func WithError(o error) MockCredentialsProviderOption {
	return func(m *MockCredentialsProvider) {
		m.error = o
	}
}

// NewMockCredentialsProvider provides a factory function to
// use with the WithCredentialsProvider option.
func NewMockCredentialsProvider(opts ...MockCredentialsProviderOption) aws.CredentialsProvider {
	m := new(MockCredentialsProvider)
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *MockCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if m.error != nil {
		return aws.Credentials{}, m.error
	}

	return m.Credentials, nil
}

// MockIAM provides a way to mock the AWS IAM API.
type MockIAM struct {
	IAMClient

	CreateAccessKeyOutput *iam.CreateAccessKeyOutput
	CreateAccessKeyError  error
	DeleteAccessKeyError  error
	ListAccessKeysOutput  *iam.ListAccessKeysOutput
	ListAccessKeysError   error
	GetUserOutput         *iam.GetUserOutput
	GetUserError          error
}

// MockIAMOption is a function for setting the various fields on a MockIAM
// object.
type MockIAMOption func(m *MockIAM) error

// WithCreateAccessKeyOutput sets the output for the CreateAccessKey method.
func WithCreateAccessKeyOutput(o *iam.CreateAccessKeyOutput) MockIAMOption {
	return func(m *MockIAM) error {
		m.CreateAccessKeyOutput = o
		return nil
	}
}

// WithCreateAccessKeyError sets the error output for the CreateAccessKey
// method.
func WithCreateAccessKeyError(e error) MockIAMOption {
	return func(m *MockIAM) error {
		m.CreateAccessKeyError = e
		return nil
	}
}

// WithDeleteAccessKeyError sets the error output for the DeleteAccessKey
// method.
func WithDeleteAccessKeyError(e error) MockIAMOption {
	return func(m *MockIAM) error {
		m.DeleteAccessKeyError = e
		return nil
	}
}

// WithListAccessKeysOutput sets the output for the ListAccessKeys method.
func WithListAccessKeysOutput(o *iam.ListAccessKeysOutput) MockIAMOption {
	return func(m *MockIAM) error {
		m.ListAccessKeysOutput = o
		return nil
	}
}

// WithListAccessKeysError sets the error output for the ListAccessKeys method.
func WithListAccessKeysError(e error) MockIAMOption {
	return func(m *MockIAM) error {
		m.ListAccessKeysError = e
		return nil
	}
}

// WithGetUserOutput sets the output for the GetUser method.
func WithGetUserOutput(o *iam.GetUserOutput) MockIAMOption {
	return func(m *MockIAM) error {
		m.GetUserOutput = o
		return nil
	}
}

// WithGetUserError sets the error output for the GetUser method.
func WithGetUserError(e error) MockIAMOption {
	return func(m *MockIAM) error {
		m.GetUserError = e
		return nil
	}
}

// NewMockIAM provides a factory function to use with the WithIAMAPIFunc
// option.
func NewMockIAM(opts ...MockIAMOption) IAMAPIFunc {
	return func(_ *aws.Config) (IAMClient, error) {
		m := new(MockIAM)
		for _, opt := range opts {
			if err := opt(m); err != nil {
				return nil, err
			}
		}

		return m, nil
	}
}

func (m *MockIAM) CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	if m.CreateAccessKeyError != nil {
		return nil, m.CreateAccessKeyError
	}

	return m.CreateAccessKeyOutput, nil
}

func (m *MockIAM) DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	return &iam.DeleteAccessKeyOutput{}, m.DeleteAccessKeyError
}

func (m *MockIAM) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if m.ListAccessKeysError != nil {
		return nil, m.ListAccessKeysError
	}

	return m.ListAccessKeysOutput, nil
}

func (m *MockIAM) GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	if m.GetUserError != nil {
		return nil, m.GetUserError
	}

	return m.GetUserOutput, nil
}

// MockSTS provides a way to mock the AWS STS API.
type MockSTS struct {
	STSClient

	GetCallerIdentityOutput *sts.GetCallerIdentityOutput
	GetCallerIdentityError  error

	AssumeRoleOutput *sts.AssumeRoleOutput
	AssumeRoleError  error
}

// MockSTSOption is a function for setting the various fields on a MockSTS
// object.
type MockSTSOption func(m *MockSTS) error

// WithAssumeRoleOutput sets the output for the AssumeRole method.
func WithAssumeRoleOutput(o *sts.AssumeRoleOutput) MockSTSOption {
	return func(m *MockSTS) error {
		m.AssumeRoleOutput = o
		return nil
	}
}

// WithAssumeRoleError sets the error output for the AssumeRole method.
func WithAssumeRoleError(e error) MockSTSOption {
	return func(m *MockSTS) error {
		m.AssumeRoleError = e
		return nil
	}
}

// WithGetCallerIdentityOutput sets the output for the GetCallerIdentity
// method.
func WithGetCallerIdentityOutput(o *sts.GetCallerIdentityOutput) MockSTSOption {
	return func(m *MockSTS) error {
		m.GetCallerIdentityOutput = o
		return nil
	}
}

// WithGetCallerIdentityError sets the error output for the GetCallerIdentity
// method.
func WithGetCallerIdentityError(e error) MockSTSOption {
	return func(m *MockSTS) error {
		m.GetCallerIdentityError = e
		return nil
	}
}

// NewMockSTS provides a factory function to use with the WithSTSAPIFunc
// option.
//
// If withGetCallerIdentityError is supplied, calls to GetCallerIdentity will
// return the supplied error. Otherwise, a basic mock API output is returned.
func NewMockSTS(opts ...MockSTSOption) STSAPIFunc {
	return func(_ *aws.Config) (STSClient, error) {
		m := new(MockSTS)
		for _, opt := range opts {
			if err := opt(m); err != nil {
				return nil, err
			}
		}

		return m, nil
	}
}

func (m *MockSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityError != nil {
		return nil, m.GetCallerIdentityError
	}

	return m.GetCallerIdentityOutput, nil
}

func (m *MockSTS) AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.AssumeRoleError != nil {
		return nil, m.AssumeRoleError
	}

	return m.AssumeRoleOutput, nil
}
