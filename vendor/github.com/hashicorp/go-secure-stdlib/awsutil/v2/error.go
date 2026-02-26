// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	multierror "github.com/hashicorp/go-multierror"
)

var ErrUpstreamRateLimited = errors.New("upstream rate limited")

// CheckAWSError will examine an error and convert to a logical error if
// appropriate. If no appropriate error is found, return nil
func CheckAWSError(err error) error {
	retryErr := retry.ThrottleErrorCode{
		Codes: retry.DefaultThrottleErrorCodes,
	}
	if retryErr.IsErrorThrottle(err).Bool() {
		return ErrUpstreamRateLimited
	}
	return nil
}

// AppendAWSError checks if the given error is a known AWS error we modify,
// and if so then returns a go-multierror, appending the original and the
// AWS error.
// If the error is not an AWS error, or not an error we wish to modify, then
// return the original error.
func AppendAWSError(err error) error {
	if awserr := CheckAWSError(err); awserr != nil {
		err = multierror.Append(err, awserr)
	}
	return err
}
