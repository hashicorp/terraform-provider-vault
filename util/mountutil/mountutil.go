// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mountutil

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// Error strings that are returned by the Vault API.
const (
	VaultSecretMountNotFoundErrMsg = "No secret engine mount at"
	VaultAuthMountNotFoundErrMsg   = "No auth engine at"
)

// Error strings that are used internally by TFVP
var (
	// ErrMountNotFound is used to signal to resources that a secret or auth
	// mount does not exist and should be removed from state.
	ErrMountNotFound = errors.New("mount not found")
)

// GetMount will fetch the secret mount at the given path.
func GetMount(ctx context.Context, client *api.Client, path string) (*api.MountOutput, error) {
	if resp, err := client.Sys().GetMountWithContext(ctx, path); err != nil {
		return nil, err
	} else if resp == nil {
		return nil, ErrMountNotFound
	} else {
		return resp, nil
	}
}

// GetAuthMount will fetch the auth mount at the given path.
func GetAuthMount(ctx context.Context, client *api.Client, path string) (*api.MountOutput, error) {
	if resp, err := client.Sys().GetAuthWithContext(ctx, path); err != nil {
		return nil, err
	} else if resp == nil {
		return nil, ErrMountNotFound
	} else {
		return resp, nil
	}
}

// NormalizeMountPath to be in a form valid for accessing values from api.MountOutput
func NormalizeMountPath(path string) string {
	return TrimSlashes(path) + consts.PathDelim
}

// TrimSlashes from path.
func TrimSlashes(path string) string {
	return strings.Trim(path, consts.PathDelim)
}

// CheckMountEnabled in Vault
func CheckMountEnabled(ctx context.Context, client *api.Client, path string) (bool, error) {
	if _, err := GetMount(ctx, client, path); err != nil {
		if IsMountNotFoundError(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// IsMountNotFoundError returns true if error is a mount not found error.
func IsMountNotFoundError(err error) bool {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) && respErr != nil {
		if respErr.StatusCode == http.StatusNotFound {
			return true
		}
		if respErr.StatusCode == http.StatusBadRequest {
			for _, e := range respErr.Errors {
				if strings.Contains(e, VaultSecretMountNotFoundErrMsg) {
					return true
				}
				if strings.Contains(e, VaultAuthMountNotFoundErrMsg) {
					return true
				}
			}
		}
	}

	if errors.Is(err, ErrMountNotFound) {
		return true
	}

	return false
}
