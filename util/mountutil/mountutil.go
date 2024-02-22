package mountutil

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/vault/api"
)

// Error strings that are returned by the Vault API.
const (
	ErrVaultSecretMountNotFound = "No secret engine mount at"
	ErrVaultAuthMountNotFound   = "No auth engine at"
)

// Error strings that are used internally by TFVP
var (
	// ErrMountNotFound is used to signal to resources that a secret or auth
	// mount does not exist and should be removed from state.
	ErrMountNotFound = errors.New("mount not found")
)

// GetMount will fetch the secret mount at the given path.
func GetMount(ctx context.Context, client *api.Client, path string) (*api.MountOutput, error) {
	mount, err := client.Sys().GetMountWithContext(ctx, path)
	// Hardcoding the error string check is not ideal, but Vault does not
	// return 404 in this case
	if err != nil && strings.Contains(err.Error(), ErrVaultSecretMountNotFound) || mount == nil {
		return nil, fmt.Errorf("%w: %s", ErrMountNotFound, err)
	}
	if err != nil {
		return nil, fmt.Errorf("error reading from Vault: %s", err)
	}
	return mount, nil
}

// NormalizeMountPath to be in a form valid for accessing values from api.MountOutput
func NormalizeMountPath(path string) string {
	return TrimSlashes(path) + consts.PathDelim
}

// TrimSlashes from path.
func TrimSlashes(path string) string {
	return strings.Trim(path, consts.PathDelim)
}

// CheckMountEnabledWithContext in Vault
func CheckMountEnabledWithContext(ctx context.Context, client *api.Client, path string) (bool, error) {
	_, err := GetMount(ctx, client, path)
	if errors.Is(err, ErrMountNotFound) {
		return false, err
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

// CheckMountEnabled in Vault
func CheckMountEnabled(client *api.Client, path string) (bool, error) {
	return CheckMountEnabledWithContext(context.Background(), client, path)
}
