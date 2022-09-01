package semver

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func getTargetVaultVersion(ctx context.Context, client *api.Client) (string, error) {
	resp, err := client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return "", err
	}

	if resp == nil {
		return "", fmt.Errorf("expected response data, got nil response")
	}

	if resp.Version == "" {
		return "", fmt.Errorf("key %q not found in response", consts.FieldVersion)
	}

	return resp.Version, nil
}

// GreaterThanOrEqual receives a context, a Vault API client
// and a minimum version that the Vault server version
// should be above.
//
// It uses the go-version package
// to perform a semantic version comparison, and
// returns:
//    - a boolean describing whether the Vault
//      server version was above the minimum version
//    - the current Vault server version as a string
//    - errors captured during operation, if any
//
// This function can be used to perform semantic version comparisons
// to conditionally enable features, or to resolve any diffs in the TF
// state based on the Vault version.
func GreaterThanOrEqual(ctx context.Context, client *api.Client, minVersionString string) (bool, string, error) {
	currentVersionString, err := getTargetVaultVersion(ctx, client)
	if err != nil {
		return false, "", err
	}

	minVersion, err := version.NewVersion(minVersionString)
	if err != nil {
		return false, "", err
	}

	currentVersion, err := version.NewVersion(currentVersionString)
	if err != nil {
		return false, "", err
	}

	comparison := currentVersion.GreaterThanOrEqual(minVersion)

	return comparison, currentVersionString, nil
}
