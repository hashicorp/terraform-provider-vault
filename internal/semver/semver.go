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
