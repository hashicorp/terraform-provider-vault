package semver

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func getTargetVaultVersion(client *api.Client) (string, error) {
	// This endpoint only returns data upon an HTTP request
	// Reads using the Client do not return data
	path := "/v1/sys/seal-status"
	r := client.NewRequest("GET", path)

	resp, err := client.RawRequest(r)
	if err != nil {
		return "", fmt.Errorf("error performing GET operation at %s, err=%w", path, err)
	}

	if resp == nil {
		return "", fmt.Errorf("expected response data, got nil response")
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}

	var version string
	if v, ok := data[consts.FieldVersion]; ok {
		version = v.(string)
	} else {
		return "", fmt.Errorf("key %q not found in response", consts.FieldVersion)
	}

	return version, nil
}

func SemanticVersionComparison(minVersionString string, client *api.Client) (bool, string, error) {
	currentVersionString, err := getTargetVaultVersion(client)
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

	if comparison {
		return true, currentVersionString, nil
	} else {
		return false, currentVersionString, nil
	}
}
