package vault

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hashicorp/vault/api"
	"golang.org/x/mod/semver"
)

func getTargetVaultVersion(client *api.Client) (string, error) {
	path := "/v1/sys/seal-status"
	r := client.NewRequest("GET", path)

	resp, err := client.RawRequest(r)
	if err != nil {
		return "", fmt.Errorf("error performing GET at %s, err=%w", path, err)
	}

	if resp == nil {
		return "", fmt.Errorf("expected a response body, got nil response")
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

	version := data["version"].(string)

	return version, nil
}

func semVerComparison(minVersion string, client *api.Client) (bool, error) {
	currentVersion, err := getTargetVaultVersion(client)
	if err != nil {
		return false, err
	}

	currentVersionInput := fmt.Sprintf("v%s", currentVersion)
	minVersionInput := fmt.Sprintf("v%s", minVersion)

	comparison := semver.Compare(currentVersionInput, minVersionInput)

	if comparison == 0 || comparison == 1 {
		return true, nil
	} else {
		return false, nil
	}
}
