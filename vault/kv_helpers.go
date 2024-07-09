// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"io"
	"log"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
)

func versionedSecret(requestedVersion int, path string, client *api.Client) (*api.Secret, error) {
	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return nil, err
	}

	var versionParam map[string]string

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "data")
		if err != nil {
			return nil, err
		}

		if requestedVersion > 0 {
			versionParam = map[string]string{
				"version": fmt.Sprintf("%d", requestedVersion),
			}
		}
	}

	secret, err := kvReadRequest(client, path, versionParam)
	if err != nil {
		return nil, err
	}

	if v2 && secret != nil {
		// v2 secret can be deleted
		if metadata, ok := secret.Data["metadata"].(map[string]interface{}); ok && metadata != nil {
			if _, deleted := metadata["deletion_time"]; deleted {
				return nil, nil
			}
		}
		// This is a v2, grab the data field
		if data, ok := secret.Data["data"]; ok && data != nil {
			if dataMap, ok := data.(map[string]interface{}); ok {
				secret.Data = dataMap
			}
		}
	}

	return secret, nil
}

func kvReadRequest(client *api.Client, path string, params map[string]string) (*api.Secret, error) {
	r := client.NewRequest("GET", "/v1/"+path)
	for k, v := range params {
		r.Params.Set(k, v)
	}
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
		secret, parseErr := api.ParseSecret(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, err
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return api.ParseSecret(resp.Body)
}

func kvListRequest(client *api.Client, path string) ([]interface{}, error) {
	log.Printf("[DEBUG] Listing secrets at %s from Vault", path)
	resp, err := client.Logical().List(path)
	if err != nil {
		return nil, fmt.Errorf("error listing from Vault at path %q, err=%s", path, err)
	}

	if resp == nil {
		return nil, fmt.Errorf("no secrets found at %q", path)
	}

	// Return key names if they are present in response
	if keyNameList, ok := resp.Data["keys"]; ok && keyNameList != nil {
		keyNames, ok := keyNameList.([]interface{})
		if !ok {
			return nil, fmt.Errorf("keys are incorrectly formatted in response from Vault")
		}
		return keyNames, nil
	}

	return nil, fmt.Errorf("no keys present in response from Vault")
}

func kvPreflightVersionRequest(client *api.Client, path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

func isKVv2(path string, client *api.Client) (string, bool, error) {
	mountPath, version, err := kvPreflightVersionRequest(client, path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

func addPrefixToVKVPath(p, mountPath, apiPrefix string) string {
	switch {
	case p == mountPath, p == strings.TrimSuffix(mountPath, "/"):
		return path.Join(mountPath, apiPrefix)
	default:
		p = strings.TrimPrefix(p, mountPath)
		return path.Join(mountPath, apiPrefix, p)
	}
}
