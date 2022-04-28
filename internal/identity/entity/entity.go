package entity

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

const (
	IdentityEntityAliasPath = "/identity/entity-alias"
	IdentityEntityPath      = "/identity/entity"
)

// GetAliasesByName
func GetAliasesByName(client *api.Client, name string) ([]*api.Secret, error) {
	resp, err := client.Logical().List(IdentityEntityAliasPath + "/id")
	if resp == nil || err != nil {
		return nil, err
	}

	var result []*api.Secret
	for _, id := range resp.Data["keys"].([]interface{}) {
		config, err := client.Logical().Read(AliasIDPath(id.(string)))
		if err != nil || config == nil {
			continue
		}

		if config.Data["name"].(string) == name {
			result = append(result, config)
		}
	}

	return result, err
}

// GetAliasesByMountAccessor
func GetAliasesByMountAccessor(client *api.Client, accessor string) ([]map[string]interface{}, error) {
	resp, err := client.Logical().List(IdentityEntityPath + "/id")
	if resp == nil || err != nil {
		return nil, err
	}

	result := make([]map[string]interface{}, 0)
	for _, id := range resp.Data["keys"].([]interface{}) {
		config, err := client.Logical().Read(IDPath(id.(string)))
		if err != nil || config == nil {
			continue
		}

		if aliases, ok := config.Data["aliases"]; ok {
			for _, v := range aliases.([]interface{}) {
				alias := v.(map[string]interface{})
				if alias["mount_accessor"].(string) == accessor {
					result = append(result, alias)
				}
			}
		}
	}

	return result, err
}

// AliasIDPath
func AliasIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", IdentityEntityAliasPath, id)
}

// IDPath
func IDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", IdentityEntityPath, id)
}
