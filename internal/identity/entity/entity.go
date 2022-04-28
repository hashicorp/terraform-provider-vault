package entity

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

const (
	IdentityEntityAliasPath = "/identity/entity-alias"
	IdentityEntityPath      = "/identity/entity"
)

type Alias struct {
	CanonicalId            string                 `mapstructure:"canonical_id"`
	CreationTime           string                 `mapstructure:"creation_time"`
	CustomMetadata         map[string]interface{} `mapstructure:"custom_metadata"`
	ID                     string                 `mapstructure:"id"`
	LastUpdateTime         string                 `mapstructure:"last_update_time"`
	Local                  bool                   `mapstructure:"local"`
	MergedFromCanonicalIds interface{}            `mapstructure:"merged_from_canonical_ids"`
	Metadata               interface{}            `mapstructure:"metadata"`
	MountAccessor          string                 `mapstructure:"mount_accessor"`
	MountPath              string                 `mapstructure:"mount_path"`
	MountType              string                 `mapstructure:"mount_type"`
	Name                   string                 `mapstructure:"name"`
}

// FindAliasParams
type FindAliasParams struct {
	Name          string
	MountAccessor string
}

func FindAliases(client *api.Client, params *FindAliasParams) ([]*Alias, error) {
	resp, err := client.Logical().List(IdentityEntityPath + "/id")
	if resp == nil || err != nil {
		return nil, err
	}

	var result []*Alias
	for _, id := range resp.Data["keys"].([]interface{}) {
		config, err := client.Logical().Read(IDPath(id.(string)))
		if err != nil || config == nil {
			continue
		}

		if aliases, ok := config.Data["aliases"]; ok {
			for _, v := range aliases.([]interface{}) {
				var a Alias
				if err := mapstructure.Decode(v, &a); err != nil {
					return nil, err
				}

				if params.Name != "" && a.Name != params.Name {
					continue
				}

				if params.MountAccessor != "" && a.MountAccessor != params.MountAccessor {
					continue
				}

				result = append(result, &a)
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
