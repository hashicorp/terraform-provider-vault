// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package entity

import (
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	RootEntityPath   = "/identity/entity"
	RootEntityIDPath = RootEntityPath + "/id"
	RootAliasPath    = RootEntityPath + "-alias"
	RootAliasIDPath  = RootAliasPath + "/id"
	LookupPath       = "identity/lookup/entity"
)

var ErrEntityNotFound = errors.New("entity not found")

// Entity represents a Vault identity entity
type Entity struct {
	Aliases           []*Alias      `mapstructure:"aliases" json:"aliases,omitempty"`
	CreationTime      string        `mapstructure:"creation_time" json:"creation_time"`
	DirectGroupIds    []interface{} `mapstructure:"direct_group_ids" json:"direct_group_ids,omitempty"`
	Disabled          bool          `mapstructure:"disabled" json:"disabled,omitempty"`
	GroupIds          []interface{} `mapstructure:"group_ids" json:"group_ids,omitempty"`
	ID                string        `mapstructure:"id" json:"id,omitempty"`
	InheritedGroupIds []interface{} `mapstructure:"inherited_group_ids" json:"inherited_group_ids,omitempty"`
	LastUpdateTime    string        `mapstructure:"last_update_time" json:"last_update_time"`
	MergedEntityIds   interface{}   `mapstructure:"merged_entity_ids" json:"merged_entity_ids,omitempty"`
	Metadata          interface{}   `mapstructure:"metadata" json:"metadata,omitempty"`
	MfaSecrets        struct{}      `mapstructure:"mfa_secrets" json:"mfa_secrets"`
	Name              string        `mapstructure:"name" json:"name,omitempty"`
	NamespaceId       string        `mapstructure:"namespace_id" json:"namespace_id,omitempty"`
	Policies          []string      `mapstructure:"policies" json:"policies,omitempty"`
}

// Alias represents a Vault identity entity alias as it is associated to its Entity.
type Alias struct {
	CanonicalId            string                 `mapstructure:"canonical_id" json:"canonical_id,omitempty"`
	CreationTime           string                 `mapstructure:"creation_time" json:"creation_time,omitempty"`
	CustomMetadata         map[string]interface{} `mapstructure:"custom_metadata" json:"custom_metadata,omitempty"`
	ID                     string                 `mapstructure:"id" json:"id,omitempty"`
	LastUpdateTime         string                 `mapstructure:"last_update_time" json:"last_update_time,omitempty"`
	Local                  bool                   `mapstructure:"local" json:"local,omitempty"`
	MergedFromCanonicalIds interface{}            `mapstructure:"merged_from_canonical_ids" json:"merged_from_canonical_ids,omitempty"`
	Metadata               interface{}            `mapstructure:"metadata" json:"metadata,omitempty"`
	MountAccessor          string                 `mapstructure:"mount_accessor" json:"mount_accessor,omitempty"`
	MountPath              string                 `mapstructure:"mount_path" json:"mount_path,omitempty"`
	MountType              string                 `mapstructure:"mount_type" json:"mount_type,omitempty"`
	Name                   string                 `mapstructure:"name" json:"name,omitempty"`
}

// FindAliasParams
type FindAliasParams struct {
	// Name to constrain the search to.
	Name string
	// MountAccessor to constrain the search to.
	MountAccessor string
}

// FindAliases for the given FindAliasParams.
func FindAliases(client *api.Client, params *FindAliasParams) ([]*Alias, error) {
	resp, err := client.Logical().List(RootEntityIDPath)
	if resp == nil || err != nil {
		return nil, err
	}

	entityIDs, ok := resp.Data["keys"]
	if !ok || entityIDs == nil {
		return nil, nil
	}

	var result []*Alias

	for _, id := range entityIDs.([]interface{}) {
		config, err := client.Logical().Read(JoinEntityID(id.(string)))
		if err != nil {
			return nil, err
		}

		if config == nil {
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

// JoinAliasID to the root alias ID path.
func JoinAliasID(id string) string {
	return fmt.Sprintf("%s/%s", RootAliasIDPath, id)
}

// JoinEntityID to the root entity ID path.
func JoinEntityID(id string) string {
	return fmt.Sprintf("%s/%s", RootEntityIDPath, id)
}

// LookupEntityAlias for the given FindAliasParams.
func LookupEntityAlias(client *api.Client, params *FindAliasParams) (*Alias, error) {
	if params.Name == "" {
		return nil, fmt.Errorf("alias name cannot be empty params=%#v", params)
	}

	if params.MountAccessor == "" {
		return nil, fmt.Errorf("alias mount_accessor cannot be empty params=%#v", params)
	}

	resp, err := client.Logical().Write(LookupPath, map[string]interface{}{
		"alias_name":           params.Name,
		"alias_mount_accessor": params.MountAccessor,
	})
	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, nil
	}

	var a Alias
	if aliases, ok := resp.Data["aliases"]; ok && aliases != nil {
		for _, alias := range aliases.([]interface{}) {
			v := alias.(map[string]interface{})
			if err := mapstructure.Decode(v, &a); err != nil {
				return nil, err
			}

			if a.Name == params.Name && a.MountAccessor == params.MountAccessor {
				return &a, nil
			}
		}
	}

	return nil, nil
}

func ReadEntity(client *api.Client, path string, retry bool) (*api.Secret, error) {
	log.Printf("[DEBUG] Reading Entity from %q", path)

	var err error
	if retry {
		client, err = client.Clone()
		if err != nil {
			return nil, fmt.Errorf("error cloning client: %w", err)
		}
		util.SetupCCCRetryClient(client, provider.MaxHTTPRetriesCCC)
	}

	resp, err := client.Logical().Read(path)
	if err != nil {
		return resp, fmt.Errorf("failed reading %q", path)
	}

	if resp == nil {
		return nil, fmt.Errorf("%w: %q", ErrEntityNotFound, path)
	}

	return resp, nil
}
