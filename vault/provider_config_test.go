// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	frameworkschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkv2schema "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/terraform-provider-vault/internal/provider/fwprovider"
)

func TestProviderConfigListCardinalityMatches(t *testing.T) {
	_, primary, err := ProtoV5ProviderServerFactory(context.Background())
	require.NoError(t, err)

	framework := fwprovider.New(primary)
	var response frameworkprovider.SchemaResponse
	framework.Schema(context.Background(), frameworkprovider.SchemaRequest{}, &response)
	require.False(t, response.Diagnostics.HasError())

	for name, sdkv2Field := range primary.SchemaProvider().Schema {
		if sdkv2Field.Type != sdkv2schema.TypeList {
			continue
		}

		t.Run(name, func(t *testing.T) {
			block, ok := response.Schema.Blocks[name]
			require.True(t, ok, "Plugin Framework schema has no matching block")
			listBlock := getListNestedBlock(t, block)

			if sdkv2Field.MaxItems == 0 {
				require.False(t, validateListBlockSize(t, name, listBlock, 2).Diagnostics.HasError())
				return
			}

			require.False(t,
				validateListBlockSize(t, name, listBlock, sdkv2Field.MaxItems).Diagnostics.HasError())
			require.True(t,
				validateListBlockSize(t, name, listBlock, sdkv2Field.MaxItems+1).Diagnostics.HasError())
		})
	}
}

func getListNestedBlock(t *testing.T, block frameworkschema.Block) *frameworkschema.ListNestedBlock {
	t.Helper()

	switch block := block.(type) {
	case frameworkschema.ListNestedBlock:
		return &block
	case *frameworkschema.ListNestedBlock:
		return block
	default:
		t.Fatalf("expected ListNestedBlock, got %T", block)
		return nil
	}
}

func validateListBlockSize(
	t *testing.T,
	name string,
	block *frameworkschema.ListNestedBlock,
	size int,
) validator.ListResponse {
	t.Helper()

	objectType, ok := block.NestedObject.Type().(types.ObjectType)
	require.True(t, ok)

	elements := make([]attr.Value, size)
	for i := range elements {
		elements[i] = types.ObjectNull(objectType.AttributeTypes())
	}

	request := validator.ListRequest{
		Path:        path.Root(name),
		ConfigValue: types.ListValueMust(objectType, elements),
	}
	var response validator.ListResponse
	for _, listValidator := range block.Validators {
		listValidator.ValidateList(context.Background(), request, &response)
	}
	return response
}
