// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"

	providerversion "github.com/hashicorp/terraform-provider-vault/version"
)

// stubPrimary stands in for the SDKv2 provider; Metadata does not consult it.
type stubPrimary struct{}

func (stubPrimary) Meta() interface{} { return nil }

func TestMetadata(t *testing.T) {
	p := New(stubPrimary{})

	resp := &provider.MetadataResponse{}
	p.Metadata(context.Background(), provider.MetadataRequest{}, resp)

	if resp.TypeName != "vault" {
		t.Errorf("TypeName = %q, want %q", resp.TypeName, "vault")
	}

	if want := providerversion.ProviderVersion(); resp.Version != want {
		t.Errorf("Version = %q, want %q", resp.Version, want)
	}

	if resp.Version == "" {
		t.Error("Version is empty, the provider version was not reported")
	}
}
