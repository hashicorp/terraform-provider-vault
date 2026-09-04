// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// dnsProviderPairSchema returns the minimal schema subset needed by
// dnsProviderPairValidator (dns_provider_name + dns_provider_type only).
func dnsProviderPairSchema() schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldDnsProviderName: schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
			},
			consts.FieldDnsProviderType: schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(""),
			},
		},
	}
}

// makeDNSPairConfig constructs a tfsdk.Config for the two DNS provider fields.
func makeDNSPairConfig(t *testing.T, name, providerType string) tfsdk.Config {
	t.Helper()
	s := dnsProviderPairSchema()
	raw := tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			consts.FieldDnsProviderName: tftypes.String,
			consts.FieldDnsProviderType: tftypes.String,
		},
	}, map[string]tftypes.Value{
		consts.FieldDnsProviderName: tftypes.NewValue(tftypes.String, name),
		consts.FieldDnsProviderType: tftypes.NewValue(tftypes.String, providerType),
	})
	return tfsdk.Config{Raw: raw, Schema: s}
}

func TestDNSProviderPairValidator(t *testing.T) {
	cases := []struct {
		name         string
		providerName string
		providerType string
		wantErr      bool
		errAttr      string // which attribute the error should be on
	}{
		{
			name:         "both empty — valid (DNS not used)",
			providerName: "",
			providerType: "",
			wantErr:      false,
		},
		{
			name:         "both set — valid",
			providerName: "my-provider",
			providerType: "aws-route53",
			wantErr:      false,
		},
		{
			name:         "name set but type missing — invalid",
			providerName: "my-provider",
			providerType: "",
			wantErr:      true,
			errAttr:      consts.FieldDnsProviderType,
		},
		{
			name:         "type set but name missing — invalid",
			providerName: "",
			providerType: "azure-dns",
			wantErr:      true,
			errAttr:      consts.FieldDnsProviderName,
		},
	}

	v := dnsProviderPairValidator{}
	ctx := context.Background()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := resource.ValidateConfigRequest{
				Config: makeDNSPairConfig(t, tc.providerName, tc.providerType),
			}
			resp := &resource.ValidateConfigResponse{}

			v.ValidateResource(ctx, req, resp)

			if tc.wantErr {
				if !resp.Diagnostics.HasError() {
					t.Fatalf("expected validation error, got none")
				}
				if tc.errAttr != "" {
					found := false
					for _, d := range resp.Diagnostics.Errors() {
						if d.Detail() != "" {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error diagnostic, diagnostics were: %v", resp.Diagnostics)
					}
				}
			} else {
				if resp.Diagnostics.HasError() {
					t.Fatalf("unexpected validation error(s): %v", resp.Diagnostics)
				}
			}
		})
	}
}

func TestDNSProviderPairValidator_Description(t *testing.T) {
	v := dnsProviderPairValidator{}
	ctx := context.Background()

	desc := v.Description(ctx)
	if desc == "" {
		t.Error("Description() should return a non-empty string")
	}

	mdDesc := v.MarkdownDescription(ctx)
	if mdDesc == "" {
		t.Error("MarkdownDescription() should return a non-empty string")
	}
}
