package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func Test_handleCIDRField(t *testing.T) {
	tests := []struct {
		name    string
		want    interface{}
		s       map[string]*schema.Schema
		raw     map[string]interface{}
		k       string
		resp    *api.Secret
		wantErr bool
	}{
		{
			name: "basic",
			s: map[string]*schema.Schema{
				TokenFieldBoundCIDRs: {
					Type: schema.TypeSet,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
					Optional: true,
				},
			},
			raw: map[string]interface{}{
				TokenFieldBoundCIDRs: []interface{}{
					"10.1.1.1/32",
					"10.2.1.1",
					"10.2.0.0/24",
					"::1/128",
				},
			},
			k: TokenFieldBoundCIDRs,
			resp: &api.Secret{
				Data: map[string]interface{}{
					TokenFieldBoundCIDRs: []interface{}{
						"10.1.1.1",
						"10.2.1.1",
						"10.2.0.0/24",
						"::1",
					},
				},
			},
			want: []string{
				"10.1.1.1/32",
				"10.2.1.1",
				"10.2.0.0/24",
				"::1/128",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, tt.s, tt.raw)
			got, err := handleCIDRField(d, tt.k, tt.resp)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleCIDRField() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("handleCIDRField() got = %v, want %v", got, tt.want)
			}
		})
	}
}
