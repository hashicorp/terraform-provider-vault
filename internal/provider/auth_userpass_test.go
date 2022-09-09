package provider

import (
	"io/ioutil"
	"path"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func Test_setupUserpassAuthParams(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]interface{}
		env     map[string]string
		wantErr bool
		want    map[string]interface{}
	}{
		{
			name: "password-file",
			params: map[string]interface{}{
				consts.FieldUsername:     "bob",
				consts.FieldPasswordFile: "",
			},
			want: map[string]interface{}{
				consts.FieldUsername: "bob",
				consts.FieldPassword: "foobar",
			},
			wantErr: false,
		},
		{
			name: "error-no-username",
			params: map[string]interface{}{
				"canary": "baz",
			},
			want: map[string]interface{}{
				"canary": "baz",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filename string
			if _, ok := tt.params[consts.FieldPasswordFile]; ok {
				filename = path.Join(t.TempDir(), "password")
				tt.params[consts.FieldPasswordFile] = filename
			}

			if filename != "" {
				if err := ioutil.WriteFile(
					filename, []byte(tt.want[consts.FieldPassword].(string)), 0o440); err != nil {
					t.Fatal(err)
				}
			}

			if err := setupUserpassAuthParams(tt.params); (err != nil) != tt.wantErr {
				t.Errorf("setupUserpassAuthParams() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.want, tt.params) {
				t.Errorf("setupUserpassAuthParams() want = %v, actual %v", tt.want, tt.params)
			}
		})
	}
}
