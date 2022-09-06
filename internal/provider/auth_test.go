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
			name: "username-from-env",
			params: map[string]interface{}{
				consts.FieldPassword: "foobar",
			},
			env: map[string]string{
				consts.EnvVarUsername: "bob",
			},
			want: map[string]interface{}{
				consts.FieldUsername: "bob",
				consts.FieldPassword: "foobar",
			},
			wantErr: false,
		},
		{
			name: "password-from-env",
			params: map[string]interface{}{
				consts.FieldUsername: "bob",
			},
			env: map[string]string{
				consts.EnvVarPassword: "foobar",
			},
			want: map[string]interface{}{
				consts.FieldUsername: "bob",
				consts.FieldPassword: "foobar",
			},
			wantErr: false,
		},
		{
			name: "password-file-from-env",
			params: map[string]interface{}{
				consts.FieldUsername: "bob",
			},
			env: map[string]string{
				// setup in testrun
				consts.EnvVarPasswordFile: "",
			},
			want: map[string]interface{}{
				consts.FieldUsername: "bob",
				consts.FieldPassword: "foobar",
			},
			wantErr: false,
		},
		{
			name: "password-file-from-params",
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
			if tt.env != nil {
				if _, ok := tt.env[consts.EnvVarPasswordFile]; ok {
					filename = path.Join(t.TempDir(), "password")
					tt.env[consts.EnvVarPasswordFile] = filename
				}
			}

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

			if err := setupUserpassAuthParams(tt.params, tt.env); (err != nil) != tt.wantErr {
				t.Errorf("setupUserpassAuthParams() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.want, tt.params) {
				t.Errorf("setupUserpassAuthParams() want = %v, actual %v", tt.want, tt.params)
			}
		})
	}
}
