package provider

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
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

func TestAuthLoginUserpass_LoginPath(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "basic",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					authField: "",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldUsername: "bob",
					},
				},
			},
			want: "auth/foo/login/bob",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginUserpass{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testLoginHandler struct {
	requestCount int
	paths        []string
	params       []map[string]interface{}
}

func (t *testLoginHandler) userpassHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		t.requestCount++

		t.paths = append(t.paths, req.URL.Path)

		if req.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var params map[string]interface{}
		if err := json.Unmarshal(b, &params); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		t.params = append(t.params, params)

		parts := strings.Split(req.URL.Path, "/")
		m, err := json.Marshal(
			&api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"username": parts[len(parts)-1],
					},
				},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(m)
	}
}

func TestAuthLoginUserpass_Login(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}
	tests := []struct {
		name            string
		fields          fields
		handler         *testLoginHandler
		want            *api.Secret
		expectReqCount  int
		expectReqParams []map[string]interface{}
		expectReqPaths  []string
		wantErr         bool
	}{
		{
			name: "basic",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					authField: "baz",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldUsername: "bob",
						consts.FieldPassword: "baz",
					},
				},
			},
			handler:        &testLoginHandler{},
			expectReqCount: 1,
			expectReqPaths: []string{
				"/v1/auth/foo/login/bob",
			},
			expectReqParams: []map[string]interface{}{
				{
					consts.FieldUsername: "bob",
					consts.FieldPassword: "baz",
				},
			},
			want: &api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"username": "bob",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "error-no-username",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					authField: "baz",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldPassword: "baz",
					},
				},
			},
			handler:         &testLoginHandler{},
			expectReqCount:  0,
			expectReqPaths:  nil,
			expectReqParams: nil,
			want:            nil,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.handler

			config, ln := testutil.TestHTTPServer(t, r.userpassHandler())
			defer ln.Close()

			config.Address = fmt.Sprintf("http://%s", ln.Addr())
			c, err := api.NewClient(config)
			if err != nil {
				t.Fatal(err)
			}

			l := &AuthLoginUserpass{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}

			got, err := l.Login(c)
			if (err != nil) != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expectReqCount != tt.handler.requestCount {
				t.Errorf("Login() expected %d requests, actual %d", tt.expectReqCount, tt.handler.requestCount)
			}

			if !reflect.DeepEqual(tt.expectReqPaths, tt.handler.paths) {
				t.Errorf("Login() request paths do not match expected %#v, actual %#v", tt.expectReqPaths,
					tt.handler.paths)
			}

			if !reflect.DeepEqual(tt.expectReqParams, tt.handler.params) {
				t.Errorf("Login() request params do not match expected %#v, actual %#v", tt.expectReqParams,
					tt.handler.params)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Login() got = %v, want %v", got, tt.want)
			}
		})
	}
}
