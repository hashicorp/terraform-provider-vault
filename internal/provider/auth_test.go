// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// expectedRegisteredAuthLogin value should be modified when adding
// registering/de-registering AuthLogin resources.
const expectedRegisteredAuthLogin = 12

type authLoginTest struct {
	name               string
	authLogin          AuthLogin
	handler            *testLoginHandler
	want               *api.Secret
	expectReqCount     int
	skipCheckReqParams bool
	expectReqParams    []map[string]interface{}
	expectReqPaths     []string
	wantErr            bool
	expectErr          error
	skipFunc           func(t *testing.T)
	tls                bool
	preLoginFunc       func(t *testing.T)
	token              string
}

type authLoginInitTest struct {
	name         string
	authField    string
	raw          map[string]interface{}
	wantErr      bool
	envVars      map[string]string
	expectMount  string
	expectParams map[string]interface{}
	expectErr    error
}

type testLoginHandler struct {
	requestCount  int
	paths         []string
	params        []map[string]interface{}
	excludeParams []string
	handlerFunc   func(t *testLoginHandler, w http.ResponseWriter, req *http.Request)
}

func (t *testLoginHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		t.requestCount++

		t.paths = append(t.paths, req.URL.Path)

		switch req.Method {
		case http.MethodPut, http.MethodGet:
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		b, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var params map[string]interface{}
		if len(b) > 0 {
			if err := json.Unmarshal(b, &params); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		for _, p := range t.excludeParams {
			delete(params, p)
		}

		if len(params) > 0 {
			t.params = append(t.params, params)
		}

		t.handlerFunc(t, w, req)
	}
}

func testAuthLogin(t *testing.T, tt authLoginTest) {
	t.Helper()

	if tt.skipFunc != nil {
		tt.skipFunc(t)
	}

	if tt.preLoginFunc != nil {
		tt.preLoginFunc(t)
	}

	var config *api.Config
	var ln net.Listener
	if tt.tls {
		config, ln = testutil.TestHTTPSServer(t, tt.handler.handler())
	} else {
		config, ln = testutil.TestHTTPServer(t, tt.handler.handler())
	}
	defer ln.Close()

	c, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}

	// clear the vault token to avoid issues where it is picked up from one of its
	// default sources.
	c.ClearToken()

	if tt.token != "" {
		c.SetToken(tt.token)
	}

	got, err := tt.authLogin.Login(c)
	if (err != nil) != tt.wantErr {
		t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
		return
	}

	if err != nil && tt.expectErr != nil {
		if !reflect.DeepEqual(tt.expectErr, err) {
			t.Errorf("Login() expected error %#v, actual %#v", tt.expectErr, err)
		}
	}

	if tt.expectReqCount != tt.handler.requestCount {
		t.Errorf("Login() expected %d requests, actual %d", tt.expectReqCount, tt.handler.requestCount)
	}

	if !reflect.DeepEqual(tt.expectReqPaths, tt.handler.paths) {
		t.Errorf("Login() request paths do not match expected %#v, actual %#v", tt.expectReqPaths,
			tt.handler.paths)
	}

	if !tt.skipCheckReqParams && !reflect.DeepEqual(tt.expectReqParams, tt.handler.params) {
		t.Errorf("Login() request params do not match expected %#v, actual %#v", tt.expectReqParams,
			tt.handler.params)
	}

	if !reflect.DeepEqual(got, tt.want) {
		t.Errorf("Login() got = %#v, want %#v", got, tt.want)
	}
}

// TestMustAddAuthLoginSchema_registered is only meant to validate that all
// expected AuthLogin(s) are registered. The expected count of all registered
// entries should be modified when registering/de-registering AuthLogin
// resources.
func TestMustAddAuthLoginSchema_registered(t *testing.T) {
	tests := []struct {
		name string
		s    map[string]*schema.Schema
	}{
		{
			name: "checkRegistered",
			s:    make(map[string]*schema.Schema),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MustAddAuthLoginSchema(tt.s)
			actual := len(tt.s)
			if expectedRegisteredAuthLogin != actual {
				t.Errorf("expected %d schema entries, actual %d", expectedRegisteredAuthLogin, actual)
			}
		})
	}
}

func TestGetAuthLogin_registered(t *testing.T) {
	registeredAuthLogins := globalAuthLoginRegistry.Values()
	actualRegistered := len(registeredAuthLogins)
	if expectedRegisteredAuthLogin != actualRegistered {
		t.Fatalf("expected %d registered AuthLogin, actual %d", expectedRegisteredAuthLogin, actualRegistered)
	}

	for _, entry := range registeredAuthLogins {
		entry := entry
		t.Run(t.Name()+"-"+entry.Field(), func(t *testing.T) {
			t.Parallel()
			sr := entry.LoginSchema().Elem.(*schema.Resource)

			rawData := []map[string]interface{}{
				make(map[string]interface{}),
			}
			for f, s := range sr.Schema {
				switch s.Type {
				case schema.TypeString:
					rawData[0][f] = t.Name()
				case schema.TypeMap:
					rawData[0][f] = map[string]interface{}{
						t.Name(): "baz",
					}
				case schema.TypeBool:
					continue
				default:
					t.Fatalf("unsupported schema type %s for test", s.Type)
				}
			}

			rootProvider := NewProvider(nil, nil)
			pr := &schema.Resource{
				Schema: rootProvider.Schema,
			}
			d := pr.TestResourceData()
			if err := d.Set(entry.Field(), rawData); err != nil {
				t.Error(err)
			}

			_, err := GetAuthLogin(d)
			if err != nil {
				t.Errorf("GetAuthLogin() error = %v, wantErr false", err)
			}
		})
	}
}

func assertAuthLoginEqual(t *testing.T, expected, actual AuthLogin) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("AuthLogin instances not equal, expected %#v, actual %#v", expected, actual)
	}
}

func assertAuthLoginInit(t *testing.T, tt authLoginInitTest, s map[string]*schema.Schema, l AuthLogin) {
	t.Helper()
	for k, v := range tt.envVars {
		t.Setenv(k, v)
	}

	d := schema.TestResourceDataRaw(t, s, tt.raw)
	actual, err := l.Init(d, tt.authField)
	if (err != nil) != tt.wantErr {
		t.Fatalf("Init() error = %v, wantErr %v", err, tt.wantErr)
	}

	if !reflect.DeepEqual(tt.expectErr, err) {
		t.Errorf("Init() expected error %#v, actual %#v", tt.expectErr, err)
	}

	if !reflect.DeepEqual(tt.expectParams, l.Params()) {
		t.Errorf("Init() expected params %#v, actual %#v", tt.expectParams, l.Params())
	}

	if err != nil {
		assertAuthLoginEqual(t, nil, actual)
	} else {
		assertAuthLoginEqual(t, l, actual)
	}
}

func TestAuthLoginCommon_Namespace(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
		want   string
		exists bool
	}{
		{
			name: "root-ns",
			params: map[string]interface{}{
				consts.FieldUseRootNamespace: true,
			},
			want:   "",
			exists: true,
		},
		{
			name: "other-ns",
			params: map[string]interface{}{
				consts.FieldNamespace: "ns1",
			},
			want:   "ns1",
			exists: true,
		},
		{
			name: "empty-ns",
			params: map[string]interface{}{
				consts.FieldNamespace: "",
			},
			want:   "",
			exists: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginCommon{
				params:      tt.params,
				initialized: true,
			}
			got, exists := l.Namespace()
			if got != tt.want {
				t.Errorf("Namespace() got = %v, want %v", got, tt.want)
			}
			if exists != tt.exists {
				t.Errorf("Namespace() exists = %v, want %v", exists, tt.exists)
			}
		})
	}
}

func TestAuthLoginCommon_setDefaultFields(t *testing.T) {
	tests := []struct {
		name         string
		params       map[string]interface{}
		expectParams map[string]interface{}
		setEnv       map[string]string
		defaults     authDefaults
	}{
		{
			name: "default-unset-and-env-unset",
			params: map[string]interface{}{
				"foo": "",
			},
			defaults: authDefaults{
				{
					field:      "foo",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_FOO"},
					defaultVal: "",
				},
			},
			expectParams: map[string]interface{}{
				"foo": "",
			},
		},
		{
			name: "default-set-and-env-unset",
			params: map[string]interface{}{
				"foo": "",
			},
			defaults: authDefaults{
				{
					field:      "foo",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_FOO"},
					defaultVal: "bar",
				},
			},
			expectParams: map[string]interface{}{
				"foo": "bar",
			},
		},
		{
			name: "default-set-and-env-set",
			params: map[string]interface{}{
				"foo": "",
			},
			defaults: authDefaults{
				{
					field:      "foo",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_FOO"},
					defaultVal: "bar",
				},
			},
			// env vars should override authDefault.defaultVal
			setEnv: map[string]string{
				"TEST_TERRAFORM_VAULT_PROVIDER_FOO": "baz",
			},
			expectParams: map[string]interface{}{
				"foo": "baz",
			},
		},
		{
			name: "default-unset-and-env-set",
			params: map[string]interface{}{
				"foo": "",
			},
			defaults: authDefaults{
				{
					field:      "foo",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_FOO"},
					defaultVal: "",
				},
			},
			// env vars should override authDefault.defaultVal
			setEnv: map[string]string{
				"TEST_TERRAFORM_VAULT_PROVIDER_FOO": "baz",
			},
			expectParams: map[string]interface{}{
				"foo": "baz",
			},
		},
		{
			name: "multiple-params-default-set-and-env-set",
			params: map[string]interface{}{
				"foo": "",
				"dog": "",
			},
			defaults: authDefaults{
				{
					field:      "foo",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_FOO"},
					defaultVal: "bar",
				},
				{
					field:      "dog",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_DOG"},
					defaultVal: "bark",
				},
			},
			// env vars should override authDefault.defaultVal
			setEnv: map[string]string{
				"TEST_TERRAFORM_VAULT_PROVIDER_FOO": "baz",
				"TEST_TERRAFORM_VAULT_PROVIDER_DOG": "woof",
			},
			expectParams: map[string]interface{}{
				"foo": "baz",
				"dog": "woof",
			},
		},
		{
			name: "multiple-params-mixed-set-and-unset",
			params: map[string]interface{}{
				"foo": "",
				"dog": "",
			},
			defaults: authDefaults{
				{
					field:      "foo",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_FOO"},
					defaultVal: "bar",
				},
				{
					field:      "dog",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_DOG"},
					defaultVal: "bark",
				},
			},
			// env vars should override authDefault.defaultVal
			setEnv: map[string]string{
				"TEST_TERRAFORM_VAULT_PROVIDER_FOO": "baz",
			},
			expectParams: map[string]interface{}{
				"foo": "baz",
				"dog": "bark",
			},
		},
		{
			name: "multiple-env",
			params: map[string]interface{}{
				"foo": "",
			},
			defaults: authDefaults{
				{
					field:      "foo",
					envVars:    []string{"TEST_TERRAFORM_VAULT_PROVIDER_FOO", "TEST_TERRAFORM_VAULT_PROVIDER_QUX"},
					defaultVal: "",
				},
			},
			setEnv: map[string]string{
				"TEST_TERRAFORM_VAULT_PROVIDER_QUX": "qux",
			},
			expectParams: map[string]interface{}{
				"foo": "qux",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv != nil {
				for k, v := range tt.setEnv {
					t.Setenv(k, v)
					t.Cleanup(func() {
						err := os.Unsetenv(k)
						if err != nil {
							t.Fatalf("could not unset env, err: %v", err)
						}
					},
					)
				}
			}
			l := &AuthLoginCommon{
				params:      tt.params,
				initialized: true,
			}

			rootProvider := NewProvider(nil, nil)
			pr := &schema.Resource{
				Schema: rootProvider.Schema,
			}
			d := pr.TestResourceData()

			err := l.setDefaultFields(d, tt.defaults, tt.params)
			if err != nil {
				t.Errorf("setDefaultFields() err: %v", err)
			}

			if !reflect.DeepEqual(tt.expectParams, l.Params()) {
				t.Errorf("setDefaultFields() expected params %#v, actual %#v", tt.expectParams, l.Params())
			}
		})
	}
}
