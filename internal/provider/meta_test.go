// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	vault_consts "github.com/hashicorp/vault/sdk/helper/consts"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestProviderMeta_GetNSClient(t *testing.T) {
	rootClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		client       *api.Client
		resourceData *schema.ResourceData
		ns           string
		expectNs     string
		wantErr      bool
		expectErr    error
		calls        int
	}{
		{
			name:         "no-resource-data",
			client:       &api.Client{},
			resourceData: nil,
			wantErr:      true,
			expectErr:    errors.New("provider ResourceData not set, init with NewProviderMeta()"),
		},
		{
			name:   "basic-no-root-ns",
			client: rootClient,
			resourceData: schema.TestResourceDataRaw(t,
				map[string]*schema.Schema{
					"namespace": {
						Type:     schema.TypeString,
						Required: true,
					},
				},
				map[string]interface{}{},
			),
			ns:       "foo",
			expectNs: "foo",
		},
		{
			name:   "basic-root-ns",
			client: rootClient,
			resourceData: schema.TestResourceDataRaw(t,
				map[string]*schema.Schema{
					"namespace": {
						Type:     schema.TypeString,
						Required: true,
					},
				},
				map[string]interface{}{
					"namespace": "bar",
				},
			),
			ns:       "foo",
			expectNs: "bar/foo",
			calls:    5,
		},
		{
			name:   "basic-root-ns-trimmed",
			client: rootClient,
			resourceData: schema.TestResourceDataRaw(t,
				map[string]*schema.Schema{
					"namespace": {
						Type:     schema.TypeString,
						Required: true,
					},
				},
				map[string]interface{}{
					"namespace": "bar",
				},
			),
			ns:       "/foo/",
			expectNs: "bar/foo",
			calls:    5,
		},
	}

	assertClientCache := func(t *testing.T, p *ProviderMeta, expectedCache map[string]*api.Client) {
		t.Helper()

		if !reflect.DeepEqual(expectedCache, p.clientCache) {
			t.Errorf("GetNSClient() expected Client cache %#v, actual %#v", expectedCache, p.clientCache)
		}
	}

	assertClientNs := func(t *testing.T, c *api.Client, expectNs string) {
		actualNs := c.Headers().Get(vault_consts.NamespaceHeaderName)
		if actualNs != expectNs {
			t.Errorf("GetNSClient() got ns = %v, want %v", actualNs, expectNs)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ProviderMeta{
				client:       tt.client,
				resourceData: tt.resourceData,
			}
			got, err := p.GetNSClient(tt.ns)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetNSClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GetNSClient() expected an err, actual %#v", err)
				}

				if !reflect.DeepEqual(err, tt.expectErr) {
					t.Errorf("GetNSClient() expected err %#v, actual %#v", tt.expectErr, err)
				}

				var expectedCache map[string]*api.Client
				assertClientCache(t, p, expectedCache)

				return
			}

			assertClientCache(t, p, map[string]*api.Client{
				tt.expectNs: got,
			})
			assertClientNs(t, got, tt.expectNs)

			// test cache locking
			if tt.calls > 0 {
				var wg sync.WaitGroup
				p.clientCache = nil
				wg.Add(tt.calls)
				for i := 0; i < tt.calls; i++ {
					go func() {
						defer wg.Done()
						got, err := p.GetNSClient(tt.ns)
						if err != nil {
							t.Error(err)
							return
						}

						assertClientCache(t, p, map[string]*api.Client{
							tt.expectNs: got,
						})
						assertClientNs(t, got, tt.expectNs)
					}()
				}
				wg.Wait()
			}
		})
	}
}

func TestGetClient(t *testing.T) {
	rootClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// testing schema.ResourceDiff is not covered here
	// since its field members are private.

	rscData := func(t *testing.T, set bool, ns string) interface{} {
		i := schema.TestResourceDataRaw(t,
			map[string]*schema.Schema{
				consts.FieldNamespace: {
					Type:     schema.TypeString,
					Required: true,
				},
			},
			map[string]interface{}{},
		)
		if set {
			if err := i.Set(consts.FieldNamespace, ns); err != nil {
				t.Fatal(err)
			}
		}
		return i
	}

	instanceState := func(_ *testing.T, set bool, ns string) interface{} {
		i := &terraform.InstanceState{
			Attributes: map[string]string{},
		}
		if set {
			i.Attributes[consts.FieldNamespace] = ns
		}
		return i
	}

	tests := []struct {
		name      string
		meta      interface{}
		ifcNS     string
		envNS     string
		want      string
		wantErr   bool
		expectErr error
		setAttr   bool
		ifaceFunc func(t *testing.T, set bool, ns string) interface{}
	}{
		{
			name:  "string",
			ifcNS: "ns1-string",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: func(t *testing.T, set bool, ns string) interface{} {
				return "ns1-string"
			},
			want:    "ns1-string",
			setAttr: true,
		},
		{
			name:  "rsc-data",
			ifcNS: "ns1-rsc-data",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: rscData,
			want:      "ns1-rsc-data",
			setAttr:   true,
		},
		{
			name:  "inst-state",
			ifcNS: "ns1-inst-state",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			want:      "ns1-inst-state",
			setAttr:   true,
			ifaceFunc: instanceState,
		},
		{
			name: "import-env",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: instanceState,
			envNS:     "ns1-import-env",
			want:      "ns1-import-env",
			setAttr:   false,
		},
		{
			name: "ignore-env-rsc-data",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: rscData,
			ifcNS:     "ns1",
			envNS:     "ns1-import-env",
			want:      "ns1",
			setAttr:   true,
		},
		{
			name: "ignore-env-inst-state",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: instanceState,
			ifcNS:     "ns1",
			envNS:     "ns1-import-env",
			want:      "ns1",
			setAttr:   true,
		},
		{
			name: "error-unsupported-type",
			meta: &ProviderMeta{
				client:       rootClient,
				resourceData: nil,
			},
			ifaceFunc: func(t *testing.T, set bool, ns string) interface{} {
				return nil
			},
			wantErr:   true,
			expectErr: fmt.Errorf("GetClient() called with unsupported type <nil>"),
		},
		{
			name:      "error-not-provider-meta",
			meta:      nil,
			wantErr:   true,
			expectErr: fmt.Errorf("meta argument must be a *provider.ProviderMeta, not <nil>"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.meta != nil {
				m := tt.meta.(*ProviderMeta)
				m.resourceData = schema.TestResourceDataRaw(t,
					map[string]*schema.Schema{
						consts.FieldNamespace: {
							Type:     schema.TypeString,
							Required: true,
						},
					},
					map[string]interface{}{},
				)
				tt.meta = m
			}

			var i interface{}
			if tt.ifaceFunc != nil {
				i = tt.ifaceFunc(t, tt.setAttr, tt.ifcNS)
			}

			// set ns in env
			if tt.envNS != "" {
				if err := os.Setenv(consts.EnvVarVaultNamespaceImport, tt.envNS); err != nil {
					t.Fatal(err)
				}
				defer os.Unsetenv(consts.EnvVarVaultNamespaceImport)
			}

			got, err := GetClient(i, tt.meta)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetClient() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(err, tt.expectErr) {
					t.Errorf("GetClient() expected err %#v, actual %#v", tt.expectErr, err)
				}
				return
			}

			actual := got.Headers().Get(vault_consts.NamespaceHeaderName)
			if !reflect.DeepEqual(actual, tt.want) {
				t.Errorf("GetClient() got = %v, want %v", actual, tt.want)
			}
		})
	}
}

func TestIsAPISupported(t *testing.T) {
	testutil.SkipTestAcc(t)
	testutil.TestAccPreCheck(t)

	rootClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatalf("error initializing root client, err=%s", err)
	}

	VaultVersion10, err := version.NewVersion("1.10.0")
	if err != nil {
		t.Fatal(err)
	}

	VaultVersion11, err := version.NewVersion("1.11.0")
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name       string
		minVersion *version.Version
		expected   bool
		meta       interface{}
	}{
		{
			name:       "supported-greater-than",
			minVersion: version.Must(version.NewSemver("1.8.0")),
			expected:   true,
			meta: &ProviderMeta{
				client:       rootClient,
				vaultVersion: VaultVersion11,
			},
		},
		{
			name:       "supported-less-than",
			minVersion: version.Must(version.NewSemver("1.12.0")),
			expected:   false,
			meta: &ProviderMeta{
				client:       rootClient,
				vaultVersion: VaultVersion11,
			},
		},
		{
			name:       "supported-equal",
			minVersion: version.Must(version.NewSemver("1.10.0")),
			expected:   true,
			meta: &ProviderMeta{
				client:       rootClient,
				vaultVersion: VaultVersion10,
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.meta != nil {
				m := tt.meta.(*ProviderMeta)
				m.resourceData = schema.TestResourceDataRaw(t,
					map[string]*schema.Schema{
						consts.FieldNamespace: {
							Type:     schema.TypeString,
							Required: true,
						},
						consts.FieldVaultVersionOverride: {
							Type: schema.TypeString,
						},
						consts.FieldSkipGetVaultVersion: {
							Type: schema.TypeBool,
						},
					},
					map[string]interface{}{},
				)
				tt.meta = m
			}

			isTFVersionGreater := tt.meta.(*ProviderMeta).IsAPISupported(tt.minVersion)

			if isTFVersionGreater != tt.expected {
				t.Errorf("IsAPISupported() got = %v, want %v", isTFVersionGreater, tt.expected)
			}
		})
	}
}

func TestIsEnterpriseSupported(t *testing.T) {
	testutil.SkipTestAcc(t)
	testutil.TestAccPreCheck(t)

	rootClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatalf("error initializing root client, err=%s", err)
	}

	VaultVersion10, err := version.NewVersion("1.10.0")
	if err != nil {
		t.Fatal(err)
	}

	VaultVersion11HSM, err := version.NewVersion("1.11.0+ent.hsm")
	if err != nil {
		t.Fatal(err)
	}

	VaultVersion12, err := version.NewVersion("1.12.0+ent")
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name     string
		expected bool
		meta     interface{}
	}{
		{
			name:     "not-enterprise",
			expected: false,
			meta: &ProviderMeta{
				client:       rootClient,
				vaultVersion: VaultVersion10,
			},
		},
		{
			name:     "enterprise-hsm",
			expected: true,
			meta: &ProviderMeta{
				client:       rootClient,
				vaultVersion: VaultVersion11HSM,
			},
		},
		{
			name:     "enterprise",
			expected: true,
			meta: &ProviderMeta{
				client:       rootClient,
				vaultVersion: VaultVersion12,
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.meta != nil {
				m := tt.meta.(*ProviderMeta)
				m.resourceData = schema.TestResourceDataRaw(t,
					map[string]*schema.Schema{
						consts.FieldNamespace: {
							Type:     schema.TypeString,
							Required: true,
						},
						consts.FieldVaultVersionOverride: {
							Type: schema.TypeString,
						},
						consts.FieldSkipGetVaultVersion: {
							Type: schema.TypeBool,
						},
					},
					map[string]interface{}{},
				)
				tt.meta = m
			}

			isEnterprise := tt.meta.(*ProviderMeta).IsEnterpriseSupported()

			if isEnterprise != tt.expected {
				t.Errorf("IsEnterpriseSupported() got = %v, want %v", isEnterprise, tt.expected)
			}
		})
	}
}

func TestNewProviderMeta(t *testing.T) {
	testutil.SkipTestAcc(t)
	testutil.SkipTestAccEnt(t)
	testutil.TestAccPreCheck(t)

	nsPrefix := acctest.RandomWithPrefix("ns") + "-"

	defaultUser := "alice"
	defaultPassword := "f00bazB1ff"

	rootProvider := NewProvider(nil, nil)
	pr := &schema.Resource{
		Schema: rootProvider.Schema,
	}

	tests := []struct {
		name                      string
		d                         *schema.ResourceData
		data                      map[string]interface{}
		env                       map[string]string
		wantNamespace             string
		tokenNamespace            string
		authLoginNamespace        string
		wantErr                   bool
		checkSetSetTokenNamespace bool
		wantNamespaceFromToken    string
	}{
		{
			name:    "invalid-nil-ResourceData",
			d:       nil,
			wantErr: true,
		},
		{
			// expect provider namespace set.
			name: "with-provider-ns-only",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldNamespace:           nsPrefix + "prov",
				consts.FieldSkipGetVaultVersion: true,
			},
			wantNamespace: nsPrefix + "prov",
			wantErr:       false,
		},
		{
			// expect token namespace set
			name: "with-token-ns-only",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
			},
			tokenNamespace: nsPrefix + "token-ns-only",
			wantNamespace:  nsPrefix + "token-ns-only",
			wantErr:        false,
		},
		{
			// expect provider namespace set.
			name: "with-provider-ns-and-token-ns",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldNamespace:           nsPrefix + "prov-and-token",
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
			},
			tokenNamespace: nsPrefix + "token-ns",
			wantNamespace:  nsPrefix + "prov-and-token",
			wantErr:        false,
		},
		{
			// expect auth_login namespace set.
			name: "with-auth-login-and-ns",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
				consts.FieldAuthLoginUserpass: []map[string]interface{}{
					{
						consts.FieldNamespace: nsPrefix + "auth-ns",
						consts.FieldMount:     consts.MountTypeUserpass,
						consts.FieldUsername:  defaultUser,
						consts.FieldPassword:  defaultPassword,
					},
				},
			},
			authLoginNamespace: nsPrefix + "auth-ns",
			wantNamespace:      nsPrefix + "auth-ns",
			wantErr:            false,
		},
		{
			// expect provider namespace set.
			name: "with-provider-ns-and-auth-login-with-ns",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldNamespace:           nsPrefix + "prov-ns-prov-ns",
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
				consts.FieldAuthLoginUserpass: []map[string]interface{}{
					{
						consts.FieldNamespace: nsPrefix + "auth-ns-auth-ns",
						consts.FieldMount:     consts.MountTypeUserpass,
						consts.FieldUsername:  defaultUser,
						consts.FieldPassword:  defaultPassword,
					},
				},
			},
			authLoginNamespace: nsPrefix + "auth-ns-auth-ns",
			wantNamespace:      nsPrefix + "prov-ns-prov-ns",
			wantErr:            false,
		},
		{
			// expect token based namespace to be ignored.
			name: "set-namespace-from-token-false",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
			},
			env: map[string]string{
				"VAULT_SET_NAMESPACE_FROM_TOKEN": "false",
			},
			tokenNamespace:            nsPrefix + "set-ns-from-token-auth-false-ignored",
			wantNamespace:             nsPrefix + "set-ns-from-token-auth-false-ignored",
			checkSetSetTokenNamespace: true,
			wantNamespaceFromToken:    "",
			wantErr:                   false,
		},
		{
			// expect token based namespace to be ignored.
			name: "set-namespace-from-token-true",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
				consts.FieldAuthLoginUserpass: []map[string]interface{}{
					{
						consts.FieldNamespace: nsPrefix + "set-ns-from-token-auth-true",
						consts.FieldMount:     consts.MountTypeUserpass,
						consts.FieldUsername:  defaultUser,
						consts.FieldPassword:  defaultPassword,
					},
				},
			},
			env: map[string]string{
				"VAULT_SET_NAMESPACE_FROM_TOKEN": "true",
			},
			authLoginNamespace:        nsPrefix + "set-ns-from-token-auth-true",
			wantNamespace:             nsPrefix + "set-ns-from-token-auth-true",
			checkSetSetTokenNamespace: true,
			wantNamespaceFromToken:    nsPrefix + "set-ns-from-token-auth-true",
			wantErr:                   false,
		},
		{
			// expect token namespace to be ignored
			name: "with-token-ns-only-override-env-false",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
			},
			env: map[string]string{
				"VAULT_SET_NAMESPACE_FROM_TOKEN": "false",
			},
			tokenNamespace:            nsPrefix + "token-ns-only",
			wantNamespace:             nsPrefix + "token-ns-only",
			checkSetSetTokenNamespace: true,
			wantNamespaceFromToken:    "",
			wantErr:                   false,
		},
	}

	createNamespace := func(t *testing.T, client *api.Client, ns string) {
		t.Helper()
		t.Cleanup(func() {
			err := backoff.Retry(func() error {
				_, err := client.Logical().Delete(consts.SysNamespaceRoot + ns)
				return err
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Microsecond*500), 10))
			if err != nil {
				t.Fatalf("failed to delete namespace %q, err=%s", ns, err)
			}
		})
		if _, err := client.Logical().Write(
			consts.SysNamespaceRoot+ns, nil); err != nil {
			t.Fatalf("failed to create namespace, err=%s", err)
		}
	}

	config := api.DefaultConfig()
	config.CloneToken = true
	client, err := api.NewClient(config)
	if err != nil {
		t.Fatalf("failed to create Vault client, err=%s", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// we cannot run these in Parallel
			// some of the test cases will set env vars that will cause flakiness
			if tt.env != nil {
				for k, v := range tt.env {
					if err := os.Setenv(k, v); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						os.Unsetenv(k)
					})
				}
			}

			if tt.authLoginNamespace != "" {
				createNamespace(t, client, tt.authLoginNamespace)
				options := &api.EnableAuthOptions{
					Type:        consts.MountTypeUserpass,
					Description: "test auth_userpass",
					Local:       true,
				}

				clone, err := client.Clone()
				if err != nil {
					t.Fatalf("failed to clone Vault client, err=%s", err)
				}

				clone.SetNamespace(tt.authLoginNamespace)
				if err := clone.Sys().EnableAuthWithOptions(consts.MountTypeUserpass, options); err != nil {
					t.Fatalf("failed to enable auth, err=%s", err)
				}

				if _, err := clone.Logical().Write("auth/userpass/users/alice",
					map[string]interface{}{
						consts.FieldPassword:      defaultPassword,
						consts.FieldTokenPolicies: []string{"admin", "default"},
					}); err != nil {
					t.Fatalf("failed to create user, err=%s", err)
				}
			}

			if tt.tokenNamespace != "" {
				if tt.data == nil {
					t.Fatal("test data cannot be nil when tokenNamespace set")
				}

				createNamespace(t, client, tt.tokenNamespace)
				clone, err := client.Clone()
				if err != nil {
					t.Fatalf("failed to clone Vault client, err=%s", err)
				}

				// in order not to trigger the min TTL warning we can add some time to the min.
				tokenTTL := TokenTTLMinRecommended + time.Second*10
				clone.SetNamespace(tt.tokenNamespace)
				resp, err := clone.Auth().Token().Create(&api.TokenCreateRequest{
					TTL: tokenTTL.String(),
				})
				if err != nil {
					t.Fatalf("failed to create Vault token, err=%s", err)
				}
				tt.data[consts.FieldToken] = resp.Auth.ClientToken
			}

			for k, v := range tt.data {
				if err := tt.d.Set(k, v); err != nil {
					t.Fatalf("failed to set resource data, key=%s, value=%#v", k, v)
				}
			}

			got, err := NewProviderMeta(tt.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProviderMeta() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				if got != nil {
					t.Errorf("NewProviderMeta() got = %v, want nil", got)
				}
				return
			}

			p, ok := got.(*ProviderMeta)
			if !ok {
				t.Fatalf("invalid type got %T, expected %T", got, &ProviderMeta{})
			}

			client, err := p.GetClient()
			if err != nil {
				t.Fatalf("got unexpected error %s", err)
			}

			if !reflect.DeepEqual(client.Namespace(), tt.wantNamespace) {
				t.Errorf("NewProviderMeta() got ns = %v, want ns %v", p.client.Namespace(), tt.wantNamespace)
			}

			if tt.checkSetSetTokenNamespace && tt.wantNamespaceFromToken != tt.d.Get(consts.FieldNamespace).(string) {
				t.Errorf("NewProviderMeta() got ns = %q, want ns %q", tt.d.Get(consts.FieldNamespace).(string), tt.wantNamespaceFromToken)
			}

			if client.Token() == "" {
				t.Errorf("NewProviderMeta() got empty Client token")
			}
		})
	}
}

func TestNewProviderMeta_Cert(t *testing.T) {
	testutil.SkipTestAcc(t)
	testutil.SkipTestAccEnt(t)
	testutil.TestAccPreCheck(t)

	nsPrefix := acctest.RandomWithPrefix("ns") + "-"

	defaultUser := "alice"
	defaultPassword := "f00bazB1ff"

	rootProvider := NewProvider(nil, nil)
	pr := &schema.Resource{
		Schema: rootProvider.Schema,
	}

	tests := []struct {
		name               string
		d                  *schema.ResourceData
		data               map[string]interface{}
		wantNamespace      string
		tokenNamespace     string
		authLoginNamespace string
		wantErr            bool
	}{
		{
			name:    "invalid-nil-ResourceData",
			d:       nil,
			wantErr: true,
		},
		{
			// expect provider namespace set.
			name: "with-provider-ns-only",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldNamespace:           nsPrefix + "prov",
				consts.FieldSkipGetVaultVersion: true,
			},
			wantNamespace: nsPrefix + "prov",
			wantErr:       false,
		},
		{
			// expect token namespace set
			name: "with-token-ns-only",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
			},
			tokenNamespace: nsPrefix + "token-ns-only",
			wantNamespace:  nsPrefix + "token-ns-only",
			wantErr:        false,
		},
		{
			// expect provider namespace set.
			name: "with-provider-ns-and-token-ns",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldNamespace:           nsPrefix + "prov-and-token",
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
			},
			tokenNamespace: nsPrefix + "token-ns",
			wantNamespace:  nsPrefix + "prov-and-token",
			wantErr:        false,
		},
		{
			// expect auth_login namespace set.
			name: "with-auth-login-and-ns",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
				consts.FieldAuthLoginUserpass: []map[string]interface{}{
					{
						consts.FieldNamespace: nsPrefix + "auth-ns",
						consts.FieldMount:     consts.MountTypeUserpass,
						consts.FieldUsername:  defaultUser,
						consts.FieldPassword:  defaultPassword,
					},
				},
			},
			authLoginNamespace: nsPrefix + "auth-ns",
			wantNamespace:      nsPrefix + "auth-ns",
			wantErr:            false,
		},
		{
			// expect provider namespace set.
			name: "with-provider-ns-and-auth-login-with-ns",
			d:    pr.TestResourceData(),
			data: map[string]interface{}{
				consts.FieldNamespace:           nsPrefix + "prov-ns-auth-ns",
				consts.FieldSkipGetVaultVersion: true,
				consts.FieldSkipChildToken:      true,
				consts.FieldAuthLoginUserpass: []map[string]interface{}{
					{
						consts.FieldNamespace: nsPrefix + "auth-ns-prov-ns",
						consts.FieldMount:     consts.MountTypeUserpass,
						consts.FieldUsername:  defaultUser,
						consts.FieldPassword:  defaultPassword,
					},
				},
			},
			authLoginNamespace: nsPrefix + "auth-ns-prov-ns",
			wantNamespace:      nsPrefix + "prov-ns-auth-ns",
			wantErr:            false,
		},
	}

	createNamespace := func(t *testing.T, client *api.Client, ns string) {
		t.Helper()
		t.Cleanup(func() {
			err := backoff.Retry(func() error {
				_, err := client.Logical().Delete(consts.SysNamespaceRoot + ns)
				return err
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Microsecond*500), 10))
			if err != nil {
				t.Fatalf("failed to delete namespace %q, err=%s", ns, err)
			}
		})
		if _, err := client.Logical().Write(
			consts.SysNamespaceRoot+ns, nil); err != nil {
			t.Fatalf("failed to create namespace, err=%s", err)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := api.DefaultConfig()
			config.CloneToken = true
			client, err := api.NewClient(config)
			if err != nil {
				t.Fatalf("failed to create Vault client, err=%s", err)
			}

			if tt.authLoginNamespace != "" {
				createNamespace(t, client, tt.authLoginNamespace)
				options := &api.EnableAuthOptions{
					Type:        consts.MountTypeUserpass,
					Description: "test auth_userpass",
					Local:       true,
				}

				clone, err := client.Clone()
				if err != nil {
					t.Fatalf("failed to clone Vault client, err=%s", err)
				}

				clone.SetNamespace(tt.authLoginNamespace)
				if err := clone.Sys().EnableAuthWithOptions(consts.MountTypeUserpass, options); err != nil {
					t.Fatalf("failed to enable auth, err=%s", err)
				}

				if _, err := clone.Logical().Write("auth/userpass/users/alice",
					map[string]interface{}{
						consts.FieldPassword:      defaultPassword,
						consts.FieldTokenPolicies: []string{"admin", "default"},
					}); err != nil {
					t.Fatalf("failed to create user, err=%s", err)
				}
			}

			if tt.tokenNamespace != "" {
				if tt.data == nil {
					t.Fatal("test data cannot be nil when tokenNamespace set")
				}

				createNamespace(t, client, tt.tokenNamespace)
				clone, err := client.Clone()
				if err != nil {
					t.Fatalf("failed to clone Vault client, err=%s", err)
				}

				// in order not to trigger the min TTL warning we can add some time to the min.
				tokenTTL := TokenTTLMinRecommended + time.Second*10
				clone.SetNamespace(tt.tokenNamespace)
				resp, err := clone.Auth().Token().Create(&api.TokenCreateRequest{
					TTL: tokenTTL.String(),
				})
				if err != nil {
					t.Fatalf("failed to create Vault token, err=%s", err)
				}
				tt.data[consts.FieldToken] = resp.Auth.ClientToken
			}

			for k, v := range tt.data {
				if err := tt.d.Set(k, v); err != nil {
					t.Fatalf("failed to set resource data, key=%s, value=%#v", k, v)
				}
			}

			got, err := NewProviderMeta(tt.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProviderMeta() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				if got != nil {
					t.Errorf("NewProviderMeta() got = %v, want nil", got)
				}
				return
			}

			p, ok := got.(*ProviderMeta)
			if !ok {
				t.Fatalf("invalid type got %T, expected %T", got, &ProviderMeta{})
			}

			pClient, err := p.GetClient()
			if err != nil {
				t.Fatalf("got unexpected error %s", err)
			}

			if !reflect.DeepEqual(pClient.Namespace(), tt.wantNamespace) {
				t.Errorf("NewProviderMeta() got ns = %v, want ns %v", p.client.Namespace(), tt.wantNamespace)
			}

			if client.Token() == "" {
				t.Errorf("NewProviderMeta() got empty Client token")
			}
		})
	}
}

func TestGetResourceDataBool(t *testing.T) {
	testutil.TestAccPreCheck(t)
	testutil.SkipTestAcc(t)
	rootProvider := NewProvider(nil, nil)

	//pr := &schema.Resource{
	//	Schema: rootProvider.Schema,
	//}

	tests := []struct {
		name     string
		field    string
		data     map[string]interface{}
		dv       bool
		env      string
		expected bool
	}{
		{
			name: "unset",
			data: map[string]interface{}{
				consts.FieldSkipChildToken: true,
			},
			field:    consts.FieldSetNamespaceFromToken,
			dv:       true,
			env:      "VAULT_SET_NAMESPACE_FROM_TOKEN",
			expected: true,
		},
		{
			name: "set-to-false",
			data: map[string]interface{}{
				consts.FieldSetNamespaceFromToken: false,
			},
			field:    consts.FieldSetNamespaceFromToken,
			dv:       true,
			env:      "VAULT_SET_NAMESPACE_FROM_TOKEN",
			expected: false,
		},
		{
			name: "set-to-true",
			data: map[string]interface{}{
				consts.FieldSetNamespaceFromToken: true,
			},
			field:    consts.FieldSetNamespaceFromToken,
			dv:       true,
			env:      "VAULT_SET_NAMESPACE_FROM_TOKEN",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//ctx := context.Background()
			//cfg := terraform.NewResourceConfigRaw(tt.data)
			//rootProvider.Configure(ctx, cfg)
			diff := schema.TestResourceDataRaw(t,
				rootProvider.Schema,
				tt.data)
			//for k, v := range tt.data {
			//	if err := tt.d.Set(k, v); err != nil {
			//		t.Fatalf("failed to set resource data, key=%s, value=%#v", k, v)
			//	}
			//}

			got := GetResourceDataBool(diff, tt.field, tt.env, tt.dv)
			if got != tt.expected {
				t.Errorf("GetResourceDataBool() got = %v, want %v", got, tt.expected)
			}
		})
	}
}
