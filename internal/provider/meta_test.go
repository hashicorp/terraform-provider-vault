package provider

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
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
			name:         "no-client",
			client:       nil,
			resourceData: &schema.ResourceData{},
			wantErr:      true,
			expectErr:    errors.New("root api.Client not set, init with NewProviderMeta()"),
		},
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
		actualNs := c.Headers().Get(consts.NamespaceHeaderName)
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
