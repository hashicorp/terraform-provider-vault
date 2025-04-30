// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityEntity(t *testing.T) {
	var p *schema.Provider
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(resourceName),
			},
		},
	})
}

func TestAccIdentityEntityUpdate(t *testing.T) {
	var p *schema.Provider
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(resourceName),
			},
			{
				Config: testAccIdentityEntityConfigUpdate(entity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityEntityCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s-2", entity)),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "2"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "policies.1", "test"),
					resource.TestCheckResourceAttr(resourceName, "disabled", "true"),
				),
			},
		},
	})
}

func TestAccIdentityEntityUpdateRemoveValues(t *testing.T) {
	var p *schema.Provider
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(resourceName),
			},
			{
				Config: testAccIdentityEntityConfigUpdateRemove(entity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", fmt.Sprintf("%s-2", entity)),
					resource.TestCheckResourceAttr(resourceName, "external_policies", "false"),
					resource.TestCheckResourceAttr(resourceName, "disabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "0"),
				),
			},
		},
	})
}

// Testing an edge case where external_policies is true but policies
// are still in the plan. They should be removed from the entity if this
// bool is true.
func TestAccIdentityEntityUpdateRemovePolicies(t *testing.T) {
	var p *schema.Provider
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(resourceName),
			},
			{
				Config: testAccIdentityEntityConfigUpdateRemovePolicies(entity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "external_policies", "true"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "policies.0", "test"),
				),
			},
		},
	})
}

func testAccCheckIdentityEntityDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_entity" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(entity.JoinEntityID(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity entity %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity entity role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityEntityCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := entity.JoinEntityID(rs.Primary.ID)
		tAttrs := []*testutil.VaultStateTest{
			{
				ResourceName: resourceName,
				StateAttr:    "name",
				VaultAttr:    "name",
			},
			{
				ResourceName: resourceName,
				StateAttr:    "policies",
				VaultAttr:    "policies",
			},
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccIdentityEntityConfig(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}`, entityName)
}

func testAccIdentityEntityConfigUpdate(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s-2"
  policies = ["dev", "test"]
  metadata = {
    version = "2"
  }
  disabled = true
  external_policies = false
}`, entityName)
}

func testAccIdentityEntityConfigUpdateRemove(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s-2"
}`, entityName)
}

func testAccIdentityEntityConfigUpdateRemovePolicies(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s-2"
  policies = ["dev", "test"]
  external_policies = true
}`, entityName)
}

func TestReadEntity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		path            string
		maxRetries      int
		expectedRetries int
		wantError       error
		retryHandler    *testutil.TestRetryHandler
		retryWait       time.Duration
	}{
		{
			name: "retry-none",
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount: 1,
				// RetryStatus: http.StatusNotFound,
				RespData: []byte(`{"data": {"foo": "baz"}}`),
			},
			maxRetries:      4,
			expectedRetries: 0,
		},
		{
			name: "retry-ok-404",
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount:   3,
				RetryStatus: http.StatusNotFound,
				RespData:    []byte(`{"data": {"foo": "baz"}}`),
			},
			maxRetries:      4,
			expectedRetries: 2,
		},
		{
			name: "retry-ok-412",
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount:   3,
				RetryStatus: http.StatusPreconditionFailed,
				RespData:    []byte(`{"data": {"foo": "baz"}}`),
			},
			maxRetries:      4,
			expectedRetries: 2,
		},
		{
			name: "retry-exhausted-default-max-404",
			path: entity.JoinEntityID("retry-exhausted-default-max-404"),
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount:   0,
				RetryStatus: http.StatusNotFound,
			},
			maxRetries:      DefaultMaxHTTPRetriesCCC,
			expectedRetries: DefaultMaxHTTPRetriesCCC,
			wantError: fmt.Errorf(`%w: %q`, entity.ErrEntityNotFound,
				entity.JoinEntityID("retry-exhausted-default-max-404")),
		},
		{
			name: "retry-exhausted-default-max-412",
			path: entity.JoinEntityID("retry-exhausted-default-max-412"),
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount:   0,
				RetryStatus: http.StatusPreconditionFailed,
			},
			maxRetries:      DefaultMaxHTTPRetriesCCC,
			expectedRetries: DefaultMaxHTTPRetriesCCC,
			wantError: fmt.Errorf(`failed reading %q`,
				entity.JoinEntityID("retry-exhausted-default-max-412")),
		},
		{
			name: "retry-exhausted-custom-max-404",
			path: entity.JoinEntityID("retry-exhausted-custom-max-404"),
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount:   0,
				RetryStatus: http.StatusNotFound,
			},
			maxRetries:      5,
			expectedRetries: 5,
			wantError: fmt.Errorf(`%w: %q`, entity.ErrEntityNotFound,
				entity.JoinEntityID("retry-exhausted-custom-max-404")),
			retryWait: time.Millisecond,
		},
		{
			name: "retry-exhausted-custom-max-412",
			path: entity.JoinEntityID("retry-exhausted-custom-max-412"),
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount:   0,
				RetryStatus: http.StatusPreconditionFailed,
			},
			maxRetries:      5,
			expectedRetries: 5,
			wantError: fmt.Errorf(`failed reading %q`,
				entity.JoinEntityID("retry-exhausted-custom-max-412")),
			retryWait: 500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				provider.MaxHTTPRetriesCCC = DefaultMaxHTTPRetriesCCC
			}()
			provider.MaxHTTPRetriesCCC = tt.maxRetries

			r := tt.retryHandler

			config, ln := testutil.TestHTTPServer(t, r.Handler())
			defer ln.Close()

			config.Address = fmt.Sprintf("http://%s", ln.Addr())
			c, err := api.NewClient(config)
			if err != nil {
				t.Fatal(err)
			}

			path := tt.path
			if path == "" {
				path = tt.name
			}

			retryWait := time.Nanosecond
			if tt.retryWait != 0 {
				// set wait to be larger for flaky tests
				retryWait = tt.retryWait
			}
			actualResp, err := entity.ReadEntity(c, path, true,
				entity.WithMinRetryWait(retryWait),
				entity.WithMaxRetryWait(retryWait))

			if tt.wantError != nil {
				if err == nil {
					t.Fatal("expected an error")
				}

				if tt.wantError.Error() != err.Error() {
					t.Errorf("expected err %q, actual %q", tt.wantError, err)
				}

				if tt.retryHandler.RetryStatus == http.StatusNotFound {
					if !group.IsIdentityNotFoundError(err) {
						t.Errorf("expected an errEntityNotFound err %q, actual %q", entity.ErrEntityNotFound, err)
					}
				}
			} else {
				if err != nil {
					t.Fatal("unexpected error", err)
				}

				var data map[string]interface{}
				if err := json.Unmarshal(tt.retryHandler.RespData, &data); err != nil {
					t.Fatalf("invalid test data %#v, err=%s", tt.retryHandler.RespData, err)
				}

				expectedResp := &api.Secret{
					Data: data["data"].(map[string]interface{}),
				}

				if !reflect.DeepEqual(expectedResp, actualResp) {
					t.Errorf("expected secret %#v, actual %#v", expectedResp, actualResp)
				}
			}

			if tt.expectedRetries != r.Retries {
				t.Fatalf("expected %d retries, actual %d", tt.expectedRetries, r.Retries)
			}
		})
	}
}

func TestIsEntityNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "default",
			err:      entity.ErrEntityNotFound,
			expected: true,
		},
		{
			name:     "wrapped",
			err:      fmt.Errorf("%w: foo", entity.ErrEntityNotFound),
			expected: true,
		},
		{
			name:     "not",
			err:      fmt.Errorf("%s: foo", entity.ErrEntityNotFound),
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := group.IsIdentityNotFoundError(tt.err)
			if actual != tt.expected {
				t.Fatalf("isIdentityNotFoundError(): expected %v, actual %v", tt.expected, actual)
			}
		})
	}
}
