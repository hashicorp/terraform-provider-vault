// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/internal/identity/group"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityEntity(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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
	entity := acctest.RandomWithPrefix("test-entity")

	resourceName := "vault_identity_entity.entity"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
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

// TestIdentityEntityCreate_alreadyExists is a regression test

// It reproduces the Vault Enterprise 2.0.3 behavior where POST
// /identity/entity returns a 200 response with a non-nil body but a null
// "data" field when the entity already exists. Before the fix, the create
// path assumed a nil *api.Secret in this situation and panicked with
// "interface conversion: interface {} is nil, not string" while doing
// resp.Data["id"].(string). This test asserts that identityEntityCreate
// instead returns a clean "already exists" error, with no panic.
func TestIdentityEntityCreate_alreadyExists(t *testing.T) {
	handler := testTokenLookupHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identity/entity":
			// Non-nil response with a null "data" field (entity already exists).
			json.NewEncoder(w).Encode(map[string]interface{}{
				"request_id": "test-request-id",
				"data":       nil,
			})
		case "/v1/identity/entity/name/app1":
			// Realistic fallback lookup response: the entity actually
			// exists, so the "may be imported" hint can be resolved.
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id":   "existing-entity-id",
					"name": "app1",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found"}})
		}
	})
	meta := testProviderMeta(t, handler)

	rsc := identityEntityResource()
	d := rsc.TestResourceData()
	d.Set(consts.FieldName, "app1")

	// The key assertion here is that this call does not panic. Prior to the
	// fix, this line would crash the whole test binary rather than
	// surfacing as a normal test failure.
	err := identityEntityCreate(d, meta)

	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected an 'already exists' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "existing-entity-id") {
		t.Errorf("expected error to include the existing entity id for import, got: %v", err)
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
