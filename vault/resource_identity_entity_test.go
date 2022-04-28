package vault

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/identity/entity"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityEntity(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(),
			},
		},
	})
}

func TestAccIdentityEntityUpdate(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(),
			},
			{
				Config: testAccIdentityEntityConfigUpdate(entity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityEntityCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "name", fmt.Sprintf("%s-2", entity)),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "metadata.version", "2"),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "policies.#", "2"),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "policies.1", "test"),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "disabled", "true"),
				),
			},
		},
	})
}

func TestAccIdentityEntityUpdateRemoveValues(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(),
			},
			{
				Config: testAccIdentityEntityConfigUpdateRemove(entity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "name", fmt.Sprintf("%s-2", entity)),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "external_policies", "false"),
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "disabled", "false"),
					resource.TestCheckNoResourceAttr("vault_identity_entity.entity", "metadata"),
					resource.TestCheckNoResourceAttr("vault_identity_entity.entity", "policies")),
			},
		},
	})
}

// Testing an edge case where external_policies is true but policies
// are still in the plan. They should be removed from the entity if this
// bool is true.
func TestAccIdentityEntityUpdateRemovePolicies(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityEntityConfig(entity),
				Check:  testAccIdentityEntityCheckAttrs(),
			},
			{
				Config: testAccIdentityEntityConfigUpdateRemovePolicies(entity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_entity.entity", "external_policies", "true"),
					resource.TestCheckNoResourceAttr("vault_identity_entity.entity", "policies")),
			},
		},
	})
}

func testAccCheckIdentityEntityDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_entity" {
			continue
		}
		secret, err := client.Logical().Read(entity.IDPath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity entity %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity entity role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityEntityCheckAttrs() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_identity_entity.entity"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID

		path := entity.IDPath(id)
		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", path)
		}

		attrs := map[string]string{
			"name":     "name",
			"policies": "policies",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}
			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}

					for i := 0; i < count; i++ {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								if apiData[i] == stateValue {
									found = true
									break
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, path, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
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
		retryHandler    *testRetryHandler
	}{
		{
			name: "retry-none",
			retryHandler: &testRetryHandler{
				okAtCount: 1,
				// retryStatus: http.StatusNotFound,
				respData: []byte(`{"data": {"foo": "baz"}}`),
			},
			maxRetries:      4,
			expectedRetries: 0,
		},
		{
			name: "retry-ok-404",
			retryHandler: &testRetryHandler{
				okAtCount:   3,
				retryStatus: http.StatusNotFound,
				respData:    []byte(`{"data": {"foo": "baz"}}`),
			},
			maxRetries:      4,
			expectedRetries: 2,
		},
		{
			name: "retry-ok-412",
			retryHandler: &testRetryHandler{
				okAtCount:   3,
				retryStatus: http.StatusPreconditionFailed,
				respData:    []byte(`{"data": {"foo": "baz"}}`),
			},
			maxRetries:      4,
			expectedRetries: 2,
		},
		{
			name: "retry-exhausted-default-max-404",
			path: entity.IDPath("retry-exhausted-default-max-404"),
			retryHandler: &testRetryHandler{
				okAtCount:   0,
				retryStatus: http.StatusNotFound,
			},
			maxRetries:      DefaultMaxHTTPRetriesCCC,
			expectedRetries: DefaultMaxHTTPRetriesCCC,
			wantError: fmt.Errorf(`%w: %q`, errEntityNotFound,
				entity.IDPath("retry-exhausted-default-max-404")),
		},
		{
			name: "retry-exhausted-default-max-412",
			path: entity.IDPath("retry-exhausted-default-max-412"),
			retryHandler: &testRetryHandler{
				okAtCount:   0,
				retryStatus: http.StatusPreconditionFailed,
			},
			maxRetries:      DefaultMaxHTTPRetriesCCC,
			expectedRetries: DefaultMaxHTTPRetriesCCC,
			wantError: fmt.Errorf(`failed reading %q`,
				entity.IDPath("retry-exhausted-default-max-412")),
		},
		{
			name: "retry-exhausted-custom-max-404",
			path: entity.IDPath("retry-exhausted-custom-max-404"),
			retryHandler: &testRetryHandler{
				okAtCount:   0,
				retryStatus: http.StatusNotFound,
			},
			maxRetries:      5,
			expectedRetries: 5,
			wantError: fmt.Errorf(`%w: %q`, errEntityNotFound,
				entity.IDPath("retry-exhausted-custom-max-404")),
		},
		{
			name: "retry-exhausted-custom-max-412",
			path: entity.IDPath("retry-exhausted-custom-max-412"),
			retryHandler: &testRetryHandler{
				okAtCount:   0,
				retryStatus: http.StatusPreconditionFailed,
			},
			maxRetries:      5,
			expectedRetries: 5,
			wantError: fmt.Errorf(`failed reading %q`,
				entity.IDPath("retry-exhausted-custom-max-412")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				maxHTTPRetriesCCC = DefaultMaxHTTPRetriesCCC
			}()
			maxHTTPRetriesCCC = tt.maxRetries

			r := tt.retryHandler

			config, ln := testHTTPServer(t, r.handler())
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

			actualResp, err := readEntity(c, path, true)

			if tt.wantError != nil {
				if err == nil {
					t.Fatal("expected an error")
				}

				if tt.wantError.Error() != err.Error() {
					t.Errorf("expected err %q, actual %q", tt.wantError, err)
				}

				if tt.retryHandler.retryStatus == http.StatusNotFound {
					if !isIdentityNotFoundError(err) {
						t.Errorf("expected an errEntityNotFound err %q, actual %q", errEntityNotFound, err)
					}
				}
			} else {
				if err != nil {
					t.Fatal("unexpected error", err)
				}

				var data map[string]interface{}
				if err := json.Unmarshal(tt.retryHandler.respData, &data); err != nil {
					t.Fatalf("invalid test data %#v, err=%s", tt.retryHandler.respData, err)
				}

				expectedResp := &api.Secret{
					Data: data["data"].(map[string]interface{}),
				}

				if !reflect.DeepEqual(expectedResp, actualResp) {
					t.Errorf("expected secret %#v, actual %#v", expectedResp, actualResp)
				}
			}

			retries := r.requests - 1
			if tt.expectedRetries != retries {
				t.Fatalf("expected %d retries, actual %d", tt.expectedRetries, retries)
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
			err:      errEntityNotFound,
			expected: true,
		},
		{
			name:     "wrapped",
			err:      fmt.Errorf("%w: foo", errEntityNotFound),
			expected: true,
		},
		{
			name:     "not",
			err:      fmt.Errorf("%s: foo", errEntityNotFound),
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := isIdentityNotFoundError(tt.err)
			if actual != tt.expected {
				t.Fatalf("isIdentityNotFoundError(): expected %v, actual %v", tt.expected, actual)
			}
		})
	}
}

type testRetryHandler struct {
	requests    int
	okAtCount   int
	respData    []byte
	retryStatus int
}

func (t *testRetryHandler) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		t.requests++
		if t.okAtCount > 0 && (t.requests >= t.okAtCount) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(t.respData)
			return
		} else {
			w.WriteHeader(t.retryStatus)
		}
	}
}

// testHTTPServer creates a test HTTP server that handles requests until
// the listener returned is closed.
// XXX: copied from github.com/hashicorp/vault/api/client_test.go
func testHTTPServer(t *testing.T, handler http.Handler) (*api.Config, net.Listener) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	server := &http.Server{Handler: handler}
	go server.Serve(ln)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", ln.Addr())

	return config, ln
}
