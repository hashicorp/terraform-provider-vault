package testutil

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/coreos/pkg/multierror"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
)

const (
	EnvVarSkipVaultNext = "SKIP_VAULT_NEXT_TESTS"
)

func TestAccPreCheck(t *testing.T) {
	FatalTestEnvUnset(t, api.EnvVaultAddress, api.EnvVaultToken)
}

func TestEntPreCheck(t *testing.T) {
	SkipTestAccEnt(t)
	TestAccPreCheck(t)
}

func SkipTestAcc(t *testing.T) {
	SkipTestEnvUnset(t, resource.TestEnvVar)
}

func SkipTestAccEnt(t *testing.T) {
	SkipTestEnvUnset(t, "TF_ACC_ENTERPRISE")
}

// SkipTestEnvSet skips the test if any of the provided environment variables
// have a non-empty value.
func SkipTestEnvSet(t *testing.T, envVars ...string) []string {
	t.Helper()
	return handleTestEnvSetF(t.Skipf, envVars...)
}

// SkipTestEnvUnset skips the test if any of the provided environment variables
// are empty/unset.
func SkipTestEnvUnset(t *testing.T, envVars ...string) []string {
	t.Helper()
	return handleTestEnvUnsetF(t.Skipf, envVars...)
}

// FatalTestEnvUnset fails the test if any of the provided environment variables
// have non-empty values.
func FatalTestEnvUnset(t *testing.T, envVars ...string) []string {
	t.Helper()
	return handleTestEnvUnsetF(t.Fatalf, envVars...)
}

func handleTestEnvUnsetF(f func(f string, args ...interface{}), envVars ...string) []string {
	return handleTestEnv(func(k, v string) {
		if v == "" {
			f("%q must be set", k)
		}
	}, envVars...)
}

func handleTestEnvSetF(f func(f string, args ...interface{}), envVars ...string) []string {
	return handleTestEnv(func(k, v string) {
		if v != "" {
			f("%q is set", k)
		}
	}, envVars...)
}

func handleTestEnv(f func(k, v string), envVars ...string) []string {
	var result []string
	for _, k := range envVars {
		v := os.Getenv(k)
		f(k, v)
		result = append(result, v)
	}
	return result
}

func GetTestAWSCreds(t *testing.T) (string, string) {
	v := SkipTestEnvUnset(t, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
	return v[0], v[1]
}

func GetTestAWSRegion(t *testing.T) string {
	v := SkipTestEnvUnset(t, "AWS_DEFAULT_REGION")
	return v[0]
}

type AzureTestConf struct {
	SubscriptionID, TenantID, ClientID, ClientSecret, Scope string
}

func GetTestAzureConf(t *testing.T) *AzureTestConf {
	v := SkipTestEnvUnset(t,
		"AZURE_SUBSCRIPTION_ID",
		"AZURE_TENANT_ID",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_ROLE_SCOPE")

	return &AzureTestConf{
		SubscriptionID: v[0],
		TenantID:       v[1],
		ClientID:       v[2],
		ClientSecret:   v[3],
		Scope:          v[4],
	}
}

func GetTestGCPCreds(t *testing.T) (string, string) {
	// v := SkipTestEnvUnset(t, "GOOGLE_CREDENTIALS", "GOOGLE_PROJECT")
	v := SkipTestEnvUnset(t, "GOOGLE_CREDENTIALS")

	var project string
	// maybeCreds, project := v[0], v[1]
	maybeCreds := v[0]
	maybeFilename := maybeCreds
	if maybeCreds[0] == '~' {
		var err error
		maybeFilename, err = homedir.Expand(maybeCreds)
		if err != nil {
			t.Fatal("Error reading GOOGLE_CREDENTIALS: " + err.Error())
		}
	}

	if _, err := os.Lstat(maybeFilename); err == nil {
		contents, err := ioutil.ReadFile(maybeFilename)
		if err != nil {
			t.Fatal("Error reading GOOGLE_CREDENTIALS: " + err.Error())
		}
		maybeCreds = string(contents)

	}
	if _, ok := os.LookupEnv("GOOGLE_PROJECT"); !ok {
		// attempt to get the project ID from the creds JSON
		var i map[string]interface{}
		if err := json.Unmarshal([]byte(maybeCreds), &i); err == nil {
			if v, ok := i["project_id"]; ok {
				project = v.(string)
			}
		}
	} else {
		project = SkipTestEnvSet(t, "GOOGLE_PROJECT")[0]
	}

	return maybeCreds, project
}

func GetTestRMQCreds(t *testing.T) (string, string, string) {
	v := SkipTestEnvUnset(t, "RMQ_CONNECTION_URI", "RMQ_USERNAME", "RMQ_PASSWORD")
	return v[0], v[1], v[2]
}

func GetTestADCreds(t *testing.T) (string, string, string) {
	v := SkipTestEnvUnset(t, "AD_BINDDN", "AD_BINDPASS", "AD_URL")
	return v[0], v[1], v[2]
}

func GetTestNomadCreds(t *testing.T) (string, string) {
	v := SkipTestEnvUnset(t, "NOMAD_ADDR", "NOMAD_TOKEN")
	return v[0], v[1]
}

func TestCheckResourceAttrJSON(name, key, expectedValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("not found: %q", name)
		}
		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("%q has no primary instance state", name)
		}
		v, ok := instanceState.Attributes[key]
		if !ok {
			return fmt.Errorf("%s: attribute not found %q", name, key)
		}
		if expectedValue == "" && v == expectedValue {
			return nil
		}
		if v == "" {
			return fmt.Errorf("%s: attribute %q expected %#v, got %#v", name, key, expectedValue, v)
		}

		var stateJSON, expectedJSON interface{}
		err := json.Unmarshal([]byte(v), &stateJSON)
		if err != nil {
			return fmt.Errorf("%s: attribute %q not JSON: %s", name, key, err)
		}
		err = json.Unmarshal([]byte(expectedValue), &expectedJSON)
		if err != nil {
			return fmt.Errorf("expected value %q not JSON: %s", expectedValue, err)
		}
		if !reflect.DeepEqual(stateJSON, expectedJSON) {
			return fmt.Errorf("%s: attribute %q expected %#v, got %#v", name, key, expectedJSON, stateJSON)
		}
		return nil
	}
}

// GHOrgResponse provides access to a subset of the GH API's 'orgs' response data.
type GHOrgResponse struct {
	// Login is the GH organization's name
	Login string `json:"login"`
	// ID of the GH organization
	ID int `json:"id"`
}

// cache GH API responses to avoid triggering the GH request rate limiter
var ghOrgResponseCache = map[string]*GHOrgResponse{}

// GetGHOrgResponse returns the GH org's meta configuration.
func GetGHOrgResponse(t *testing.T, org string) *GHOrgResponse {
	t.Helper()

	if v, ok := ghOrgResponseCache[org]; ok {
		return v
	}

	client := newGHRESTClient()

	result := &GHOrgResponse{}
	if err := client.get(fmt.Sprintf("orgs/%s", org), result); err != nil {
		t.Fatal(err)
	}

	if org != result.Login {
		t.Fatalf("expected org %q from GH API response, actual %q", org, result.Login)
	}

	ghOrgResponseCache[org] = result

	return result
}

func newGHRESTClient() *ghRESTClient {
	client := retryablehttp.NewClient()
	client.Logger = nil
	return &ghRESTClient{
		client: client,
	}
}

type ghRESTClient struct {
	client *retryablehttp.Client
}

func (c *ghRESTClient) get(path string, v interface{}) error {
	return c.do(http.MethodGet, path, v)
}

func (c *ghRESTClient) do(method, path string, v interface{}) error {
	url := fmt.Sprintf("https://api.github.com/%s", path)
	req, err := retryablehttp.NewRequest(method, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid response for req=%#v, resp=%#v", req, resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, v); err != nil {
		return err
	}
	return nil
}

// testHTTPServer creates a test HTTP server that handles requests until
// the listener returned is closed.
// XXX: copied from github.com/hashicorp/vault/api/client_test.go
func TestHTTPServer(t *testing.T, handler http.Handler) (*api.Config, net.Listener) {
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

func GetDynamicTCPListeners(host string, count int) ([]net.Listener, func() error, error) {
	_, p, err := net.SplitHostPort(host)
	if err != nil {
		pErr := err.(*net.AddrError)
		if pErr.Err != "missing port in address" {
			return nil, nil, err
		}
	}
	if p != "" {
		return nil, nil, fmt.Errorf("host %q contains a port", host)
	}

	addr := host + ":0"
	listeners := make([]net.Listener, count)
	for i := 0; i < count; i++ {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, nil, err
		}
		listeners[i] = ln
	}

	closer := func() error {
		errs := multierror.Error{}
		for _, ln := range listeners {
			if err := ln.Close(); err != nil {
				errs = append(errs, err)
			}
		}

		if len(errs) > 0 {
			return errs
		}
		return nil
	}

	return listeners, closer, nil
}

// VaultStateTest for validating a resource's state to what is configured in Vault.
type VaultStateTest struct {
	// ResourceName fully qualified resource name
	ResourceName string
	// StateAttr for the resource
	StateAttr string
	// VaultAttr from api.Secret.Data
	VaultAttr string
	// IsSubset check when checking equality of []interface{} state value
	IsSubset bool
	// AsSet evaluation
	AsSet bool
	// TransformVaultValue function for
	TransformVaultValue TransformVaultValue
}

func (v *VaultStateTest) String() string {
	return fmt.Sprintf(`"%s.%s"" (vault attr: %q)`, v.ResourceName, v.StateAttr, v.VaultAttr)
}

// TransformVaultValue function to be used for a value from vault into a form that can be ccmpared to a value from
// from the TF state.
type TransformVaultValue func(st *VaultStateTest, resp *api.Secret) (interface{}, error)

func SplitVaultValueString(st *VaultStateTest, resp *api.Secret) (interface{}, error) {
	v, ok := resp.Data[st.VaultAttr]
	if !ok {
		return nil, fmt.Errorf("expected vault attribute %q, not found", st.VaultAttr)
	}

	result := []interface{}{}
	if v.(string) == "" {
		return result, nil
	}

	for _, s := range strings.Split(v.(string), ",") {
		result = append(result, s)
	}

	return result, nil
}

func AssertVaultState(client *api.Client, s *terraform.State, path string, tests ...*VaultStateTest) error {
	resp, err := client.Logical().Read(path)
	if resp == nil {
		return fmt.Errorf("%q doesn't exist", path)
	}
	if err != nil {
		return fmt.Errorf("error reading path %q, err=%w", path, err)
	}

	return assertVaultState(resp, s, path, tests...)
}

func AssertVaultStateFromResp(resp *api.Secret, s *terraform.State, path string, tests ...*VaultStateTest) error {
	return assertVaultState(resp, s, path, tests...)
}

func assertVaultState(resp *api.Secret, tfs *terraform.State, path string, tests ...*VaultStateTest) error {
	for _, st := range tests {
		rs, err := GetResourceFromRootModule(tfs, st.ResourceName)
		if err != nil {
			return err
		}
		attrs := rs.Primary.Attributes

		var s string
		var inState bool
		for _, suffix := range []string{"", ".#"} {
			s, inState = attrs[st.StateAttr+suffix]
			if inState {
				break
			}
		}

		v, inVault := resp.Data[st.VaultAttr]
		if v == nil && (s == "" || s == "0") {
			continue
		}

		if !inVault && inState {
			return fmt.Errorf("expected vault attribute %q, not found", st.VaultAttr)
		}

		if st.TransformVaultValue != nil {
			i, err := st.TransformVaultValue(st, resp)
			if err != nil {
				return err
			}
			v = i
		}

		errFmt := fmt.Sprintf("expected %s (%%s in state) of %q to be %%#v, got %%#v",
			st.VaultAttr, path)

		switch v := v.(type) {
		case json.Number:
			actual, err := v.Int64()
			if err != nil {
				return fmt.Errorf("expected API field %s to be an int, was %T", st.VaultAttr, v)
			}

			expected, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("expected state field %s to be a %T, was %T", st.StateAttr, v, s)
			}

			if actual != expected {
				return fmt.Errorf(errFmt, st.StateAttr, expected, actual)
			}
		case bool:
			actual := v
			if s != "" {
				expected, err := strconv.ParseBool(s)
				if err != nil {
					return fmt.Errorf("expected state field %s to be a %T, was %T", st.StateAttr, v, s)
				}

				if actual != expected {
					return fmt.Errorf(errFmt, st.StateAttr, expected, actual)
				}
			}
		case []interface{}:
			if !inState && st.IsSubset || len(v) == 0 {
				// although not strictly a subset since the state value is not a member of Vault's
				// we consider this to be valid  in lieu of a better option.
				// Usually this means that another resource was responsible for setting the value in Vault.
				return nil
			}

			c, err := strconv.ParseInt(attrs[st.StateAttr+".#"], 10, 0)
			if err != nil {
				return err
			}

			actual := v
			expected := []interface{}{}
			for i := 0; i < int(c); i++ {
				if v, ok := attrs[fmt.Sprintf("%s.%d", st.StateAttr, i)]; ok {
					expected = append(expected, v)
				}
			}

			if st.IsSubset {
				if len(expected) > len(actual) {
					return fmt.Errorf(errFmt, st.StateAttr, expected, actual)
				}

				var count int
				for _, v := range expected {
					for _, a := range actual {
						if reflect.DeepEqual(v, a) {
							count++
						}
					}
				}
				if len(expected) != count {
					return fmt.Errorf(errFmt, st.StateAttr, expected, actual)
				}
			} else if st.AsSet {
				if len(expected) != len(actual) {
					return fmt.Errorf(errFmt, st.StateAttr, expected, actual)
				}

				union := make(map[interface{}]bool)
				for _, v := range append(expected, actual...) {
					union[v] = true
				}

				if len(union) != len(expected) {
					return fmt.Errorf(errFmt, st.StateAttr, expected, actual)
				}
			} else {
				if !reflect.DeepEqual(expected, actual) {
					return fmt.Errorf(errFmt, st.StateAttr, expected, actual)
				}
			}
		case []map[string]interface{}:
			var expected []map[string]interface{}
			c, err := strconv.ParseInt(attrs[st.StateAttr+".#"], 10, 0)
			if err != nil {
				return err
			}

			for i := 0; i < int(c); i++ {
				prefix := fmt.Sprintf("%s.%d", st.StateAttr, i)
				keys := map[string]bool{}
				for attr := range attrs {
					if strings.HasPrefix(attr, prefix) {
						parts := strings.Split(attr, ".")
						if len(parts) < 3 {
							continue
						}

						switch parts[2] {
						case "#", "%":
							continue
						}

						keys[parts[2]] = true
					}
				}

				// schema.Resource recursion is not supported.
				m := make(map[string]interface{}, len(keys))
				for key := range keys {
					p := prefix + "." + key
					if val, ok := attrs[p+".#"]; ok {
						c, err := strconv.ParseInt(val, 10, 64)
						if err != nil {
							return err
						}
						vals := make([]interface{}, c)
						for i := 0; i < int(c); i++ {
							vals[i] = attrs[fmt.Sprintf("%s.%d", p, i)]
						}
						m[key] = vals

					} else {
						m[key] = attrs[p]
					}
				}

				expected = append(expected, m)
			}
			if !reflect.DeepEqual(expected, v) {
				return fmt.Errorf(errFmt, st.StateAttr, expected, v)
			}
		case string:
			if v != s {
				return fmt.Errorf(errFmt, st.StateAttr, s, v)
			}
		default:
			return fmt.Errorf("got unsupported type %T from vault for %s", v, st)
		}
	}

	return nil
}

func GetResourceFromRootModule(s *terraform.State, resourceName string) (*terraform.ResourceState, error) {
	if rs, ok := s.RootModule().Resources[resourceName]; ok {
		return rs, nil
	}

	return nil, fmt.Errorf("expected resource %q, not found in state", resourceName)
}
