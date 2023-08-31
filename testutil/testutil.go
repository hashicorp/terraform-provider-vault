// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/pkg/multierror"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	EnvVarSkipVaultNext = "SKIP_VAULT_NEXT_TESTS"
)

func TestAccPreCheck(t *testing.T) {
	t.Helper()
	FatalTestEnvUnset(t, api.EnvVaultAddress, api.EnvVaultToken)
}

func TestEntPreCheck(t *testing.T) {
	t.Helper()
	SkipTestAccEnt(t)
	TestAccPreCheck(t)
}

func SkipTestAcc(t *testing.T) {
	t.Helper()
	SkipTestEnvUnset(t, resource.EnvTfAcc)
}

func SkipTestAccEnt(t *testing.T) {
	t.Helper()
	SkipTestEnvUnset(t, "TF_ACC_ENTERPRISE")
}

// SkipTestEnvSet skips the test if any of the provided environment variables
// have a non-empty value.
func SkipTestEnvSet(t *testing.T, envVars ...string) []string {
	t.Helper()
	return handleTestEnvSetF(t, t.Skipf, envVars...)
}

// SkipTestEnvUnset skips the test if any of the provided environment variables
// are empty/unset.
func SkipTestEnvUnset(t *testing.T, envVars ...string) []string {
	t.Helper()
	return handleTestEnvUnsetF(t, t.Skipf, envVars...)
}

// FatalTestEnvUnset fails the test if any of the provided environment variables
// have non-empty values.
func FatalTestEnvUnset(t *testing.T, envVars ...string) []string {
	t.Helper()
	return handleTestEnvUnsetF(t, t.Fatalf, envVars...)
}

func handleTestEnvUnsetF(t *testing.T, f func(f string, args ...interface{}), envVars ...string) []string {
	t.Helper()
	return handleTestEnv(t, func(k, v string) {
		t.Helper()
		if v == "" {
			f("%q must be set", k)
		}
	}, envVars...)
}

func handleTestEnvSetF(t *testing.T, f func(f string, args ...interface{}), envVars ...string) []string {
	t.Helper()
	return handleTestEnv(t, func(k, v string) {
		t.Helper()
		if v != "" {
			f("%q is set", k)
		}
	}, envVars...)
}

func handleTestEnv(t *testing.T, f func(k string, v string), envVars ...string) []string {
	t.Helper()
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
	SubscriptionID, TenantID, ClientID, ClientSecret, Scope, AppObjectID string
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

func GetTestAzureConfExistingSP(t *testing.T) *AzureTestConf {
	v := SkipTestEnvUnset(t,
		"AZURE_SUBSCRIPTION_ID",
		"AZURE_TENANT_ID",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_APPLICATION_OBJECT_ID")

	return &AzureTestConf{
		SubscriptionID: v[0],
		TenantID:       v[1],
		ClientID:       v[2],
		ClientSecret:   v[3],
		AppObjectID:    v[4],
	}
}

func GetTestGCPCreds(t *testing.T) (string, string) {
	t.Helper()

	credsEnvKey := "GOOGLE_CREDENTIALS"
	projectEnvKey := "GOOGLE_PROJECT"
	fileEnvKey := "GOOGLE_CREDENTIALS_FILE"

	var creds string
	if filename, ok := os.LookupEnv(fileEnvKey); ok {
		var f string
		var err error
		if f, err = homedir.Expand(filename); err == nil {
			var contents []byte
			contents, err = ioutil.ReadFile(f)
			if err == nil {
				creds = string(contents)
			}
		}
		if err != nil {
			t.Fatalf("Error reading GCP creds from %s: %s", filename, err)
		}
	} else {
		creds = SkipTestEnvUnset(t, credsEnvKey)[0]
	}

	var project string
	if _, ok := os.LookupEnv(projectEnvKey); !ok {
		// attempt to get the project ID from the creds JSON
		var i map[string]interface{}
		if err := json.Unmarshal([]byte(creds), &i); err != nil {
			t.Fatalf("Error invalid GCP creds JSON, err=%s", err)
		}

		k := "project_id"
		v, ok := i[k]
		if !ok {
			t.Fatalf("Error %q not found in GCP creds JSON", k)
		}
		project = v.(string)
	} else {
		project = SkipTestEnvSet(t, projectEnvKey)[0]
	}

	return creds, project
}

func GetTestRMQCreds(t *testing.T) (string, string, string) {
	v := SkipTestEnvUnset(t, "RMQ_CONNECTION_URI", "RMQ_USERNAME", "RMQ_PASSWORD")
	return v[0], v[1], v[2]
}

func GetTestMDBACreds(t *testing.T) (string, string) {
	v := SkipTestEnvUnset(t, "MONGODB_ATLAS_PRIVATE_KEY", "MONGODB_ATLAS_PUBLIC_KEY")
	return v[0], v[1]
}

func GetTestADCreds(t *testing.T) (string, string, string) {
	v := SkipTestEnvUnset(t, "AD_BINDDN", "AD_BINDPASS", "AD_URL")
	return v[0], v[1], v[2]
}

func GetTestLDAPCreds(t *testing.T) (string, string, string) {
	v := SkipTestEnvUnset(t, "LDAP_BINDDN", "LDAP_BINDPASS", "LDAP_URL")
	return v[0], v[1], v[2]
}

func GetTestNomadCreds(t *testing.T) (string, string) {
	v := SkipTestEnvUnset(t, "NOMAD_ADDR", "NOMAD_TOKEN")
	return v[0], v[1]
}

func GetTestPKCSCreds(t *testing.T) (string, string, string) {
	v := SkipTestEnvUnset(t, "PKCS_KEY_LIBRARY", "PKCS_KEY_SLOT", "PKCS_KEY_PIN")
	return v[0], v[1], v[2]
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
var ghOrgResponseCache = sync.Map{}

// GetGHOrgResponse returns the GH org's meta configuration.
func GetGHOrgResponse(t *testing.T, org string) *GHOrgResponse {
	t.Helper()

	client := newGHRESTClient()
	if v, ok := ghOrgResponseCache.Load(org); ok {
		return v.(*GHOrgResponse)
	}

	result := &GHOrgResponse{}
	if err := client.get(fmt.Sprintf("orgs/%s", org), result); err != nil {
		t.Fatal(err)
	}

	if org != result.Login {
		t.Fatalf("expected org %q from GH API response, actual %q", org, result.Login)
	}

	ghOrgResponseCache.Store(org, result)

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
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

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

// TestHTTPServer creates a test HTTP server that handles requests until
// the listener returned is closed.
// XXX: copied from github.com/hashicorp/vault/api/client_test.go
func TestHTTPServer(t *testing.T, handler http.Handler) (*api.Config, net.Listener) {
	t.Helper()

	server, ln, err := testHTTPServer(handler, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	go server.Serve(ln)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", ln.Addr())

	return config, ln
}

// TestHTTPSServer creates a test HTTP server that handles requests until
// the listener returned is closed.
// XXX: copied from github.com/hashicorp/vault/api/client_test.go
func TestHTTPSServer(t *testing.T, handler http.Handler) (*api.Config, net.Listener) {
	t.Helper()

	var ca []byte
	var key []byte
	var err error
	var serverTLSConfig *tls.Config
	ca, key, err = GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := tls.X509KeyPair(ca, key)
	if err != nil {
		t.Fatal(err)
	}

	serverTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server, ln, err := testHTTPServer(handler, serverTLSConfig)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	go server.ServeTLS(ln, "", "")

	config := api.DefaultConfig()
	config.CloneTLSConfig = true
	if err := config.ConfigureTLS(&api.TLSConfig{
		CACertBytes: ca,
	}); err != nil {
		t.Fatal(err)
	}

	config.Address = fmt.Sprintf("https://%s", ln.Addr())
	return config, ln
}

func testHTTPServer(handler http.Handler, tlsConfig *tls.Config) (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}

	server := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	return server, ln, err
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
// the TF state.
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

		var v interface{}
		var inVault bool
		if st.VaultAttr == "" {
			v = resp.Data
			inVault = true
		} else {
			v, inVault = resp.Data[st.VaultAttr]
			if v == nil && (s == "" || s == "0") {
				continue
			}

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
		case map[string]interface{}:
			expected := map[string]interface{}{}

			prefix := fmt.Sprintf("%s.", st.StateAttr)
			for attr := range attrs {
				if strings.HasPrefix(attr, prefix) {
					parts := strings.Split(attr, ".")
					if len(parts) < 2 {
						continue
					}

					switch parts[1] {
					case "#", "%":
						continue
					}

					expected[parts[1]] = attrs[attr]
				}
			}
			if !reflect.DeepEqual(expected, v) {
				return fmt.Errorf(errFmt, st.StateAttr, expected, v)
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

// CheckJSONData from an expected string for a given resource attribute.
func CheckJSONData(resourceName, attr, expected string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		actual, ok := rs.Primary.Attributes[attr]
		if !ok {
			return fmt.Errorf("resource %q has no attribute %q", resourceName, attr)
		}

		var e map[string]interface{}
		if err := json.Unmarshal([]byte(expected), &e); err != nil {
			return nil
		}

		var a map[string]interface{}
		if err := json.Unmarshal([]byte(actual), &a); err != nil {
			return nil
		}

		if !reflect.DeepEqual(e, a) {
			return fmt.Errorf("expected %#v, got %#v for resource attr %s.%s", e, a, resourceName, attr)
		}

		return nil
	}
}

// GetImportTestStep for resource name. If a custom ImportStateCheck function is not desired, pass
// a nil value. Optionally include field names that should be ignored during the import
// verification, typically ignore fields should only be provided for values that are not returned
// from the provisioning API.
func GetImportTestStep(resourceName string, skipVerify bool, check resource.ImportStateCheckFunc, ignoreFields ...string) resource.TestStep {
	ts := resource.TestStep{
		ResourceName:            resourceName,
		ImportState:             true,
		ImportStateVerify:       !skipVerify,
		ImportStateVerifyIgnore: ignoreFields,
	}

	if check != nil {
		ts.ImportStateCheck = check
	}

	return ts
}

func TestAccCheckAuthMountExists(n string, out *api.AuthMount, c *api.Client) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		return AuthMountExistsHelper(n, s, out, c)
	}
}

func AuthMountExistsHelper(resourceName string, s *terraform.State, out *api.AuthMount, c *api.Client) error {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return fmt.Errorf("Not found: %s", resourceName)
	}

	if rs.Primary.ID == "" {
		return fmt.Errorf("No id for %s is set", resourceName)
	}

	auths, err := c.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	resp := auths[strings.Trim(rs.Primary.ID, "/")+"/"]
	if resp == nil {
		return fmt.Errorf("auth mount %s not present", rs.Primary.ID)
	}
	log.Printf("[INFO] Auth mount resource '%v' confirmed to exist at path: %v", resourceName, rs.Primary.ID)
	*out = *resp

	return nil
}

// GetNamespaceImportStateCheck checks that the namespace was properly imported into the state.
func GetNamespaceImportStateCheck(ns string) resource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		for _, s := range states {
			if actual := s.Attributes[consts.FieldNamespace]; actual != ns {
				return fmt.Errorf("expected %q for %s, actual %q",
					ns, consts.FieldNamespace, actual)
			}
		}
		return nil
	}
}

// Stashing functions here for generating a CA cert in the tests. Pulled mostly
// from the vault-k8s cert package.

func GenerateCA() ([]byte, []byte, error) {
	// Create the private key we'll use for this CA cert.
	signer, key, err := PrivateKey()
	if err != nil {
		return nil, nil, err
	}

	// The serial number for the cert
	sn, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}

	signerKeyId, err := keyId(signer.Public())
	if err != nil {
		return nil, nil, err
	}

	// Create the CA cert
	template := x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "Testing CA"},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		NotAfter:              time.Now().Add(1 * time.Hour),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		AuthorityKeyId:        signerKeyId,
		SubjectKeyId:          signerKeyId,
	}

	bs, err := x509.CreateCertificate(
		rand.Reader, &template, &template, signer.Public(), signer)
	if err != nil {
		return nil, nil, err
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: bs})
	if err != nil {
		return nil, nil, err
	}

	return buf.Bytes(), key, nil
}

// PrivateKey returns a new ECDSA-based private key. Both a crypto.Signer
// and the key are returned.
func PrivateKey() (crypto.Signer, []byte, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	bs, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, nil, err
	}

	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: bs})
	if err != nil {
		return nil, nil, err
	}

	return pk, buf.Bytes(), nil
}

// serialNumber generates a new random serial number.
func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
}

// keyId returns a x509 KeyId from the given signing key. The key must be
// an *ecdsa.PublicKey currently, but may support more types in the future.
func keyId(raw interface{}) ([]byte, error) {
	switch raw.(type) {
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("invalid key type: %T", raw)
	}

	// This is not standard; RFC allows any unique identifier as long as they
	// match in subject/authority chains but suggests specific hashing of DER
	// bytes of public key including DER tags.
	bs, err := x509.MarshalPKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	// String formatted
	kID := sha256.Sum256(bs)
	return []byte(strings.Replace(fmt.Sprintf("% x", kID), " ", ":", -1)), nil
}

func GetTestCertPool(t *testing.T, cert []byte) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(cert); !ok {
		t.Fatal("test certificate contains no valid certificates")
	}
	return pool
}

type TestRetryHandler struct {
	Requests    int
	Retries     int
	OKAtCount   int
	RespData    []byte
	RetryStatus int
}

func (r *TestRetryHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if r.Requests > 0 {
			r.Retries++
		}

		r.Requests++
		if r.OKAtCount > 0 && (r.Requests == r.OKAtCount) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(r.RespData)
			return
		} else {
			w.WriteHeader(r.RetryStatus)
		}
	}
}
