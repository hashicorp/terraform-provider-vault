package testutil

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/cli/go-gh"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/mitchellh/go-homedir"
)

func TestAccPreCheck(t *testing.T) {
	FatalTestEnvUnset(t, "VAULT_ADDR", "VAULT_TOKEN")
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
	v := SkipTestEnvUnset(t, "GOOGLE_CREDENTIALS", "GOOGLE_PROJECT")

	maybeCreds, project := v[0], v[1]
	maybeFilename := maybeCreds
	if maybeCreds[0] == '~' {
		var err error
		maybeFilename, err = homedir.Expand(maybeCreds)
		if err != nil {
			t.Fatal("Error reading GOOGLE_CREDENTIALS: " + err.Error())
		}
	}

	if _, err := os.Stat(maybeFilename); err == nil {
		contents, err := ioutil.ReadFile(maybeFilename)
		if err != nil {
			t.Fatal("Error reading GOOGLE_CREDENTIALS: " + err.Error())
		}
		maybeCreds = string(contents)
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
	Login string
	// ID of the GH organization
	ID int
}

// cache GH API responses to avoid triggering the GH request rate limiter
var ghOrgResponseCache = map[string]*GHOrgResponse{}

// GetGHOrgResponse returns the GH org's meta configuration.
func GetGHOrgResponse(t *testing.T, org string) *GHOrgResponse {
	t.Helper()

	if v, ok := ghOrgResponseCache[org]; ok {
		return v
	}

	client, err := gh.RESTClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	result := &GHOrgResponse{}
	if err := client.Get(fmt.Sprintf("orgs/%s", org), result); err != nil {
		t.Fatal(err)
	}

	if org != result.Login {
		t.Fatalf("expected org %q from GH API response, actual %q", org, result.Login)
	}

	ghOrgResponseCache[org] = result

	return result
}
