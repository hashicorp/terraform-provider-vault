package testutil

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/mitchellh/go-homedir"
)

func TestAccPreCheck(t *testing.T) {
	FatalTestEnvUnset(t, "VAULT_ADDR", "VAULT_TOKEN")
}

func TestEntPreCheck(t *testing.T) {
	SkipTestEnvUnset(t, "TF_ACC_ENTERPRISE")
	TestAccPreCheck(t)
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
	v := SkipTestEnvSet(t, "AWS_DEFAULT_REGION")
	return v[0]
}

type AzureTestConf struct {
	SubscriptionID, TenantID, ClientID, ClientSecret, Scope string
}

func GetTestAzureConf(t *testing.T) *AzureTestConf {
	v := SkipTestEnvSet(t,
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
	v := SkipTestEnvSet(t, "GOOGLE_CREDENTIALS", "GOOGLE_PROJECT")

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
