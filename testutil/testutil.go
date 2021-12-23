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
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" {
		t.Skip("AWS_ACCESS_KEY_ID not set")
	}
	if secretKey == "" {
		t.Skip("AWS_SECRET_ACCESS_KEY not set")
	}
	return accessKey, secretKey
}

func GetTestAWSRegion(t *testing.T) string {
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		t.Skip("AWS_DEFAULT_REGION not set")
	}
	return region
}

type AzureTestConf struct {
	SubscriptionID, TenantID, ClientID, ClientSecret, Scope string
}

func GetTestAzureConf(t *testing.T) *AzureTestConf {
	conf := &AzureTestConf{
		SubscriptionID: os.Getenv("AZURE_SUBSCRIPTION_ID"),
		TenantID:       os.Getenv("AZURE_TENANT_ID"),
		ClientID:       os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret:   os.Getenv("AZURE_CLIENT_SECRET"),
		Scope:          os.Getenv("AZURE_ROLE_SCOPE"),
	}
	if conf.SubscriptionID == "" {
		t.Skip("AZURE_SUBSCRIPTION_ID not set")
	}
	if conf.TenantID == "" {
		t.Skip("AZURE_TENANT_ID not set")
	}
	if conf.ClientID == "" {
		t.Skip("AZURE_CLIENT_ID not set")
	}
	if conf.ClientSecret == "" {
		t.Skip("AZURE_CLIENT_SECRET not set")
	}
	if conf.Scope == "" {
		t.Skip("AZURE_ROLE_SCOPE not set")
	}
	return conf
}

func GetTestGCPCreds(t *testing.T) (string, string) {
	maybeCreds := os.Getenv("GOOGLE_CREDENTIALS")
	project := os.Getenv("GOOGLE_PROJECT")

	if maybeCreds == "" {
		t.Skip("GOOGLE_CREDENTIALS not set")
	}

	if project == "" {
		t.Skip("GOOGLE_PROJECT not set")
	}

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
	connectionUri := os.Getenv("RMQ_CONNECTION_URI")
	username := os.Getenv("RMQ_USERNAME")
	password := os.Getenv("RMQ_PASSWORD")
	if connectionUri == "" {
		t.Skip("RMQ_CONNECTION_URI not set")
	}
	if username == "" {
		t.Skip("RMQ_USERNAME not set")
	}
	if password == "" {
		t.Skip("RMQ_PASSWORD not set")
	}
	return connectionUri, username, password
}

func GetTestADCreds(t *testing.T) (string, string, string) {
	v := SkipTestEnvUnset(t, "AD_BINDDN", "AD_BINDPASS", "AD_URL")
	return v[0], v[1], v[2]
}

func GetTestNomadCreds(t *testing.T) (string, string) {
	v := SkipTestEnvUnset(t, "NOMAD_ADDR", "NOMAD_TOKEN")
	return v[0], v[1]
}
