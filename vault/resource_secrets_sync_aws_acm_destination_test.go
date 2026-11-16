// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	terraformtesting "github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	defaultAwsAcmCertificateNameTemplate = "vault/{{ .MountAccessor }}/{{ .CommonName }}"
	updatedAwsAcmCertificateNameTemplate = "vault-{{ .MountAccessor }}-{{ .CommonName }}"

	// envAWSACMVaultEnvCreds makes the ACM tests omit access_key_id and
	// secret_access_key, so that Vault uses the AWS credentials from its own
	// environment. Use it with temporary credentials: the aws-acm destination
	// does not accept a session token.
	envAWSACMVaultEnvCreds = "TEST_AWS_ACM_USE_VAULT_ENV_CREDS"
	envAWSACMRoleARN       = "TEST_AWS_ACM_ROLE_ARN"
	envAWSACMExternalID    = "TEST_AWS_ACM_EXTERNAL_ID"
)

type awsACMTestCreds struct {
	accessKey string
	secretKey string
}

func getTestAWSACMCreds(t *testing.T) awsACMTestCreds {
	t.Helper()
	if os.Getenv(envAWSACMVaultEnvCreds) != "" {
		return awsACMTestCreds{}
	}
	accessKey, secretKey := testutil.GetTestAWSCreds(t)
	return awsACMTestCreds{accessKey: accessKey, secretKey: secretKey}
}

func (c awsACMTestCreds) hcl() string {
	if c.accessKey == "" {
		return ""
	}
	return fmt.Sprintf("  access_key_id     = %q\n  secret_access_key = %q\n", c.accessKey, c.secretKey)
}

func (c awsACMTestCreds) check(resourceName string) resource.TestCheckFunc {
	if c.accessKey == "" {
		return resource.ComposeTestCheckFunc(
			resource.TestCheckNoResourceAttr(resourceName, fieldAccessKeyID),
			resource.TestCheckNoResourceAttr(resourceName, fieldSecretAccessKey),
		)
	}
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr(resourceName, fieldAccessKeyID, c.accessKey),
		resource.TestCheckResourceAttr(resourceName, fieldSecretAccessKey, c.secretKey),
	)
}

func TestAWSACMSecretsSyncDestination_schema(t *testing.T) {
	r := awsAcmSecretsSyncDestinationResource()
	if err := r.InternalValidate(nil, true); err != nil {
		t.Fatalf("schema failed internal validation: %s", err)
	}

	for _, field := range []string{consts.FieldGranularity, consts.FieldSecretNameTemplate, consts.FieldKmsKeyID, consts.FieldReplicaRegions} {
		if _, ok := r.Schema[field]; ok {
			t.Errorf("field %q is not supported by aws-acm destinations and must not be in the schema", field)
		}
	}

	for _, field := range []string{consts.FieldName, consts.FieldRegion} {
		if !r.Schema[field].ForceNew {
			t.Errorf("field %q must be ForceNew", field)
		}
	}

	// Vault falls back to AWS_REGION when region is omitted, so it must not plan a replacement.
	if region := r.Schema[consts.FieldRegion]; !region.Computed || !region.Optional {
		t.Errorf("field %q must be optional and computed", consts.FieldRegion)
	}

	deliveryMode := r.Schema[consts.FieldDeliveryMode]
	if !deliveryMode.Required {
		t.Errorf("field %q must be required", consts.FieldDeliveryMode)
	}

	tests := map[string]bool{
		"full_bundle": false,
		"cert_only":   true,
		"FULL_BUNDLE": true,
		"":            true,
	}
	for value, wantErr := range tests {
		_, errs := deliveryMode.ValidateFunc(value, consts.FieldDeliveryMode)
		if gotErr := len(errs) > 0; gotErr != wantErr {
			t.Errorf("delivery_mode %q: expected error=%t, got errors=%v", value, wantErr, errs)
		}
	}
}

func TestAWSACMSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm")
	resourceName := "vault_secrets_sync_aws_acm_destination.test"
	creds := getTestAWSACMCreds(t)
	region := testutil.GetTestAWSRegion(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAWSACMSecretsSyncDestinationDestroyed,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSACMSecretsSyncDestinationConfig_initial(creds, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsAcmSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, defaultAwsAcmCertificateNameTemplate),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar"}),
					creds.check(resourceName),
				),
			},
			{
				Config: testAWSACMSecretsSyncDestinationConfig_updated(creds, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, awsAcmSyncType),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, updatedAwsAcmCertificateNameTemplate),
					testCheckCustomTags(resourceName, map[string]string{"foo": "bar", "baz": "bux"}),
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv4_addresses.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_ipv4_addresses.*", "0.0.0.0/0"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ports.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "allowed_ports.*", "443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "true"),
					creds.check(resourceName),
				),
			},
			{
				// Vault replaces the full tag set on update, so removed tags must not come back.
				Config: testAWSACMSecretsSyncDestinationConfig_tagsRemoved(creds, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldCertificateNameTemplate, updatedAwsAcmCertificateNameTemplate),
					testCheckCustomTags(resourceName, nil),
				),
			},
			{
				// Vault keeps stored values unless they are explicitly cleared, so removing the
				// networking settings must be sent to Vault as empty values.
				Config: testAWSACMSecretsSyncDestinationConfig_networkingRemoved(creds, region, destName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv4_addresses.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ports.#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "false"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
				consts.FieldDisableStrictNetworking, // Vault API doesn't return false when not set
			),
		},
	})
}

// TestAWSACMSecretsSyncDestination_assumeRole needs a real IAM role, because Vault
// validates the effective AWS identity through STS when an ACM destination is written.
func TestAWSACMSecretsSyncDestination_assumeRole(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm-role")
	resourceName := "vault_secrets_sync_aws_acm_destination.test"
	creds := getTestAWSACMCreds(t)
	region := testutil.GetTestAWSRegion(t)
	roleArn := testutil.SkipTestEnvUnset(t, envAWSACMRoleARN)[0]
	externalID := os.Getenv(envAWSACMExternalID)

	externalIDHCL := ""
	if externalID != "" {
		externalIDHCL = fmt.Sprintf("  external_id = %q\n", externalID)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAWSACMSecretsSyncDestinationDestroyed,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name          = "%s"
  region        = "%s"
  delivery_mode = "full_bundle"
  role_arn      = "%s"
%s%s%s
}`, destName, region, roleArn, externalIDHCL, creds.hcl(), customTagsHCL(awsSyncCustomTagsWithOwner(nil))),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalID, externalID),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				fieldAccessKeyID,
				fieldSecretAccessKey,
				consts.FieldDisableStrictNetworking,
			),
		},
	})
}

func TestAWSACMSecretsSyncDestination_invalidDeliveryMode(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAWSACMSecretsSyncDestinationDestroyed,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name          = "%s"
  region        = "us-east-1"
  delivery_mode = "cert_only"
}`, destName),
				ExpectError: regexp.MustCompile(`expected delivery_mode to be one of \["full_bundle"\]`),
			},
		},
	})
}

func TestAWSACMSecretsSyncDestinationWIF(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-aws-acm-wif")
	resourceName := "vault_secrets_sync_aws_acm_destination.test"
	region := testutil.GetTestAWSRegion(t)
	values := testutil.SkipTestEnvUnset(t, "IDENTITY_TOKEN_AUDIENCE", "ROLE_ARN")
	audience := values[0]
	roleArn := values[1]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAWSACMSecretsSyncDestinationDestroyed,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion230)
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSACMSecretsSyncDestinationWIFConfig(destName, region, audience, roleArn, 30, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, region),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRoleArn, roleArn),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeliveryMode, awsAcmDeliveryModeFullBundle),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWO),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenKeyWO),
				),
			},
			{
				Config: testAWSACMSecretsSyncDestinationWIFConfig(destName, region, audience, roleArn, 60, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenTTL, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldIdentityTokenAudienceWO),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldIdentityTokenAudienceWO,
				consts.FieldIdentityTokenAudienceWOVersion,
				consts.FieldIdentityTokenKeyWO,
				consts.FieldIdentityTokenKeyWOVersion,
				consts.FieldDisableStrictNetworking,
			),
			{
				Config: fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "conflict" {
  name                       = "%s-conflict"
  region                     = "%s"
  delivery_mode              = "full_bundle"
  access_key_id              = "AKIAEXAMPLE"
  identity_token_audience_wo = "%s"
  identity_token_audience_wo_version = 1
}`, destName, region, audience),
				ExpectError: regexp.MustCompile(`conflicts with`),
			},
		},
	})
}

func testAWSACMSecretsSyncDestinationConfig_initial(creds awsACMTestCreds, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name          = "%s"
  region        = "%s"
  delivery_mode = "full_bundle"
%s%s
}
`, destName, region, creds.hcl(), customTagsHCL(awsSyncCustomTagsWithOwner(map[string]string{"foo": "bar"})))
}

// The networking step must still let Vault reach AWS STS, which it calls on every
// write of an ACM destination, so it allows all IPv4 addresses on port 443.
func testAWSACMSecretsSyncDestinationConfig_updated(creds awsACMTestCreds, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                      = "%s"
  region                    = "%s"
  delivery_mode             = "full_bundle"
  certificate_name_template = "%s"
  allowed_ipv4_addresses    = ["0.0.0.0/0"]
  allowed_ports             = [443]
  disable_strict_networking = true
%s%s
}
`, destName, region, updatedAwsAcmCertificateNameTemplate, creds.hcl(),
		customTagsHCL(awsSyncCustomTagsWithOwner(map[string]string{"foo": "bar", "baz": "bux"})))
}

func testAWSACMSecretsSyncDestinationConfig_tagsRemoved(creds awsACMTestCreds, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                      = "%s"
  region                    = "%s"
  delivery_mode             = "full_bundle"
  certificate_name_template = "%s"
  allowed_ipv4_addresses    = ["0.0.0.0/0"]
  allowed_ports             = [443]
  disable_strict_networking = true
%s%s
}
`, destName, region, updatedAwsAcmCertificateNameTemplate, creds.hcl(),
		customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
}

func testAWSACMSecretsSyncDestinationWIFConfig(destName, region, audience, roleArn string, ttl, audienceVersion int) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                               = "%s"
  region                             = "%s"
  role_arn                           = "%s"
  delivery_mode                      = "full_bundle"
  identity_token_audience_wo         = "%s"
  identity_token_audience_wo_version = %d
  identity_token_ttl                 = %d
%s
}`, destName, region, roleArn, audience, audienceVersion, ttl, customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
}

func testAWSACMSecretsSyncDestinationConfig_networkingRemoved(creds awsACMTestCreds, region, destName string) string {
	return fmt.Sprintf(`
resource "vault_secrets_sync_aws_acm_destination" "test" {
  name                      = "%s"
  region                    = "%s"
  delivery_mode             = "full_bundle"
  certificate_name_template = "%s"
%s%s
}
`, destName, region, updatedAwsAcmCertificateNameTemplate, creds.hcl(),
		customTagsHCL(awsSyncCustomTagsWithOwner(nil)))
}

func testAWSACMSecretsSyncDestinationDestroyed(s *terraformtesting.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_secrets_sync_aws_acm_destination" {
			continue
		}
		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}
		secret, err := client.Logical().Read(syncutilDestinationPath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for aws-acm destination %q: %w", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("aws-acm destination %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func syncutilDestinationPath(name string) string {
	return "sys/sync/destinations/" + awsAcmSyncType + "/" + name
}

// The tests below do not need Vault or AWS.

func newAWSACMTestMeta(t *testing.T, address, versionOverride string) interface{} {
	t.Helper()

	raw := map[string]interface{}{
		consts.FieldAddress: address,
		consts.FieldToken:   "test-token",
	}
	if versionOverride != "" {
		raw[consts.FieldVaultVersionOverride] = versionOverride
	}

	d := schema.TestResourceDataRaw(t,
		map[string]*schema.Schema{
			consts.FieldAddress:              {Type: schema.TypeString, Required: true},
			consts.FieldToken:                {Type: schema.TypeString, Required: true},
			consts.FieldVaultVersionOverride: {Type: schema.TypeString, Optional: true},
			consts.FieldSkipChildToken:       {Type: schema.TypeBool, Optional: true},
		}, raw)

	meta, err := provider.NewProviderMeta(d)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

type awsACMRecordedRequest struct {
	method string
	path   string
	body   map[string]interface{}
}

// newAWSACMMockVault serves just enough of the Vault API for the provider client to be
// created and records every request made to the aws-acm destination path.
func newAWSACMMockVault(t *testing.T) (string, func() []awsACMRecordedRequest) {
	t.Helper()

	var (
		mu       sync.Mutex
		requests []awsACMRecordedRequest
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"id": "test-token", "policies": []string{"root"}, "ttl": 0,
			}})
		case r.URL.Path == "/v1/auth/token/create":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"auth": map[string]interface{}{
				"client_token": "child-token", "policies": []string{"root"}, "lease_duration": 3600,
			}})
		case strings.HasPrefix(r.URL.Path, "/v1/sys/sync/destinations/aws-acm/"):
			rec := awsACMRecordedRequest{method: r.Method, path: r.URL.Path}
			if r.Method == http.MethodPut || r.Method == http.MethodPost {
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, &rec.body)
				mu.Lock()
				requests = append(requests, rec)
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
				return
			}
			mu.Lock()
			requests = append(requests, rec)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
				"connection_details": map[string]interface{}{},
				"options":            map[string]interface{}{},
			}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	})

	config, ln := testutil.TestHTTPServer(t, handler)
	t.Cleanup(func() { _ = ln.Close() })

	return config.Address, func() []awsACMRecordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]awsACMRecordedRequest(nil), requests...)
	}
}

func TestAWSACMSecretsSyncDestination_updateClearsRemovedFields(t *testing.T) {
	addr, recorded := newAWSACMMockVault(t)
	meta := newAWSACMTestMeta(t, addr, "2.3.0+ent")

	r := UpdateSchemaResource(awsAcmSecretsSyncDestinationResource())

	state := &terraform.InstanceState{
		ID: "acm-dest",
		Attributes: map[string]string{
			"id":                        "acm-dest",
			"name":                      "acm-dest",
			"delivery_mode":             "full_bundle",
			"region":                    "us-east-1",
			"role_arn":                  "arn:aws:iam::123456789012:role/test",
			"external_id":               "ext",
			"custom_tags.%":             "1",
			"custom_tags.foo":           "bar",
			"disable_strict_networking": "true",
			"certificate_name_template": "vault/{{ .MountAccessor }}/{{ .CommonName }}",
			"identity_token_ttl":        "3600",
			"allowed_ipv6_addresses.#":  "0",
		},
	}
	ipv4Hash := schema.HashSchema(&schema.Schema{Type: schema.TypeString})("10.0.0.0/8")
	portHash := schema.HashSchema(&schema.Schema{Type: schema.TypeInt})(443)
	state.Attributes["allowed_ipv4_addresses.#"] = "1"
	state.Attributes[fmt.Sprintf("allowed_ipv4_addresses.%d", ipv4Hash)] = "10.0.0.0/8"
	state.Attributes["allowed_ports.#"] = "1"
	state.Attributes[fmt.Sprintf("allowed_ports.%d", portHash)] = "443"

	// the config only keeps the required fields, everything else was removed
	config := terraform.NewResourceConfigRaw(map[string]interface{}{
		"name":          "acm-dest",
		"delivery_mode": "full_bundle",
	})

	diff, err := r.Diff(context.Background(), state, config, meta)
	if err != nil {
		t.Fatal(err)
	}
	if diff == nil {
		t.Fatal("expected a diff")
	}
	d, err := schema.InternalMap(r.Schema).Data(state, diff)
	if err != nil {
		t.Fatal(err)
	}

	if diags := r.UpdateContext(context.Background(), d, meta); diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}

	var write *awsACMRecordedRequest
	for _, req := range recorded() {
		if req.method == http.MethodPut || req.method == http.MethodPost {
			req := req
			write = &req
		}
	}
	if write == nil {
		t.Fatal("no write request was sent to Vault")
	}

	tags, ok := write.body[consts.FieldCustomTags].(map[string]interface{})
	if !ok || len(tags) != 0 {
		t.Errorf("custom_tags: expected an empty map to be sent, got %#v", write.body[consts.FieldCustomTags])
	}
	for _, f := range []string{consts.FieldAllowedIPv4Addresses, consts.FieldAllowedPorts} {
		l, ok := write.body[f].([]interface{})
		if !ok || len(l) != 0 {
			t.Errorf("%s: expected an empty list to be sent, got %#v", f, write.body[f])
		}
	}
	if v, ok := write.body[consts.FieldDisableStrictNetworking]; !ok || v != false {
		t.Errorf("disable_strict_networking: expected false to be sent, got %#v", v)
	}
	for _, f := range []string{consts.FieldRoleArn, consts.FieldExternalID} {
		if v, ok := write.body[f]; !ok || v != "" {
			t.Errorf("%s: expected an empty string to be sent, got %#v", f, v)
		}
	}
	for _, f := range []string{consts.FieldGranularity, consts.FieldSecretNameTemplate} {
		if _, ok := write.body[f]; ok {
			t.Errorf("%s must not be sent to aws-acm destinations", f)
		}
	}
}

func TestAWSACMSecretsSyncDestination_versionGate(t *testing.T) {
	addr, recorded := newAWSACMMockVault(t)
	meta := newAWSACMTestMeta(t, addr, "2.2.0+ent")
	r := awsAcmSecretsSyncDestinationResource()

	d := schema.TestResourceDataRaw(t, r.Schema, map[string]interface{}{
		"name":          "acm-dest",
		"delivery_mode": "full_bundle",
	})

	for name, f := range map[string]func(context.Context, *schema.ResourceData, interface{}) diag.Diagnostics{
		"create": r.CreateContext,
		"update": r.UpdateContext,
	} {
		diags := f(context.Background(), d, meta)
		if !diags.HasError() || !strings.Contains(diags[0].Summary, "feature not enabled on current Vault version") {
			t.Errorf("%s: expected a version error, got %v", name, diags)
		}
	}
	if n := len(recorded()); n != 0 {
		t.Errorf("no request should reach the destination path on unsupported versions, got %d", n)
	}
}

func awsACMConfigValue(t *testing.T, attrs map[string]cty.Value) cty.Value {
	t.Helper()
	typ := awsAcmSecretsSyncDestinationResource().CoreConfigSchema().ImpliedType()
	vals := map[string]cty.Value{}
	for name, at := range typ.AttributeTypes() {
		vals[name] = cty.NullVal(at)
	}
	for k, v := range attrs {
		vals[k] = v
	}
	return cty.ObjectVal(vals)
}

func TestAWSACMSecretsSyncDestination_validateWIFConfig(t *testing.T) {
	str := cty.StringVal
	num := cty.NumberIntVal

	tests := map[string]struct {
		attrs     map[string]cty.Value
		wantAttrs []string
	}{
		"no wif": {attrs: map[string]cty.Value{}},
		"valid": {attrs: map[string]cty.Value{
			consts.FieldRoleArn:                        str("arn"),
			consts.FieldIdentityTokenAudienceWO:        str("aud"),
			consts.FieldIdentityTokenAudienceWOVersion: num(1),
		}},
		"missing role_arn": {
			attrs: map[string]cty.Value{
				consts.FieldIdentityTokenAudienceWO:        str("aud"),
				consts.FieldIdentityTokenAudienceWOVersion: num(1),
			},
			wantAttrs: []string{consts.FieldRoleArn},
		},
		"empty role_arn": {
			attrs: map[string]cty.Value{
				consts.FieldRoleArn:                        str(""),
				consts.FieldIdentityTokenAudienceWO:        str("aud"),
				consts.FieldIdentityTokenAudienceWOVersion: num(1),
			},
			wantAttrs: []string{consts.FieldRoleArn},
		},
		"missing audience version": {
			attrs: map[string]cty.Value{
				consts.FieldRoleArn:                 str("arn"),
				consts.FieldIdentityTokenAudienceWO: str("aud"),
			},
			wantAttrs: []string{consts.FieldIdentityTokenAudienceWOVersion},
		},
		"missing key version": {
			attrs: map[string]cty.Value{
				consts.FieldIdentityTokenKeyWO: str("key"),
			},
			wantAttrs: []string{consts.FieldIdentityTokenKeyWOVersion},
		},
		"unknown role_arn is not validated": {attrs: map[string]cty.Value{
			consts.FieldRoleArn:                        cty.UnknownVal(cty.String),
			consts.FieldIdentityTokenAudienceWO:        str("aud"),
			consts.FieldIdentityTokenAudienceWOVersion: num(1),
		}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resp := &schema.ValidateResourceConfigFuncResponse{}
			validateAwsAcmWIFConfig(context.Background(), schema.ValidateResourceConfigFuncRequest{
				RawConfig: awsACMConfigValue(t, tt.attrs),
			}, resp)

			var got []string
			for _, d := range resp.Diagnostics {
				if len(d.AttributePath) == 0 {
					t.Fatalf("diagnostic has no attribute path: %v", d)
				}
				got = append(got, d.AttributePath[0].(cty.GetAttrStep).Name)
			}
			if strings.Join(got, ",") != strings.Join(tt.wantAttrs, ",") {
				t.Errorf("expected errors on %v, got %v (%v)", tt.wantAttrs, got, resp.Diagnostics)
			}
		})
	}
}

func TestAWSACMSecretsSyncDestination_validateConfig(t *testing.T) {
	r := awsAcmSecretsSyncDestinationResource()

	long := strings.Repeat("a", awsAcmMaxTagKeyLength+1)
	longValue := strings.Repeat("a", awsAcmMaxTagValueLength+1)
	tooMany := map[string]interface{}{}
	for i := 0; i <= awsAcmMaxCustomTags; i++ {
		tooMany[fmt.Sprintf("k%d", i)] = "v"
	}
	maxTags := map[string]interface{}{}
	for i := 0; i < awsAcmMaxCustomTags; i++ {
		maxTags[fmt.Sprintf("k%d", i)] = "v"
	}

	base := func(extra map[string]interface{}) map[string]interface{} {
		m := map[string]interface{}{"name": "acm-dest", "delivery_mode": "full_bundle"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	tests := map[string]struct {
		raw     map[string]interface{}
		wantErr string
	}{
		"minimal":                 {raw: base(nil)},
		"max custom tags":         {raw: base(map[string]interface{}{"custom_tags": maxTags})},
		"too many custom tags":    {raw: base(map[string]interface{}{"custom_tags": tooMany}), wantErr: "too many custom tags"},
		"custom tag key length":   {raw: base(map[string]interface{}{"custom_tags": map[string]interface{}{long: "v"}}), wantErr: "key too long"},
		"custom tag value length": {raw: base(map[string]interface{}{"custom_tags": map[string]interface{}{"k": longValue}}), wantErr: "value too long"},
		"valid template":          {raw: base(map[string]interface{}{"certificate_name_template": "vault-{{ .MountAccessor }}-{{ .CommonName }}"})},
		"invalid template":        {raw: base(map[string]interface{}{"certificate_name_template": "{{ .CommonName "}), wantErr: "not a valid template"},
		"zero identity ttl":       {raw: base(map[string]interface{}{"identity_token_ttl": 0}), wantErr: "expected identity_token_ttl to be at least"},
		"missing delivery mode":   {raw: map[string]interface{}{"name": "acm-dest"}, wantErr: "delivery_mode"},
		"access key with audience": {
			raw:     base(map[string]interface{}{"access_key_id": "AKIA", "identity_token_audience_wo": "aud", "identity_token_audience_wo_version": 1}),
			wantErr: "conflicts with",
		},
		"external id with audience": {
			raw:     base(map[string]interface{}{"external_id": "id", "identity_token_audience_wo": "aud", "identity_token_audience_wo_version": 1}),
			wantErr: "conflicts with",
		},
		"audience version without audience": {
			raw:     base(map[string]interface{}{"identity_token_audience_wo_version": 1}),
			wantErr: "all of",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			diags := r.Validate(terraform.NewResourceConfigRaw(tt.raw))
			if tt.wantErr == "" {
				if diags.HasError() {
					t.Fatalf("unexpected error: %v", diags)
				}
				return
			}
			if !diags.HasError() {
				t.Fatalf("expected an error containing %q", tt.wantErr)
			}
			var msgs []string
			for _, d := range diags {
				msgs = append(msgs, d.Summary+" "+d.Detail)
			}
			if !strings.Contains(strings.Join(msgs, "\n"), tt.wantErr) {
				t.Errorf("expected an error containing %q, got %v", tt.wantErr, msgs)
			}
		})
	}
}
