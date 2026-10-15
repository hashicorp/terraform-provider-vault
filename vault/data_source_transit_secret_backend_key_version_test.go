// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func testAccTransitKeyVersionPreCheck(t *testing.T) func() {
	return func() {
		acctestutil.TestAccPreCheck(t)
		acctestutil.TestEntPreCheck(t)
		SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion220)
	}
}

func TestAccDataSourceTransitSecretBackendKeyVersion(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	v1 := "data.vault_transit_secret_backend_key_version.v1"
	v2 := "data.vault_transit_secret_backend_key_version.v2"
	v3 := "data.vault_transit_secret_backend_key_version.v3"
	latest := "data.vault_transit_secret_backend_key_version.latest"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 testAccTransitKeyVersionPreCheck(t),
		CheckDestroy:             testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyVersionConfig(name, backend, "ecdsa-p256", "", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(v1, consts.FieldType, "ecdsa-p256"),
					resource.TestCheckResourceAttr(v1, consts.FieldVersion, "1"),
					resource.TestCheckResourceAttrSet(v1, consts.FieldPublicKey),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsSigning, "true"),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsEncryption, "false"),
					// with no version set, the latest version is read
					resource.TestCheckResourceAttr(latest, consts.FieldType, "ecdsa-p256"),
					resource.TestCheckResourceAttr(latest, consts.FieldVersion, "1"),
				),
			},
			{
				// after rotating to a new algorithm, each version keeps its own type
				Config: testTransitSecretBackendKeyVersionConfig(name, backend, "ml-dsa", `parameter_set = "65"`, 1, 2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(v1, consts.FieldType, "ecdsa-p256"),
					resource.TestCheckResourceAttr(v1, consts.FieldVersion, "1"),
					resource.TestCheckResourceAttr(v2, consts.FieldType, "ml-dsa"),
					resource.TestCheckResourceAttr(v2, consts.FieldVersion, "2"),
					resource.TestCheckResourceAttr(v2, consts.FieldParameterSet, "65"),
					resource.TestCheckResourceAttrSet(v2, consts.FieldPublicKey),
					// the unset version moves from 1 to 2 without any change to the data source's config
					resource.TestCheckResourceAttr(latest, consts.FieldType, "ml-dsa"),
					resource.TestCheckResourceAttr(latest, consts.FieldVersion, "2"),
				),
			},
			{
				// a third version, so "latest" is checked beyond the first rotation
				Config: testTransitSecretBackendKeyVersionConfig(name, backend, "ecdsa-p384", "", 1, 2, 3),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(v1, consts.FieldType, "ecdsa-p256"),
					resource.TestCheckResourceAttr(v2, consts.FieldType, "ml-dsa"),
					resource.TestCheckResourceAttr(v3, consts.FieldType, "ecdsa-p384"),
					resource.TestCheckResourceAttr(v3, consts.FieldVersion, "3"),
					resource.TestCheckResourceAttr(latest, consts.FieldType, "ecdsa-p384"),
					resource.TestCheckResourceAttr(latest, consts.FieldVersion, "3"),
				),
			},
		},
	})
}

func TestAccDataSourceTransitSecretBackendKeyVersion_hybrid(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	v1 := "data.vault_transit_secret_backend_key_version.v1"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 testAccTransitKeyVersionPreCheck(t),
		CheckDestroy:             testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyVersionConfig(name, backend, "hybrid", `
  parameter_set       = "65"
  hybrid_key_type_pqc = "ml-dsa"
  hybrid_key_type_ec  = "ecdsa-p256"`, 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(v1, consts.FieldType, "hybrid"),
					resource.TestCheckResourceAttr(v1, consts.FieldParameterSet, "65"),
					resource.TestCheckResourceAttr(v1, consts.FieldHybridKeyTypePQC, "ml-dsa"),
					resource.TestCheckResourceAttr(v1, consts.FieldHybridKeyTypeEC, "ecdsa-p256"),
					resource.TestCheckResourceAttrSet(v1, consts.FieldPublicKey),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsSigning, "true"),
				),
			},
		},
	})
}

func TestAccDataSourceTransitSecretBackendKeyVersion_symmetric(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	v1 := "data.vault_transit_secret_backend_key_version.v1"
	latest := "data.vault_transit_secret_backend_key_version.latest"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 testAccTransitKeyVersionPreCheck(t),
		CheckDestroy:             testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyVersionConfig(name, backend, "aes256-cbc", "", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(v1, consts.FieldType, "aes256-cbc"),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsEncryption, "true"),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsDecryption, "true"),
					resource.TestCheckResourceAttr(v1, consts.FieldSupportsSigning, "false"),
					// symmetric keys have no public key or parameter set
					resource.TestCheckNoResourceAttr(v1, consts.FieldPublicKey),
					resource.TestCheckNoResourceAttr(v1, consts.FieldParameterSet),
					resource.TestCheckNoResourceAttr(v1, consts.FieldHybridKeyTypeEC),
					resource.TestCheckResourceAttr(latest, consts.FieldType, "aes256-cbc"),
					resource.TestCheckResourceAttr(latest, consts.FieldVersion, "1"),
				),
			},
		},
	})
}

func TestAccDataSourceTransitSecretBackendKeyVersion_missing(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 testAccTransitKeyVersionPreCheck(t),
		CheckDestroy:             testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				// the key only has version 1
				Config:      testTransitSecretBackendKeyVersionConfig(name, backend, "ecdsa-p256", "", 99),
				ExpectError: regexp.MustCompile("no transit key version found"),
			},
			{
				Config: fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

data "vault_transit_secret_backend_key_version" "nokey" {
  backend    = vault_mount.transit.path
  name       = "%s"
  depends_on = [vault_mount.transit]
}
`, backend, name),
				ExpectError: regexp.MustCompile("no transit key version found"),
			},
		},
	})
}

// testTransitSecretBackendKeyVersionConfig returns a transit mount and key of
// the given type, a data source that reads the latest key version (no version
// set), and one data source named v<N> for each requested version.
func testTransitSecretBackendKeyVersionConfig(name, path, keyType, extra string, versions ...int) string {
	config := testTransitSecretBackendKeyConfig_cryptoAgility(name, path, keyType, extra) + `
data "vault_transit_secret_backend_key_version" "latest" {
  backend    = vault_mount.transit.path
  name       = vault_transit_secret_backend_key.test.name
  depends_on = [vault_transit_secret_backend_key.test]
}
`
	for _, v := range versions {
		config += fmt.Sprintf(`
data "vault_transit_secret_backend_key_version" "v%[1]d" {
  backend    = vault_mount.transit.path
  name       = vault_transit_secret_backend_key.test.name
  version    = %[1]d
  depends_on = [vault_transit_secret_backend_key.test]
}
`, v)
	}
	return config
}

// fakeTransitKeyVersionServer records the requests made to a fake Vault that
// serves a transit key with the given latest version. Like Vault, it serves the
// latest version when version 0 is requested.
type fakeTransitKeyVersionServer struct {
	mu       sync.Mutex
	requests []string
}

func (f *fakeTransitKeyVersionServer) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// newFakeTransitKeyVersionMeta returns a provider meta for a fake Vault with a
// transit key "my-key" on mount "transit" that has versions 1..latest. The
// meta reports Vault Enterprise 2.2.0, unless the version is overridden.
func newFakeTransitKeyVersionMeta(t *testing.T, latest int, vaultVersion string) (interface{}, *fakeTransitKeyVersionServer) {
	t.Helper()

	fake := &fakeTransitKeyVersionServer{}

	srv := httptest.NewServer(testTokenLookupHandler(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		fake.requests = append(fake.requests, r.URL.Path)
		fake.mu.Unlock()

		notFound := func() {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{}})
		}

		const keyPath = "/v1/transit/keys/my-key"
		switch {
		case strings.HasPrefix(r.URL.Path, keyPath+"/versions/"):
			var v int
			if _, err := fmt.Sscanf(strings.TrimPrefix(r.URL.Path, keyPath+"/versions/"), "%d", &v); err != nil || v < 0 || v > latest {
				notFound()
				return
			}
			if v == 0 {
				v = latest
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"name": "my-key", "version": v, "type": fmt.Sprintf("type-%d", v),
					"supports_signing": true,
				},
			})
		default:
			notFound()
		}
	}))
	t.Cleanup(srv.Close)

	s := map[string]*schema.Schema{
		consts.FieldAddress:             {Type: schema.TypeString, Required: true},
		"token":                         {Type: schema.TypeString, Required: true},
		consts.FieldSkipGetVaultVersion: {Type: schema.TypeBool, Optional: true},
		consts.FieldVaultVersionOverride: {
			Type:     schema.TypeString,
			Optional: true,
		},
	}
	raw := map[string]interface{}{
		consts.FieldAddress:             srv.URL,
		"token":                         "test-token",
		consts.FieldSkipGetVaultVersion: true,
	}
	if vaultVersion != "" {
		raw[consts.FieldVaultVersionOverride] = vaultVersion
	}

	meta, err := provider.NewProviderMeta(schema.TestResourceDataRaw(t, s, raw))
	if err != nil {
		t.Fatalf("NewProviderMeta: %v", err)
	}

	return meta, fake
}

func readFakeTransitKeyVersion(t *testing.T, meta interface{}, version *int) (*schema.ResourceData, error) {
	t.Helper()

	d := transitSecretBackendKeyVersionDataSource().TestResourceData()
	if err := d.Set(consts.FieldBackend, "transit"); err != nil {
		t.Fatal(err)
	}
	if err := d.Set(consts.FieldName, "my-key"); err != nil {
		t.Fatal(err)
	}
	if version != nil {
		if err := d.Set(consts.FieldVersion, *version); err != nil {
			t.Fatal(err)
		}
	}

	return d, transitSecretBackendKeyVersionDataSourceRead(d, meta)
}

func versionRequests(paths []string) []string {
	var out []string
	for _, p := range paths {
		if strings.HasPrefix(p, "/v1/transit/") {
			out = append(out, strings.TrimPrefix(p, "/v1/transit/keys/my-key"))
		}
	}
	return out
}

// With no version set, version 0 is requested and the server returns the latest
// version.
func TestTransitSecretBackendKeyVersionRead_unsetVersionReadsLatest(t *testing.T) {
	meta, fake := newFakeTransitKeyVersionMeta(t, 3, "2.2.0+ent")

	d, err := readFakeTransitKeyVersion(t, meta, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := d.Get(consts.FieldVersion).(int); got != 3 {
		t.Errorf("expected version 3, got %d", got)
	}
	if got := d.Get(consts.FieldType).(string); got != "type-3" {
		t.Errorf("expected type %q, got %q", "type-3", got)
	}
	if want := "transit/keys/my-key/versions/0"; d.Id() != want {
		t.Errorf("expected id %q, got %q", want, d.Id())
	}

	got := versionRequests(fake.paths())
	want := []string{"/versions/0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("expected requests %q, got %q", want, got)
	}
}

func TestTransitSecretBackendKeyVersionRead_zeroVersionReadsLatest(t *testing.T) {
	meta, fake := newFakeTransitKeyVersionMeta(t, 4, "2.2.0+ent")

	zero := 0
	d, err := readFakeTransitKeyVersion(t, meta, &zero)
	if err != nil {
		t.Fatal(err)
	}

	if got := d.Get(consts.FieldVersion).(int); got != 4 {
		t.Errorf("expected version 4, got %d", got)
	}
	if got := versionRequests(fake.paths()); strings.Join(got, ",") != "/versions/0" {
		t.Errorf("expected only version 0 to be requested, got %q", got)
	}
}

// An explicit version must be read as is, including when it is not the latest.
func TestTransitSecretBackendKeyVersionRead_explicitVersion(t *testing.T) {
	meta, fake := newFakeTransitKeyVersionMeta(t, 3, "2.2.0+ent")

	version := 2
	d, err := readFakeTransitKeyVersion(t, meta, &version)
	if err != nil {
		t.Fatal(err)
	}

	if got := d.Get(consts.FieldVersion).(int); got != 2 {
		t.Errorf("expected version 2, got %d", got)
	}
	if got := d.Get(consts.FieldType).(string); got != "type-2" {
		t.Errorf("expected type %q, got %q", "type-2", got)
	}
	if got := versionRequests(fake.paths()); strings.Join(got, ",") != "/versions/2" {
		t.Errorf("expected only version 2 to be read, got %q", got)
	}
}

func TestTransitSecretBackendKeyVersionRead_versionNotFound(t *testing.T) {
	meta, _ := newFakeTransitKeyVersionMeta(t, 2, "2.2.0+ent")

	version := 5
	_, err := readFakeTransitKeyVersion(t, meta, &version)
	if err == nil || !strings.Contains(err.Error(), "no transit key version found") {
		t.Fatalf("expected a version not found error, got: %v", err)
	}
}

func TestTransitSecretBackendKeyVersionRead_keyNotFound(t *testing.T) {
	meta, _ := newFakeTransitKeyVersionMeta(t, 2, "2.2.0+ent")

	d := transitSecretBackendKeyVersionDataSource().TestResourceData()
	_ = d.Set(consts.FieldBackend, "transit")
	_ = d.Set(consts.FieldName, "other-key")

	err := transitSecretBackendKeyVersionDataSourceRead(d, meta)
	if err == nil || !strings.Contains(err.Error(), "no transit key version found") {
		t.Fatalf("expected a not found error, got: %v", err)
	}
}

func TestTransitSecretBackendKeyVersionRead_unsupportedVersion(t *testing.T) {
	for name, vaultVersion := range map[string]string{
		"older enterprise": "2.1.0+ent",
		"community":        "2.2.0",
	} {
		t.Run(name, func(t *testing.T) {
			meta, fake := newFakeTransitKeyVersionMeta(t, 2, vaultVersion)

			_, err := readFakeTransitKeyVersion(t, meta, nil)
			if err == nil || !strings.Contains(err.Error(), "requires Vault Enterprise 2.2.0") {
				t.Fatalf("expected an unsupported version error, got: %v", err)
			}
			if got := versionRequests(fake.paths()); len(got) != 0 {
				t.Errorf("expected no key requests, got %q", got)
			}
		})
	}
}
