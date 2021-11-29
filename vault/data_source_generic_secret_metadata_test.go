package vault

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestDataSourceGenericSecretMetadata(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-acctest-kv-metadata")
	path := acctest.RandomWithPrefix("foo")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceSecretMetadataCreateSecretAndMetadata(mount, path),
				Check:  testDataSourceGenericSecretMetadata_check,
			},
		},
		//PreventPostDestroyRefresh: true,
	})
}

func testDataSourceSecretMetadataCreateSecretMount(mount string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv"
  description = "This is an example mount for metadata testing"
  options = {
    version = "2"
  }
}


`, mount)
}

func testDataSourceSecretMetadataCreateSecretAndMetadata(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv"
  description = "This is an example mount for metadata testing"
  options = {
    version = "2"
  }
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.test.path}/%s"
    data_json = jsonencode({blah = "diblah"})
}

resource "vault_generic_secret_metadata" "test" {
   depends_on = [vault_generic_secret.test]
   path = vault_generic_secret.test.path
   custom_metadata = {
		some_key = "some_value"
		blah = "diblah"
   } 
   delete_version_after = "730h"
   max_versions = 17
   cas_required = false
}

data "vault_generic_secret_metadata" "test" {
  path = vault_generic_secret_metadata.test.path
}
`, mount, path)
}

func testDataSourceGenericSecretMetadata_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_generic_secret_metadata.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	// Lease information
	ts, ok := iState.Attributes["lease_start_time"]
	if !ok {
		return fmt.Errorf("lease_start_time not set")
	}

	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return fmt.Errorf("lease_start_time value %q is not in the expected format, err=%s", ts, err)
	}

	elapsed := time.Now().UTC().Unix() - t.Unix()
	// give a reasonable amount of buffer to allow for any system contention.
	maxElapsed := int64(30)
	if elapsed > maxElapsed {
		return fmt.Errorf("elapsed lease_start_time %ds exceeds maximum %ds", elapsed, maxElapsed)
	}

	// Custom Metadata
	wantCustomMetadata := map[string]string{"some_key": "some_value", "blah": "diblah"}
	fmt.Printf("[DEBUG] state Attributes is %+v\n", iState.Attributes)
	var errorString string
	for key, value := range wantCustomMetadata {
		path := fmt.Sprintf("%s.%s", customMetadataKeyName, key)
		fmt.Printf("[DEBUG] checking for %s, value is %s\n", path, value)
		if got := iState.Attributes[path]; got != value {
			errorString += fmt.Sprintf("* key %s is %s. Want %s\n", path, got, value)
		}
	}
	if errorString != "" {
		return fmt.Errorf("Issue while checking datasource secret_metadata: \n%s", errorString)
	}

	// cas required
	casRequired, err := strconv.ParseBool(iState.Attributes[casRequiredKeyName])
	if err != nil {
		return fmt.Errorf("unable to parse bool string %v. err=%w", iState.Attributes[casRequiredKeyName], err)
	}
	if casRequired != false {
		return fmt.Errorf("cas_required value %v is not the expected one %v, err=%s", casRequired, false, err)
	}

	// delete_version_after
	deleteVersionAfter, err := time.ParseDuration(iState.Attributes[deleteVersionAfterKeyName])
	if err != nil {
		return fmt.Errorf("unable to parse time duration %v. err=%w", iState.Attributes[deleteVersionAfterKeyName], err)
	}
	wantDeleteVersionAfter, _ := time.ParseDuration("730h")
	if deleteVersionAfter != wantDeleteVersionAfter {
		return fmt.Errorf("delete_version_after value %q is not the expected one %v, err=%s", deleteVersionAfter, wantDeleteVersionAfter, err)
	}

	// delete_version_after
	maxVersions, err := strconv.Atoi(iState.Attributes[maxVersionsKeyName])
	if err != nil {
		return fmt.Errorf("unable to parse %v as string. err=%w", iState.Attributes[maxVersionsKeyName], err)
	}

	// max_versions
	wantMaxVersions := 17
	if maxVersions != wantMaxVersions {
		return fmt.Errorf("max_versions value %q is not the expected one %v, err=%s", maxVersions, wantMaxVersions, err)
	}

	return nil
}
