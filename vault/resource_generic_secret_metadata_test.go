package vault

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceGenericSecretMetadata(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-acc-tests-metadata")
	path := acctest.RandomWithPrefix("foo")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testresourcegenericsecretmetadataInitialconfig(mount, path),
				Check:  testresourcegenericsecretInitialcheck(mount, path),
			},
		},
	})
}

func testresourcegenericsecretmetadataInitialconfig(mount, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "kv"
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
`, mount, path)
}

func testresourcegenericsecretInitialcheck(mount, expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_generic_secret_metadata.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}
		if path != fmt.Sprintf("%s/%s", mount, expectedPath) {
			return fmt.Errorf("unexpected secret path. got=%s want=%s", path, expectedPath)
		}

		client := testProvider.Meta().(*api.Client)
		path = addPrefixToVKVPath(expectedPath, mount, "metadata")
		secret, err := client.Logical().Read(path)

		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		// Test custom_metadata
		wantCustomMetadata := map[string]interface{}{"some_key": "some_value", "blah": "diblah"}
		if got, want := secret.Data[customMetadataKeyName], wantCustomMetadata; !reflect.DeepEqual(got, want) {
			return fmt.Errorf("custom_metadata is not as expected. got=%#v, want=%#v", got, want)
		}

		// Test delete_version_after
		wantDeleteVersionAfter, _ := time.ParseDuration("730h")
		parsedGotDeleteVersionAfter, err := time.ParseDuration(secret.Data[deleteVersionAfterKeyName].(string))
		if err != nil {
			return fmt.Errorf("unable to parse time duration from %v. err=%w", secret.Data[deleteVersionAfterKeyName], err)
		}
		if parsedGotDeleteVersionAfter != wantDeleteVersionAfter {
			return fmt.Errorf("delete_version_after is not as expected. got=%+v, want=%+v", parsedGotDeleteVersionAfter, wantDeleteVersionAfter)
		}

		// test max_versions
		wantMaxVersions := 17
		parsedGotMaxVersions, err := strconv.Atoi(secret.Data[maxVersionsKeyName].(json.Number).String())
		if err != nil {
			return fmt.Errorf("unable to parse int value from %v. err=%w", secret.Data[maxVersionsKeyName], err)
		}
		if parsedGotMaxVersions != wantMaxVersions {
			return fmt.Errorf("max_versions is not as expected. got=%+v, want=%+v", parsedGotMaxVersions, wantMaxVersions)
		}

		return nil
	}
}
