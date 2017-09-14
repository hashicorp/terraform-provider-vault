package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccDataSourceAWSSecret(t *testing.T) {
	mountPath := acctest.RandomWithPrefix("aws")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAWSSecret_config(mountPath),
				Check:  testAccDataSourceAWSSecret_check(mountPath),
			},
		},
	})
}

func testAccDataSourceAWSSecret_config(mountPath string) string {
	accessKey := "AKIAIAXPQ6LSO42THTHQ"
	secretKey := "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"
	return fmt.Sprintf(`
resource "vault_mount" "aws" {
    path = "%s"
    type = "aws"
    description = "Obtain AWS credentials."
}

resource "vault_generic_secret" "root" {
    path = "${vault_mount.aws.path}/config/root"
    data_json = <<EOT
{
    "access_key": "%s",
    "secret_key": "%s",
    "region": "us-east-1"
}
EOT
}

resource "vault_generic_secret" "policy" {
    path = "${vault_mount.aws.path}/roles/test"
    data_json = <<EOT
{
    "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"iam:*\", \"Resource\": \"*\"}]}"
}
EOT
}

data "vault_aws_secret" "test" {
    path = "${vault_mount.aws.path}/creds/test"
    depends_on = ["vault_generic_secret.policy", "vault_generic_secret.root"]
}
`, mountPath, accessKey, secretKey)
}

func testAccDataSourceAWSSecret_check(mountPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["data.vault_generic_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
		}

		iState := resourceState.Primary
		if iState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		wantJson := `{"zip":"zap"}`
		if got, want := iState.Attributes["data_json"], wantJson; got != want {
			return fmt.Errorf("data_json contains %s; want %s", got, want)
		}

		if got, want := iState.Attributes["data.zip"], "zap"; got != want {
			return fmt.Errorf("data[\"zip\"] contains %s; want %s", got, want)
		}

		return nil
	}
}
