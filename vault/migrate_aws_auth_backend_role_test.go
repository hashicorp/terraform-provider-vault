package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform/terraform"
)

func TestMigrateawsAuthBackendRoleResourceStateV0toV1(t *testing.T) {
	oldAttributes := map[string]string{
		"bound_ami_id":                   "ami-1234",
		"bound_account_id":               "account-123",
		"bound_iam_instance_profile_arn": "arn::123",
		"bound_iam_principal_arn":        "arn::234",
		"bound_iam_role_arn":             "arn::456",
		"bound_region":                   "us-west-1",
		"bound_subnet_id":                "sub-abc",
		"bound_vpc_id":                   "vpc-1234",
	}

	newState, err := migrateawsAuthBackendRoleResourceStateV0toV1(&terraform.InstanceState{
		ID:         "nonempty",
		Attributes: oldAttributes,
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedAttributes := map[string]string{
		"bound_ami_id.#":                   "1",
		"bound_ami_id.0":                   "ami-1234",
		"bound_account_id.#":               "1",
		"bound_account_id.0":               "account-123",
		"bound_iam_instance_profile_arn.#": "1",
		"bound_iam_instance_profile_arn.0": "arn::123",
		"bound_iam_principal_arn.#":        "1",
		"bound_iam_principal_arn.0":        "arn::234",
		"bound_iam_role_arn.#":             "1",
		"bound_iam_role_arn.0":             "arn::456",
		"bound_region.#":                   "1",
		"bound_region.0":                   "us-west-1",
		"bound_subnet_id.#":                "1",
		"bound_subnet_id.0":                "sub-abc",
		"bound_vpc_id.#":                   "1",
		"bound_vpc_id.0":                   "vpc-1234",
	}

	if !reflect.DeepEqual(newState.Attributes, expectedAttributes) {
		t.Fatalf("Expected attributes:%#v Given:%#v", expectedAttributes, newState.Attributes)
	}
}
