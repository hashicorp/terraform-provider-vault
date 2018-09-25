package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/terraform"
)

func awsAuthBackendRoleResourceMigrateState(v int, is *terraform.InstanceState, meta interface{}) (*terraform.InstanceState, error) {
	switch v {
	case 0:
		log.Println("[INFO] Found AWS Auth Backend Role State v0; migrating to v1")
		return migrateawsAuthBackendRoleResourceStateV0toV1(is)
	default:
		return is, fmt.Errorf("Unexpected schema version: %d", v)
	}
}

func migrateawsAuthBackendRoleResourceStateV0toV1(is *terraform.InstanceState) (*terraform.InstanceState, error) {
	if is.Empty() {
		log.Println("[DEBUG] Empty InstanceState; nothing to migrate.")
		return is, nil
	}
	log.Printf("[DEBUG] AWS Auth Backend Role Attributes before migration: %#v", is.Attributes)

	convertSingleAttributeToList(is, "bound_account_id")
	convertSingleAttributeToList(is, "bound_ami_id")
	convertSingleAttributeToList(is, "bound_iam_instance_profile_arn")
	convertSingleAttributeToList(is, "bound_iam_principal_arn")
	convertSingleAttributeToList(is, "bound_iam_role_arn")
	convertSingleAttributeToList(is, "bound_region")
	convertSingleAttributeToList(is, "bound_subnet_id")
	convertSingleAttributeToList(is, "bound_vpc_id")

	return is, nil
}

func convertSingleAttributeToList(is *terraform.InstanceState, attr string) {
	if v, ok := is.Attributes[attr]; ok {
		is.Attributes[attr+".#"] = "1"
		is.Attributes[attr+".0"] = v
		delete(is.Attributes, attr)
	}
}
