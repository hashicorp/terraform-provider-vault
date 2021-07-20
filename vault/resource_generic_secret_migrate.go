package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func resourceGenericSecretMigrateState(v int, s *terraform.InstanceState, meta interface{}) (*terraform.InstanceState, error) {
	if s.Empty() {
		log.Println("[DEBUG] Empty InstanceState; nothing to migrate.")
		return s, nil
	}

	switch v {
	case 0:
		log.Println("[INFO] Found Vault Generic Secret state v0; migrating to v1")
		s, err := migrateGenericSecretStateV0toV1(s)
		return s, err
	default:
		return s, fmt.Errorf("unexpected schema version: %d", v)
	}
}

func migrateGenericSecretStateV0toV1(s *terraform.InstanceState) (*terraform.InstanceState, error) {
	log.Printf("[DEBUG] Attributes before migration: %#v", s.Attributes)

	disabledRead := s.Attributes["allow_read"] != "true"
	if disabledRead {
		s.Attributes["disable_read"] = "true"
	}

	log.Printf("[DEBUG] Attributes after migration: %#v:", s.Attributes)
	return s, nil
}
