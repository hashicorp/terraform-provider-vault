package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func resourceAuthBackendMigrateState(v int, s *terraform.InstanceState, meta interface{}) (*terraform.InstanceState, error) {
	if s.Empty() {
		log.Println("[DEBUG] Empty InstanceState; nothing to migrate.")
		return s, nil
	}

	switch v {
	case 0:
		log.Println("[INFO] Found Vault Auth Backend state v0; migrating to v1")
		s, err := migrateAuthBackendStateV0toV1(s)
		return s, err
	default:
		return s, fmt.Errorf("unexpected schema version: %d", v)
	}
}

func migrateAuthBackendStateV0toV1(s *terraform.InstanceState) (*terraform.InstanceState, error) {
	log.Printf("[DEBUG] Attributes before migration: %#v", s.Attributes)

	s.Attributes["type"] = s.ID
	if s.Attributes["path"] == "" {
		s.Attributes["path"] = s.Attributes["type"]
	}
	s.ID = strings.TrimSuffix(s.Attributes["path"], "/")

	log.Printf("[DEBUG] Attributes after migration: %#v:", s.Attributes)
	return s, nil
}
