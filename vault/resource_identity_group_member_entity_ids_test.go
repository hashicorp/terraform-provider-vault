package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccIdentityGroupMemberEntityIdsExclusiveEmpty(t *testing.T) {
	devEntity := acctest.RandomWithPrefix("dev-entity")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusiveEmpty(),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs("vault_identity_group_member_entity_ids.member_entity_ids"),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusive(devEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs("vault_identity_group_member_entity_ids.member_entity_ids"),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusiveEmpty(),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs("vault_identity_group_member_entity_ids.member_entity_ids"),
				),
			},
		},
	})
}

// TODO: disabling this test until we can fix it because this test fails very consistently with the following error:
// testing.go:669: Step 1 error: Check failed: Check 3/3 error: vault_identity_group_member_entity_ids.member_entity_ids:
// Attribute 'member_entity_ids.#' expected "1", got "2"
func TestAccIdentityGroupMemberEntityIdsExclusive(t *testing.T) {
	t.Skip(t)

	devEntity := acctest.RandomWithPrefix("dev-entity")
	testEntity := acctest.RandomWithPrefix("test-entity")
	var devEntityTester memberEntityTester
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusive(devEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs("vault_identity_group_member_entity_ids.member_entity_ids"),
					devEntityTester.GetMemberEntity("vault_identity_group_member_entity_ids.member_entity_ids", 1),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigExclusiveUpdate(devEntity, testEntity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupMemberEntityIdsCheckAttrs("vault_identity_group_member_entity_ids.member_entity_ids"),
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.member_entity_ids", "member_entity_ids.#", "2"),
					devEntityTester.CheckMemberEntity("vault_identity_group_member_entity_ids.member_entity_ids"),
				),
			},
		},
	})
}

func TestAccIdentityGroupMemberEntityIdsNonExclusiveEmpty(t *testing.T) {
	devEntity := acctest.RandomWithPrefix("dev-entity")
	testEntity := acctest.RandomWithPrefix("test-entity")
	var devEntityTester memberEntityTester
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveEmpty(devEntity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.dev", "member_entity_ids.#", "1"),
					devEntityTester.GetMemberEntity("vault_identity_group_member_entity_ids.dev", 1),
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.test", "member_entity_ids.#", "0"),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusive(devEntity, testEntity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.dev", "member_entity_ids.#", "1"),
					devEntityTester.CheckMemberEntity("vault_identity_group_member_entity_ids.dev"),
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.test", "member_entity_ids.#", "1"),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveEmpty(devEntity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.dev", "member_entity_ids.#", "1"),
					devEntityTester.CheckMemberEntity("vault_identity_group_member_entity_ids.dev"),
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.test", "member_entity_ids.#", "0"),
				),
			},
		},
	})
}

// TODO: disabling this test until we can fix it because this test fails very consistently with the following error:
// testing.go:669: Step 2 error: Check failed: unexpected member entity id 8e6a0c69-3b7b-d609-a62c-20a8ceac800b
// in group 77065bec-940e-2d0d-ea34-60440e1a4a47
func TestAccIdentityGroupMemberEntityIdsNonExclusive(t *testing.T) {
	t.Skip(t)

	devEntity := acctest.RandomWithPrefix("dev-entity")
	testEntity := acctest.RandomWithPrefix("test-entity")
	fooEntity := acctest.RandomWithPrefix("foo-entity")
	var devEntityTester memberEntityTester
	var testEntityTester memberEntityTester
	var fooEntityTester memberEntityTester
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckidentityGroupMemberEntityIdsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusive(devEntity, testEntity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.dev", "member_entity_ids.#", "1"),
					devEntityTester.GetMemberEntity("vault_identity_group_member_entity_ids.dev", 1),
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.test", "member_entity_ids.#", "1"),
					testEntityTester.GetMemberEntity("vault_identity_group_member_entity_ids.test", 1),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveUpdate(devEntity, fooEntity),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.dev", "member_entity_ids.#", "1"),
					devEntityTester.CheckMemberEntity("vault_identity_group_member_entity_ids.dev"),
					resource.TestCheckResourceAttr("vault_identity_group_member_entity_ids.test", "member_entity_ids.#", "1"),
					testEntityTester.CheckNoMemberEntity("vault_identity_group_member_entity_ids.test"),
					fooEntityTester.GetMemberEntity("vault_identity_group_member_entity_ids.test", 1),
				),
			},
			{
				Config: testAccIdentityGroupMemberEntityIdsConfigNonExclusiveUpdate(devEntity, fooEntity),
				Check:  testAccIdentityGroupMemberEntityIdsCheckLogical("vault_identity_group.group", []*memberEntityTester{&devEntityTester, &fooEntityTester}),
			},
		},
	})
}

type memberEntityTester struct {
	EntityIDKey   string
	EntityIDValue string
}

func (tester *memberEntityTester) GetMemberEntity(resource string, index int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[resource]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		// TestCheckResourceAttr index starts at 1
		count := 1
		for key, element := range instanceState.Attributes {
			if strings.HasPrefix(key, "member_entity_ids") {
				if count == index {
					tester.EntityIDKey = key
					tester.EntityIDValue = element
					return nil
				}

				count++
			}
		}

		return fmt.Errorf("member entity index at %d  not found", index)
	}
}

func (tester *memberEntityTester) CheckMemberEntity(resourceString string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		f := resource.TestCheckResourceAttr(resourceString, tester.EntityIDKey, tester.EntityIDValue)
		return f(s)
	}
}

func (tester *memberEntityTester) CheckNoMemberEntity(resourceString string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		f := resource.TestCheckNoResourceAttr(resourceString, tester.EntityIDKey)
		return f(s)
	}
}

func testAccCheckidentityGroupMemberEntityIdsDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_group_member_entity_ids" {
			continue
		}

		group, err := readIdentityGroup(client, rs.Primary.ID)
		if err != nil {
			return err
		}
		if group == nil {
			continue
		}
		apiMemberEntityIds, err := readIdentityGroupMemberEntityIds(client, rs.Primary.ID)
		if err != nil {
			return err
		}
		length := rs.Primary.Attributes["member_entity_ids.#"]

		if length != "" {
			count, err := strconv.Atoi(length)
			if err != nil {
				return fmt.Errorf("expected %s.# to be a number, got %q", "member_entity_ids.#", length)
			}

			for i := 0; i < count; i++ {
				resourcePolicy := rs.Primary.Attributes["member_entity_ids."+strconv.Itoa(i)]
				if found, _ := util.SliceHasElement(apiMemberEntityIds, resourcePolicy); found {
					return fmt.Errorf("identity group %s still has member entity id %s", rs.Primary.ID, resourcePolicy)
				}
			}
		}
	}
	return nil
}

func testAccIdentityGroupMemberEntityIdsCheckAttrs(resource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[resource]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID

		path := identityGroupIDPath(id)
		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", path)
		}

		attrs := map[string]string{
			"group_id":          "id",
			"group_name":        "name",
			"member_entity_ids": "member_entity_ids",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}
			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}

					for i := 0; i < count; i++ {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								if apiData[i] == stateValue {
									found = true
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, path, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccIdentityGroupMemberEntityIdsCheckLogical(resource string, member_entity_ids []*memberEntityTester) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[resource]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID

		path := identityGroupIDPath(id)
		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", path)
		}

		if resp.Data["member_entity_ids"] == nil && member_entity_ids == nil {
			return nil
		}

		apiMemberEntityIds := resp.Data["member_entity_ids"].([]interface{})

		if len(apiMemberEntityIds) != len(member_entity_ids) {
			return fmt.Errorf("expected group %s to have %d member_entity_ids, has %d", id, len(member_entity_ids), len(apiMemberEntityIds))
		}

		for _, apiMemberEntityIdI := range apiMemberEntityIds {
			apiMemberEntityId := apiMemberEntityIdI.(string)

			found := false
			for _, memberEntityId := range member_entity_ids {
				if apiMemberEntityId == memberEntityId.EntityIDValue {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("unexpected member entity id %s in group %s", apiMemberEntityId, id)
			}
		}

		return nil
	}
}

func testAccIdentityGroupMemberEntityIdsConfigExclusiveEmpty() string {
	return `
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_group_member_entity_ids" "member_entity_ids" {
  	group_id = vault_identity_group.group.id
}`
}

func testAccIdentityGroupMemberEntityIdsConfigExclusive(devEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "member_entity_ids" {
  group_id = vault_identity_group.group.id
  member_entity_ids = [vault_identity_entity.dev.id]
}`, devEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigExclusiveUpdate(devEntityName, testEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_entity" "test" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "member_entity_ids" {
	group_id = vault_identity_group.group.id
	member_entity_ids = [vault_identity_entity.dev.id, vault_identity_entity.test.id]
}`, devEntityName, testEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigNonExclusiveEmpty(devEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "dev" {
	group_id = vault_identity_group.group.id
  	exclusive = false
  	member_entity_ids = [vault_identity_entity.dev_entity.id]
}


resource "vault_identity_group_member_entity_ids" "test" {
	group_id = vault_identity_group.group.id
	exclusive = false
}
`, devEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigNonExclusive(devEntityName, testEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_entity" "test_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "dev" {
	group_id = vault_identity_group.group.id
  	exclusive = false
  	member_entity_ids = [vault_identity_entity.dev_entity.id]
}


resource "vault_identity_group_member_entity_ids" "test" {
	group_id = vault_identity_group.group.id
	exclusive = false
	member_entity_ids = [vault_identity_entity.test_entity.id]
}
`, devEntityName, testEntityName)
}

func testAccIdentityGroupMemberEntityIdsConfigNonExclusiveUpdate(devEntityName, fooEntityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
	external_member_entity_ids = true
}

resource "vault_identity_entity" "dev_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_entity" "foo_entity" {
	name = "%s"
	metadata = {
	  version = "2"
	}
}

resource "vault_identity_group_member_entity_ids" "dev" {
	group_id = vault_identity_group.group.id
	exclusive = false
	member_entity_ids = [vault_identity_entity.dev_entity.id]
}

resource "vault_identity_group_member_entity_ids" "test" {
  	group_id = vault_identity_group.group.id
	exclusive = false
	member_entity_ids = [vault_identity_entity.foo_entity.id]
}
`, devEntityName, fooEntityName)
}
