package generated

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/terraform-providers/terraform-provider-vault/generated/resources/transform/role"
	"github.com/terraform-providers/terraform-provider-vault/generated/resources/transform/transformation"
)

var ResourceRegistry = map[string]*schema.Resource{
	"vault_transform_role_name":           role.NameResource(),
	"vault_transform_transformation_name": transformation.NameResource(),
}
