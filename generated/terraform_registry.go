package generated

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/generated/datasources/transform/decode"
	"github.com/hashicorp/terraform-provider-vault/generated/datasources/transform/encode"
	"github.com/hashicorp/terraform-provider-vault/generated/resources/transform/alphabet"
	"github.com/hashicorp/terraform-provider-vault/generated/resources/transform/role"
	"github.com/hashicorp/terraform-provider-vault/generated/resources/transform/template"
	"github.com/hashicorp/terraform-provider-vault/generated/resources/transform/transformation"
)

// Please alphabetize.
var DataSourceRegistry = map[string]*schema.Resource{
	"vault_transform_encode": encode.RoleNameDataSource(),
	"vault_transform_decode": decode.RoleNameDataSource(),
}

// Please alphabetize.
var ResourceRegistry = map[string]*schema.Resource{
	"vault_transform_alphabet":       alphabet.NameResource(),
	"vault_transform_role":           role.NameResource(),
	"vault_transform_template":       template.NameResource(),
	"vault_transform_transformation": transformation.NameResource(),
}
