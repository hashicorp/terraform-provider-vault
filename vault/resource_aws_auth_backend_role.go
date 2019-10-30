package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	awsAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	awsAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func awsAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		"auth_type": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "iam",
			Description: "The auth type permitted for this role.",
			ForceNew:    true,
		},
		"bound_ami_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Only EC2 instances using this AMI ID will be permitted to log in.",
			Removed:     `Use "bound_ami_ids" as a list.`,
		},
		"bound_ami_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances using this AMI ID will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_account_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Only EC2 instances with this account ID in their identity document will be permitted to log in.",
			Removed:     `Use "bound_account_ids" as a list.`,
		},
		"bound_account_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances with this account ID in their identity document will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_region": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Only EC2 instances in this region will be permitted to log in.",
			Removed:     `Use "bound_regions" as a list.`,
		},
		"bound_regions": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances in this region will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_vpc_id": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Only EC2 instances associated with this VPC ID will be permitted to log in.",
			Removed:       `Use "bound_vpc_ids" as a list.`,
			ConflictsWith: []string{"bound_vpc_ids"},
		},
		"bound_vpc_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances associated with this VPC ID will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_subnet_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Only EC2 instances associated with this subnet ID will be permitted to log in.",
			Removed:     `Use "bound_subnet_ids" as a list.`,
		},
		"bound_subnet_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances associated with this subnet ID will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_iam_role_arn": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Only EC2 instances that match this IAM role ARN will be permitted to log in.",
			Removed:     `Use "bound_iam_role_arns" as a list.`,
		},
		"bound_iam_role_arns": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances that match this IAM role ARN will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_iam_instance_profile_arn": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Only EC2 instances associated with an IAM instance profile ARN that matches this value will be permitted to log in.",
			Removed:     `Use "bound_iam_instance_profile_arns" as a list.`,
		},
		"bound_iam_instance_profile_arns": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances associated with an IAM instance profile ARN that matches this value will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_ec2_instance_id": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances that match this instance ID will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Removed: `Use "bound_ec2_instance_ids".`,
		},
		"bound_ec2_instance_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Only EC2 instances that match this instance ID will be permitted to log in.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"role_tag": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The key of the tag on EC2 instance to use for role tags.",
		},
		"bound_iam_principal_arn": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The IAM principal that must be authenticated using the iam auth method.",
			Removed:     `Use "bound_iam_principal_arns" as a list.`,
		},
		"bound_iam_principal_arns": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "The IAM principal that must be authenticated using the iam auth method.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"inferred_entity_type": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The type of inferencing Vault should do.",
		},
		"inferred_aws_region": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The region to search for the inferred entities in.",
		},
		"resolve_aws_unique_ids": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Whether or not Vault should resolve the bound_iam_principal_arn to an AWS Unique ID. When true, deleting a principal and recreating it with the same name won't automatically grant the new principal the same roles in Vault that the old principal had.",
			Default:     true,
		},
		"allow_instance_migration": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "When true, allows migration of the underlying instance where the client resides. Use with caution.",
			Default:     false,
		},
		"disallow_reauthentication": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "When true, only allows a single token to be granted per instance ID.",
			Default:     false,
		},
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the auth backend to configure.",
			ForceNew:    true,
			Default:     "aws",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},

		// Deprecated
		"ttl": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "The TTL period of tokens issued using this role, provided as the number of seconds.",
			Deprecated:    "use `token_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_ttl"},
		},
		"max_ttl": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "The maximum allowed lifetime of tokens issued using this role, provided as the number of seconds.",
			Deprecated:    "use `token_max_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_max_ttl"},
		},
		"period": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this field. The maximum allowed lifetime of token issued using this role. Specified as a number of seconds.",
			Deprecated:    "use `token_period` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_period"},
		},
		"policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description:   "Policies to be set on tokens issued using this role.",
			Deprecated:    "use `token_policies` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_policies"},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{
		TokenMaxTTLConflict:   []string{"max_ttl"},
		TokenPoliciesConflict: []string{"policies"},
		TokenPeriodConflict:   []string{"period"},
		TokenTTLConflict:      []string{"ttl"},
	})

	return &schema.Resource{
		CustomizeDiff: resourceVaultAwsAuthBackendRoleCustomizeDiff,
		Create:        awsAuthBackendRoleCreate,
		Read:          awsAuthBackendRoleRead,
		Update:        awsAuthBackendRoleUpdate,
		Delete:        awsAuthBackendRoleDelete,
		Exists:        awsAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func resourceVaultAwsAuthBackendRoleCustomizeDiff(diff *schema.ResourceDiff, v interface{}) error {
	if diff.HasChange("resolve_aws_unique_ids") {
		o, n := diff.GetChange("resolve_aws_unique_ids")
		// The resolve_aws_unique_ids field can be updated from false to true
		// but cannot be updated from true to false without recreating.
		if o.(bool) && !n.(bool) {
			if err := diff.ForceNew("resolve_aws_unique_ids"); err != nil {
				return err
			}
		}
	}
	return nil
}

func setSlice(d *schema.ResourceData, tfFieldName, vaultFieldName string, data map[string]interface{}) {
	if ifcValue, ok := d.GetOk(tfFieldName); ok {
		ifcValues := ifcValue.(*schema.Set).List()
		strVals := make([]string, len(ifcValues))
		for i, ifcVal := range ifcValues {
			strVals[i] = ifcVal.(string)
		}
		data[vaultFieldName] = strVals
	}
}

func awsAuthBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role").(string)

	path := awsAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing AWS auth backend role %q", path)

	authType := d.Get("auth_type").(string)
	inferred := d.Get("inferred_entity_type").(string)

	data := map[string]interface{}{
		"auth_type": authType,
	}
	updateTokenFields(d, data, true)

	// Deprecated Fields
	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(int)
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(int)
	}
	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}

	if isEc2(authType, inferred) {

		if v, ok := d.GetOk("bound_ami_id"); ok {
			data["bound_ami_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_ami_ids"); ok {
			setSlice(d, "bound_ami_ids", "bound_ami_id", data)
		}

		if v, ok := data["bound_account_id"].(string); ok {
			d.Set("bound_account_ids", []string{v})
		} else {
			setSlice(d, "bound_account_ids", "bound_account_id", data)
		}

		if v, ok := d.GetOk("bound_region"); ok {
			data["bound_region"] = v.(string)
		} else if _, ok := d.GetOk("bound_regions"); ok {
			setSlice(d, "bound_regions", "bound_region", data)
		}

		if v, ok := d.GetOk("bound_vpc_id"); ok {
			data["bound_vpc_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_vpc_ids"); ok {
			setSlice(d, "bound_vpc_ids", "bound_vpc_id", data)
		}

		if v, ok := d.GetOk("bound_subnet_id"); ok {
			data["bound_subnet_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_subnet_ids"); ok {
			setSlice(d, "bound_subnet_ids", "bound_subnet_id", data)
		}

		if v, ok := d.GetOk("bound_iam_role_arn"); ok {
			data["bound_iam_role_arn"] = v.(string)
		} else if _, ok := d.GetOk("bound_iam_role_arns"); ok {
			setSlice(d, "bound_iam_role_arns", "bound_iam_role_arn", data)
		}

		if v, ok := d.GetOk("bound_iam_instance_profile_arn"); ok {
			data["bound_iam_instance_profile_arn"] = v.(string)
		} else if _, ok := d.GetOk("bound_iam_instance_profile_arns"); ok {
			setSlice(d, "bound_iam_instance_profile_arns", "bound_iam_instance_profile_arn", data)
		}

		if v, ok := d.GetOk("bound_ec2_instance_id"); ok {
			data["bound_ec2_instance_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_ec2_instance_ids"); ok {
			setSlice(d, "bound_ec2_instance_ids", "bound_ec2_instance_id", data)
		}
	}

	if authType == "ec2" {
		if v, ok := d.GetOk("role_tag"); ok {
			data["role_tag"] = v.(string)
		}
		if v, ok := d.GetOk("allow_instance_migration"); ok {
			data["allow_instance_migration"] = v.(bool)
		}
		if v, ok := d.GetOk("disallow_reauthentication"); ok {
			data["disallow_reauthentication"] = v.(bool)
		}
	}
	if authType == "iam" {
		if inferred != "" {
			data["inferred_entity_type"] = inferred
		}

		if v, ok := data["bound_iam_principal_arns"].(string); ok {
			d.Set("bound_iam_principal_arns", []string{v})
		} else {
			setSlice(d, "bound_iam_principal_arns", "bound_iam_principal_arn", data)
		}
		if v, ok := d.GetOk("inferred_aws_region"); ok {
			data["inferred_aws_region"] = v.(string)
		}
		if v, ok := d.GetOkExists("resolve_aws_unique_ids"); ok {
			data["resolve_aws_unique_ids"] = v.(bool)
		}
	}
	d.SetId(path)
	if _, err := client.Logical().Write(path, data); err != nil {
		d.SetId("")
		return fmt.Errorf("error writing AWS auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote AWS auth backend role %q", path)

	return awsAuthBackendRoleRead(d, meta)
}

func awsAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := awsAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for AWS auth backend role: %s", path, err)
	}

	role, err := awsAuthBackendRoleNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for AWS auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading AWS auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading AWS auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read AWS auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] AWS auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	readTokenFields(d, resp)

	// Check if the user is using the deprecated `policies`
	if _, deprecated := d.GetOk("policies"); deprecated {
		// Then we see if `token_policies` was set and unset it
		// Vault will still return `policies`
		if _, ok := d.GetOk("token_policies"); ok {
			d.Set("token_policies", nil)
		}

		if v, ok := resp.Data["policies"]; ok {
			d.Set("policies", v)
		}
	}

	// Check if the user is using the deprecated `period`
	if _, deprecated := d.GetOk("period"); deprecated {
		// Then we see if `token_period` was set and unset it
		// Vault will still return `period`
		if _, ok := d.GetOk("token_period"); ok {
			d.Set("token_period", nil)
		}

		if v, ok := resp.Data["period"]; ok {
			d.Set("period", v)
		}
	}

	// Check if the user is using the deprecated `ttl`
	if _, deprecated := d.GetOk("ttl"); deprecated {
		// Then we see if `token_ttl` was set and unset it
		// Vault will still return `ttl`
		if _, ok := d.GetOk("token_ttl"); ok {
			d.Set("token_ttl", nil)
		}

		if v, ok := resp.Data["ttl"]; ok {
			d.Set("ttl", v)
		}

	}

	// Check if the user is using the deprecated `max_ttl`
	if _, deprecated := d.GetOk("max_ttl"); deprecated {
		// Then we see if `token_max_ttl` was set and unset it
		// Vault will still return `max_ttl`
		if _, ok := d.GetOk("token_max_ttl"); ok {
			d.Set("token_max_ttl", nil)
		}

		if v, ok := resp.Data["max_ttl"]; ok {
			d.Set("max_ttl", v)
		}
	}

	d.Set("backend", backend)
	d.Set("role", role)
	d.Set("auth_type", resp.Data["auth_type"])

	if v, ok := resp.Data["bound_account_id"].(string); ok {
		d.Set("bound_account_ids", []string{v})
	} else {
		d.Set("bound_account_ids", resp.Data["bound_account_id"])
	}

	if v, ok := resp.Data["bound_ami_id"].(string); ok {
		d.Set("bound_ami_ids", []string{v})
	} else {
		d.Set("bound_ami_ids", resp.Data["bound_ami_id"])
	}

	if v, ok := resp.Data["bound_ec2_instance_id"].(string); ok {
		d.Set("bound_ec2_instance_ids", []string{v})
	} else {
		d.Set("bound_ec2_instance_ids", resp.Data["bound_ec2_instance_id"])
	}

	if v, ok := resp.Data["bound_iam_instance_profile_arn"].(string); ok {
		d.Set("bound_iam_instance_profile_arns", []string{v})
	} else {
		d.Set("bound_iam_instance_profile_arns", resp.Data["bound_iam_instance_profile_arn"])
	}

	if v, ok := resp.Data["bound_iam_role_arn"].(string); ok {
		d.Set("bound_iam_role_arns", []string{v})
	} else {
		d.Set("bound_iam_role_arns", resp.Data["bound_iam_role_arn"])
	}

	if v, ok := resp.Data["bound_subnet_id"].(string); ok {
		d.Set("bound_subnet_ids", []string{v})
	} else {
		d.Set("bound_subnet_ids", resp.Data["bound_subnet_id"])
	}

	if v, ok := resp.Data["bound_vpc_id"].(string); ok {
		d.Set("bound_vpc_ids", []string{v})
	} else {
		d.Set("bound_vpc_ids", resp.Data["bound_vpc_id"])
	}

	if v, ok := resp.Data["bound_region"].(string); ok {
		d.Set("bound_regions", []string{v})
	} else {
		d.Set("bound_regions", resp.Data["bound_region"])
	}

	if v, ok := resp.Data["bound_iam_principal_arn"].(string); ok {
		d.Set("bound_iam_principal_arns", []string{v})
	} else {
		d.Set("bound_iam_principal_arns", resp.Data["bound_iam_principal_arn"])
	}

	d.Set("role_tag", resp.Data["role_tag"])
	d.Set("inferred_entity_type", resp.Data["inferred_entity_type"])
	d.Set("inferred_aws_region", resp.Data["inferred_aws_region"])
	d.Set("resolve_aws_unique_ids", resp.Data["resolve_aws_unique_ids"])
	d.Set("allow_instance_migration", resp.Data["allow_instance_migration"])
	d.Set("disallow_reauthentication", resp.Data["disallow_reauthentication"])

	return nil
}

func awsAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating AWS auth backend role %q", path)

	authType := d.Get("auth_type").(string)
	inferred := d.Get("inferred_entity_type").(string)

	data := map[string]interface{}{}
	updateTokenFields(d, data, false)

	// Deprecated Fields
	if d.HasChange("ttl") {
		data["ttl"] = d.Get("ttl").(int)
	}
	if d.HasChange("max_ttl") {
		data["max_ttl"] = d.Get("max_ttl").(int)
	}
	if d.HasChange("period") {
		data["period"] = d.Get("period").(int)
	}
	if d.HasChange("policies") {
		data["policies"] = d.Get("policies").(*schema.Set).List()
	}

	if isEc2(authType, inferred) {

		if v, ok := d.GetOk("bound_ami_id"); ok {
			data["bound_ami_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_ami_ids"); ok {
			setSlice(d, "bound_ami_ids", "bound_ami_id", data)
		}

		if v, ok := d.GetOk("bound_account_id"); ok {
			data["bound_account_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_account_ids"); ok {
			setSlice(d, "bound_account_ids", "bound_account_id", data)
		}

		if v, ok := d.GetOk("bound_region"); ok {
			data["bound_region"] = v.(string)
		} else if _, ok := d.GetOk("bound_regions"); ok {
			setSlice(d, "bound_regions", "bound_region", data)
		}

		if v, ok := d.GetOk("bound_vpc_id"); ok {
			data["bound_vpc_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_vpc_ids"); ok {
			setSlice(d, "bound_vpc_ids", "bound_vpc_id", data)
		}

		if v, ok := d.GetOk("bound_subnet_id"); ok {
			data["bound_subnet_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_subnet_ids"); ok {
			setSlice(d, "bound_subnet_ids", "bound_subnet_id", data)
		}

		if v, ok := d.GetOk("bound_iam_role_arn"); ok {
			data["bound_iam_role_arn"] = v.(string)
		} else if _, ok := d.GetOk("bound_iam_role_arns"); ok {
			setSlice(d, "bound_iam_role_arns", "bound_iam_role_arn", data)
		}

		if v, ok := d.GetOk("bound_iam_instance_profile_arn"); ok {
			data["bound_iam_instance_profile_arn"] = v.(string)
		} else if _, ok := d.GetOk("bound_iam_instance_profile_arns"); ok {
			setSlice(d, "bound_iam_instance_profile_arns", "bound_iam_instance_profile_arn", data)
		}

		if v, ok := d.GetOk("bound_ec2_instance_id"); ok {
			data["bound_ec2_instance_id"] = v.(string)
		} else if _, ok := d.GetOk("bound_ec2_instance_ids"); ok {
			setSlice(d, "bound_ec2_instance_ids", "bound_ec2_instance_id", data)
		}
	}

	if authType == "ec2" {
		if v, ok := d.GetOk("role_tag"); ok {
			data["role_tag"] = v.(string)
		}
		if v, ok := d.GetOk("allow_instance_migration"); ok {
			data["allow_instance_migration"] = v.(bool)
		}
		if v, ok := d.GetOk("disallow_reauthentication"); ok {
			data["disallow_reauthentication"] = v.(bool)
		}
	}

	if authType == "iam" {
		if inferred != "" {
			data["inferred_entity_type"] = inferred
		}

		if v, ok := d.GetOk("bound_iam_principal_arn"); ok {
			data["bound_iam_principal_arn"] = v.(string)
		} else if _, ok := d.GetOk("bound_iam_principal_arns"); ok {
			setSlice(d, "bound_iam_principal_arns", "bound_iam_principal_arn", data)
		}

		if v, ok := d.GetOk("inferred_aws_region"); ok {
			data["inferred_aws_region"] = v.(string)
		}

		if v, ok := d.GetOkExists("resolve_aws_unique_ids"); ok {
			data["resolve_aws_unique_ids"] = v.(bool)
		}
	}

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating AWS auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated AWS auth backend role %q", path)

	return awsAuthBackendRoleRead(d, meta)
}

func isEc2(authType, inferred string) bool {
	isEc2InstanceWithIam := inferred == "ec2_instance" && authType == "iam"
	return authType == "ec2" || isEc2InstanceWithIam
}

func awsAuthBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting AWS auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting AWS auth backend role %q", path)
	}
	log.Printf("[DEBUG] Deleted AWS auth backend role %q", path)

	return nil
}

func awsAuthBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if AWS auth backend role %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if AWS auth backend role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if AWS auth backend role %q exists", path)

	return resp != nil, nil
}

func awsAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func awsAuthBackendRoleNameFromPath(path string) (string, error) {
	if !awsAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := awsAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func awsAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !awsAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := awsAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
