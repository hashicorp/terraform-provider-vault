// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func awsSecretBackendRoleResource(name string) *schema.Resource {
	return &schema.Resource{
		Create: awsSecretBackendRoleWrite,
		Read:   provider.ReadWrapper(awsSecretBackendRoleRead),
		Update: awsSecretBackendRoleWrite,
		Delete: awsSecretBackendRoleDelete,
		Exists: awsSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the AWS Secret Backend the role belongs to.",
			},
			"policy_arns": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "ARN for an existing IAM policy the role should use.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"policy_document": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "IAM policy the role should use in JSON format.",
				ValidateFunc:     ValidateDataJSONFunc(name),
				DiffSuppressFunc: util.JsonDiffSuppress,
			},
			"credential_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Role credential type.",
			},
			"role_arns": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:    true,
				ForceNew:    true,
				Description: "ARNs of AWS roles allowed to be assumed. Only valid when credential_type is 'assumed_role'",
			},
			"iam_groups": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:    true,
				Description: "A list of IAM group names. IAM users generated against this vault role will be added to these IAM Groups. For a credential type of assumed_role or federation_token, the policies sent to the corresponding AWS call (sts:AssumeRole or sts:GetFederation) will be the policies from each group in iam_groups combined with the policy_document and policy_arns parameters.",
			},
			"iam_tags": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "A map of strings representing key/value pairs used as tags for any IAM user created by this role.",
			},
			"default_sts_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The default TTL in seconds for STS credentials. When a TTL is not specified when STS credentials are requested, and a default TTL is specified on the role, then this default TTL will be used. Valid only when credential_type is one of assumed_role or federation_token.",
			},
			"max_sts_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "The max allowed TTL in seconds for STS credentials (credentials TTL are capped to max_sts_ttl). Valid only when credential_type is one of assumed_role or federation_token.",
			},
			"permissions_boundary_arn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The ARN of the AWS Permissions Boundary to attach to IAM users created in the role. Valid only when credential_type is iam_user. If not specified, then no permissions boundary policy will be attached.",
			},
			"user_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The path for the user name. Valid only when credential_type is iam_user. Default is /",
			},
		},
	}
}

func awsSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	policyARNsIfc, ok := d.GetOk("policy_arns")
	var policyARNs []interface{}
	if ok {
		policyARNs = policyARNsIfc.(*schema.Set).List()
	}

	policyDocument := d.Get("policy_document")

	roleARNs := d.Get("role_arns").(*schema.Set).List()

	iamGroups := d.Get("iam_groups").(*schema.Set).List()

	iamTags := d.Get("iam_tags")

	if policyDocument == "" && len(policyARNs) == 0 && len(roleARNs) == 0 && len(iamGroups) == 0 {
		return fmt.Errorf("at least one of: `policy_document`, `policy_arns`, `role_arns` or `iam_groups` must be set")
	}

	credentialType := d.Get("credential_type").(string)

	userPath := d.Get("user_path").(string)

	permissionBoundaryArn := d.Get("permissions_boundary_arn").(string)

	data := map[string]interface{}{
		"credential_type": credentialType,
	}
	if d.HasChange("permissions_boundary_arn") {
		if credentialType == "iam_user" {
			data["permissions_boundary_arn"] = permissionBoundaryArn
		} else {
			return fmt.Errorf("permissions_boundary_arn is only valid when credential_type is iam_user")
		}
	}
	if d.HasChange("policy_document") {
		data["policy_document"] = policyDocument
	}
	if d.HasChange("policy_arns") {
		data["policy_arns"] = policyARNs
	}
	if d.HasChange("role_arns") {
		data["role_arns"] = roleARNs
	}
	if d.HasChange("iam_groups") {
		data["iam_groups"] = iamGroups
	}
	if d.HasChange("iam_tags") {
		data["iam_tags"] = iamTags
	}
	if d.HasChange("user_path") {
		if credentialType == "iam_user" {
			data["user_path"] = userPath
		} else {
			return fmt.Errorf("user_path is only valid when credential_type is iam_user")
		}
	}

	defaultStsTTL, defaultStsTTLOk := d.GetOk("default_sts_ttl")
	maxStsTTL, maxStsTTLOk := d.GetOk("max_sts_ttl")
	if credentialType == "assumed_role" || credentialType == "federation_token" {
		if defaultStsTTLOk {
			data["default_sts_ttl"] = strconv.Itoa(defaultStsTTL.(int))
		}
		if maxStsTTLOk {
			data["max_sts_ttl"] = strconv.Itoa(maxStsTTL.(int))
		}
	} else {
		if defaultStsTTLOk {
			return fmt.Errorf("default_sts_ttl is only valid when credential_type is assumed_role or federation_token")
		}
		if maxStsTTLOk {
			return fmt.Errorf("max_sts_ttl is only valid when credential_type is assumed_role or federation_token")
		}
	}

	log.Printf("[DEBUG] Creating role %q on AWS backend %q", name, backend)
	_, err := client.Logical().Write(backend+"/roles/"+name, data)
	if err != nil {
		return fmt.Errorf("error creating role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on AWS backend %q", name, backend)

	d.SetId(backend + "/roles/" + name)
	return awsSecretBackendRoleRead(d, meta)
}

func awsSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	pathPieces := strings.Split(path, "/")
	if len(pathPieces) < 3 || pathPieces[len(pathPieces)-2] != "roles" {
		return fmt.Errorf("invalid id %q; must be {backend}/roles/{name}", path)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if _, ok := d.GetOk("policy_document"); ok {
		d.Set("policy_document", secret.Data["policy_document"])
	} else if v, ok := secret.Data["policy_document"]; ok {
		d.Set("policy_document", v)
	}

	if _, ok := d.GetOk("policy_arns"); ok {
		d.Set("policy_arns", secret.Data["policy_arns"])
	} else if v, ok := secret.Data["policy_arns"]; ok {
		d.Set("policy_arns", v)
	}

	d.Set("credential_type", secret.Data["credential_type"])
	d.Set("role_arns", secret.Data["role_arns"])
	if v, ok := secret.Data["default_sts_ttl"]; ok {
		d.Set("default_sts_ttl", v)
	}
	if v, ok := secret.Data["max_sts_ttl"]; ok {
		d.Set("max_sts_ttl", v)
	}
	if v, ok := secret.Data["iam_groups"]; ok {
		d.Set("iam_groups", v)
	}
	if v, ok := secret.Data["permissions_boundary_arn"]; ok {
		d.Set("permissions_boundary_arn", v)
	}
	if v, ok := secret.Data["user_path"]; ok {
		d.Set("user_path", v)
	}

	d.Set("backend", strings.Join(pathPieces[:len(pathPieces)-2], "/"))
	d.Set("name", pathPieces[len(pathPieces)-1])
	return nil
}

func awsSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func awsSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}
