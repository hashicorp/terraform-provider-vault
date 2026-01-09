// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

var oktaAuthType = "okta"

const (
	fieldBypassOktaMFA = "bypass_okta_mfa"
	fieldUser          = "user"
	fieldGroup         = "group"
	fieldGroups        = "groups"
)

func oktaAuthBackendResource() *schema.Resource {
	tokenFieldsConfig := &addTokenFieldsConfig{}

	fields := map[string]*schema.Schema{
		consts.FieldPath: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "path to mount the backend",
			Default:     oktaAuthType,
			ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
				value := v.(string)
				if strings.HasSuffix(value, "/") {
					errs = append(errs, errors.New("cannot write to a path ending in '/'"))
				}
				return
			},
		},

		consts.FieldDescription: {
			Type:        schema.TypeString,
			Required:    false,
			Optional:    true,
			Description: "The description of the auth backend",
		},

		consts.FieldOrgName: {
			Type:         schema.TypeString,
			Optional:     true,
			Computed:     true,
			Description:  "The Okta organization. This will be the first part of the url https://XXX.okta.com.",
			ExactlyOneOf: []string{consts.FieldOrgName, consts.FieldOrganization},
		},

		consts.FieldOrganization: {
			Type:         schema.TypeString,
			Optional:     true,
			Computed:     true,
			Description:  "The Okta organization. This will be the first part of the url https://XXX.okta.com. Use org_name instead.",
			Deprecated:   "Use org_name instead",
			ExactlyOneOf: []string{consts.FieldOrgName, consts.FieldOrganization},
		},

		consts.FieldAPIToken: {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "The Okta API token. This is required to query Okta for user group membership. If this is not supplied only locally configured groups will be enabled.",
			Sensitive:     true,
			ConflictsWith: []string{consts.FieldToken, consts.FieldAPITokenWO},
		},

		consts.FieldAPITokenWO: {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Write-only Okta API token. This is required to query Okta for user group membership. If this is not supplied only locally configured groups will be enabled.",
			Sensitive:     true,
			WriteOnly:     true,
			ConflictsWith: []string{consts.FieldToken, consts.FieldAPIToken},
			RequiredWith:  []string{consts.FieldAPITokenWOVersion},
		},

		consts.FieldAPITokenWOVersion: {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "Version counter for write-only api_token.",
			RequiredWith: []string{consts.FieldAPITokenWO},
		},

		consts.FieldToken: {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "The Okta API token. This is required to query Okta for user group membership. If this is not supplied only locally configured groups will be enabled. Use api_token instead.",
			Sensitive:     true,
			Deprecated:    "Use api_token instead",
			ConflictsWith: []string{consts.FieldAPIToken, consts.FieldAPITokenWO},
		},

		consts.FieldBaseURL: {
			Type:        schema.TypeString,
			Required:    false,
			Optional:    true,
			Description: "The Okta url. Examples: oktapreview.com, okta.com (default)",
		},

		fieldBypassOktaMFA: {
			Type:        schema.TypeBool,
			Required:    false,
			Optional:    true,
			Description: "When true, requests by Okta for a MFA check will be bypassed. This also disallows certain status checks on the account, such as whether the password is expired.",
		},

		fieldGroup: {
			Type:       schema.TypeSet,
			Required:   false,
			Optional:   true,
			Computed:   true,
			ConfigMode: schema.SchemaConfigModeAttr,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					consts.FieldGroupName: {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Name of the Okta group",
						ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
							value := v.(string)
							// No comma as it'll become part of a comma separate list
							if strings.Contains(value, ",") {
								errs = append(errs, errors.New("group cannot contain ','"))
							}
							return
						},
					},

					consts.FieldPolicies: {
						Type:        schema.TypeSet,
						Required:    true,
						Description: "Policies to associate with this group",
						Elem: &schema.Schema{
							Type: schema.TypeString,
							ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
								value := v.(string)
								// No comma as it'll become part of a comma separate list
								if strings.Contains(value, ",") {
									errs = append(errs, errors.New("policy cannot contain ','"))
								}
								return
							},
						},
						Set: schema.HashString,
					},
				},
			},
			Set: resourceOktaGroupHash,
		},

		fieldUser: {
			Type:       schema.TypeSet,
			Required:   false,
			Optional:   true,
			Computed:   true,
			ConfigMode: schema.SchemaConfigModeAttr,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					fieldGroups: {
						Type:        schema.TypeSet,
						Optional:    true,
						Description: "Groups within the Okta auth backend to associate with this user",
						Elem: &schema.Schema{
							Type: schema.TypeString,
							ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
								value := v.(string)
								// No comma as it'll become part of a comma separate list
								if strings.Contains(value, ",") {
									errs = append(errs, errors.New("group cannot contain ','"))
								}
								return
							},
						},
						Set: schema.HashString,
					},

					consts.FieldUsername: {
						Type:        schema.TypeString,
						Required:    true,
						Description: "Name of the user within Okta",
						ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
							value := v.(string)
							if strings.Contains(value, "/") {
								errs = append(errs, errors.New("user cannot contain '/'"))
							}
							return
						},
					},

					consts.FieldPolicies: {
						Type:        schema.TypeSet,
						Required:    false,
						Optional:    true,
						Description: "Policies to associate with this user",
						Elem: &schema.Schema{
							Type: schema.TypeString,
							ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
								value := v.(string)
								// No comma as it'll become part of a comma separate list
								if strings.Contains(value, ",") {
									errs = append(errs, errors.New("policy cannot contain ','"))
								}
								return
							},
						},
						Set: schema.HashString,
					},
				},
			},
			Set: resourceOktaUserHash,
		},

		consts.FieldAccessor: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The mount accessor related to the auth mount.",
		},

		consts.FieldTune: authMountTuneSchema(),
	}

	addTokenFields(fields, tokenFieldsConfig)

	return provider.MustAddMountMigrationSchema(&schema.Resource{
		CreateContext: oktaAuthBackendWrite,
		DeleteContext: oktaAuthBackendDelete,
		ReadContext:   provider.ReadContextWrapper(oktaAuthBackendRead),
		UpdateContext: oktaAuthBackendUpdate,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		CustomizeDiff: getMountCustomizeDiffFunc(consts.FieldPath),
		Schema:        fields,
	}, false)
}

func normalizeOktaTTL(i interface{}) string {
	s, err := parseDurationSeconds(i)
	if err != nil {
		// validateOktaTTL should prevent ever getting here
		return i.(string)
	}
	return s
}

func validateOktaTTL(i interface{}, k string) ([]string, []error) {
	var values []string
	var errors []error
	_, err := parseDurationSeconds(i)
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid value for %q, could not parse %q", k, i))
	}
	return values, errors
}

func parseDurationSeconds(i interface{}) (string, error) {
	d, err := parseutil.ParseDurationSecond(i)
	if err != nil {
		log.Printf("[ERROR] Could not parse %v to seconds, error: %s", i, err)
		return "", err
	}
	return strconv.Itoa(int(d.Seconds())), nil
}

// getOrgName returns the organization name from config, preferring the new field name
func getOrgName(d *schema.ResourceData) string {
	rawConfig := d.GetRawConfig()
	if !rawConfig.IsNull() {
		// Check config for org_name first
		orgNameAttr := rawConfig.GetAttr(consts.FieldOrgName)
		if !orgNameAttr.IsNull() {
			return orgNameAttr.AsString()
		}
		// Fallback to deprecated organization field in config
		organizationAttr := rawConfig.GetAttr(consts.FieldOrganization)
		if !organizationAttr.IsNull() {
			return organizationAttr.AsString()
		}
	}
	return ""
}

func oktaAuthBackendWrite(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	authType := oktaAuthType
	desc := d.Get(consts.FieldDescription).(string)
	path := d.Get(consts.FieldPath).(string)

	log.Printf("[DEBUG] Writing auth %s to Vault", authType)

	err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
		Type:        authType,
		Description: desc,
	})
	if err != nil {
		return diag.Errorf("error writing to Vault: %s", err)
	}
	log.Printf("[INFO] Enabled okta auth backend at '%s'", path)

	d.SetId(path)
	return oktaAuthBackendUpdate(ctx, d, meta)
}

func oktaAuthBackendDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	err := client.Sys().DisableAuthWithContext(ctx, path)
	if err != nil {
		return diag.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func oktaAuthBackendRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()
	log.Printf("[DEBUG] Reading auth %s from Vault", path)

	mount, err := mountutil.GetAuthMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found, removing from state.", path)
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldPath, path); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(consts.FieldAccessor, mount.Accessor); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldDescription, mount.Description); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading groups for mount %s from Vault", path)
	groups, err := oktaReadAllGroups(client, path)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(fieldGroup, groups); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Reading users for mount %s from Vault", path)
	users, err := oktaReadAllUsers(client, path)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(fieldUser, users); err != nil {
		return diag.FromErr(err)
	}

	if err := oktaReadAuthConfig(client, path, d); err != nil {
		return diag.FromErr(err)
	}

	// Tune block support
	log.Printf("[DEBUG] Reading okta auth tune from %q", path+"/tune")
	rawTune, err := authMountTuneGet(ctx, client, "auth/"+path)
	if err != nil {
		return diag.FromErr(err)
	}
	input, err := retrieveMountConfigInput(d)
	if err != nil {
		return diag.FromErr(err)
	}
	mergedTune := mergeAuthMethodTune(rawTune, input)
	if err := d.Set(consts.FieldTune, mergedTune); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path %q to state: %s", path+"/tune", err)
		return diag.FromErr(err)
	}

	return nil
}

func oktaReadAuthConfig(client *api.Client, path string, d *schema.ResourceData) error {
	log.Printf("[DEBUG] Reading auth config for mount %s from Vault", path)
	config, err := client.Logical().Read(oktaConfigEndpoint(path))
	if err != nil {
		return err
	}

	if err := readTokenFields(d, config); err != nil {
		return err
	}

	// Set fields that don't need backward compatibility handling
	params := []string{
		consts.FieldBaseURL,
		fieldBypassOktaMFA,
	}
	for _, param := range params {
		if err := d.Set(param, config.Data[param]); err != nil {
			return err
		}
	}

	// Handle organization field with backward compatibility
	// Vault API returns "org_name" and "organization" in the response
	var orgValue string
	var ok bool

	// Get the org value from Vault API response
	if val, exists := config.Data[consts.FieldOrgName]; exists {
		orgValue, ok = val.(string)
	} else if val, exists := config.Data[consts.FieldOrganization]; exists {
		orgValue, ok = val.(string)
	}

	if ok {
		// Set org_name as the primary field in state
		if err := d.Set(consts.FieldOrgName, orgValue); err != nil {
			return err
		}

		// Also set organization for backward compatibility
		if err := d.Set(consts.FieldOrganization, orgValue); err != nil {
			return err
		}
	}

	return nil
}

func oktaAuthBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	path := d.Id()

	if !d.IsNewResource() {
		path, e = util.Remount(d, client, consts.FieldPath, true)
		if e != nil {
			return diag.FromErr(e)
		}
	}

	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	configuration := map[string]interface{}{
		consts.FieldBaseURL: d.Get(consts.FieldBaseURL),
		fieldBypassOktaMFA:  d.Get(fieldBypassOktaMFA),
		consts.FieldOrgName: getOrgName(d),
	}

	// Handle token field - check regular fields first, then write-only versions
	// Vault API expects the field name to be "api_token"
	if v, ok := d.GetOk(consts.FieldAPIToken); ok {
		configuration[consts.FieldAPIToken] = v.(string)
	} else if v, ok := d.GetOk(consts.FieldToken); ok {
		// Support deprecated "token" field for backward compatibility
		configuration[consts.FieldAPIToken] = v.(string)
	} else if d.HasChange(consts.FieldAPITokenWOVersion) {
		// User is using write-only api_token_wo and version changed
		if apiTokenWo, _ := d.GetRawConfigAt(cty.GetAttrPath(consts.FieldAPITokenWO)); !apiTokenWo.IsNull() {
			configuration[consts.FieldAPIToken] = apiTokenWo.AsString()
		}
	}

	updateTokenFields(d, configuration, false)

	_, err := client.Logical().WriteWithContext(ctx, oktaConfigEndpoint(path), configuration)
	if err != nil {
		return diag.Errorf("error updating configuration to Vault for path %s: %s", path, err)
	}

	if d.HasChange(fieldGroup) {
		oldValue, newValue := d.GetChange(fieldGroup)

		err = oktaAuthUpdateGroups(client, path, oldValue, newValue)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	if d.HasChange(fieldUser) {
		oldValue, newValue := d.GetChange(fieldUser)

		err = oktaAuthUpdateUsers(client, path, oldValue, newValue)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	if d.HasChange(consts.FieldTune) {
		log.Printf("[DEBUG] Okta Auth '%q' tune configuration changed", path)
		if raw, ok := d.GetOk(consts.FieldTune); ok {
			log.Printf("[DEBUG] Writing Okta auth tune to '%q'", path)

			if err := authMountTune(ctx, client, "auth/"+path, raw); err != nil {
				return diag.FromErr(err)
			}

			log.Printf("[DEBUG] Written Okta auth tune to '%q'", path)
		}
	}

	return oktaAuthBackendRead(ctx, d, meta)
}

func oktaReadAllGroups(client *api.Client, path string) (*schema.Set, error) {
	groupNames, err := listOktaGroups(client, path)
	if err != nil {
		return nil, fmt.Errorf("unable to list groups from %s in Vault: %s", path, err)
	}

	groups := &schema.Set{F: resourceOktaGroupHash}
	for _, groupName := range groupNames {
		group, err := readOktaGroup(client, path, groupName)
		if err != nil {
			return nil, fmt.Errorf("unable to read group %s from %s in Vault: %s", path, groupName, err)
		}

		policies := &schema.Set{F: schema.HashString}
		for _, v := range group.Policies {
			policies.Add(v)
		}

		m := make(map[string]interface{})
		m[consts.FieldPolicies] = policies
		m[consts.FieldGroupName] = group.Name

		groups.Add(m)
	}

	return groups, nil
}

func oktaReadAllUsers(client *api.Client, path string) (*schema.Set, error) {
	userNames, err := listOktaUsers(client, path)
	if err != nil {
		return nil, fmt.Errorf("unable to list groups from %s in Vault: %s", path, err)
	}

	users := &schema.Set{F: resourceOktaUserHash}
	for _, userName := range userNames {
		user, err := readOktaUser(client, path, userName)
		if err != nil {
			return nil, fmt.Errorf("unable to read user %s from %s in Vault: %s", path, userName, err)
		}

		groups := &schema.Set{F: schema.HashString}
		for _, v := range user.Groups {
			groups.Add(v)
		}

		policies := &schema.Set{F: schema.HashString}
		for _, v := range user.Policies {
			policies.Add(v)
		}

		m := make(map[string]interface{})
		m[consts.FieldPolicies] = policies
		m[fieldGroups] = groups
		m[consts.FieldUsername] = user.Username

		users.Add(m)
	}

	return users, nil
}

func oktaAuthUpdateGroups(client *api.Client, path string, oldValue, newValue interface{}) error {
	groupsToDelete := oldValue.(*schema.Set).Difference(newValue.(*schema.Set))
	newGroups := newValue.(*schema.Set).Difference(oldValue.(*schema.Set))

	for _, group := range groupsToDelete.List() {
		groupName := group.(map[string]interface{})[consts.FieldGroupName].(string)
		log.Printf("[DEBUG] Removing Okta group %s from Vault", groupName)
		if err := deleteOktaGroup(client, path, groupName); err != nil {
			return fmt.Errorf("error removing group %s to Vault for path %s: %s", groupName, path, err)
		}
	}

	groups := oldValue.(*schema.Set).Intersection(newValue.(*schema.Set))

	for _, v := range newGroups.List() {
		groupMapping := v.(map[string]interface{})
		groupName := groupMapping[consts.FieldGroupName].(string)

		log.Printf("[DEBUG] Adding Okta group %s to Vault", groupName)

		group := oktaGroup{
			Name:     groupName,
			Policies: util.ToStringArray(groupMapping[consts.FieldPolicies].(*schema.Set).List()),
		}

		if err := updateOktaGroup(client, path, group); err != nil {
			return fmt.Errorf("error updating group %s mapping to Vault for path %s: %s", group.Name, path, err)
		}

		groups.Add(v)
	}

	return nil
}

func oktaAuthUpdateUsers(client *api.Client, path string, oldValue, newValue interface{}) error {
	usersToDelete := oldValue.(*schema.Set).Difference(newValue.(*schema.Set))
	newUsers := newValue.(*schema.Set).Difference(oldValue.(*schema.Set))

	for _, user := range usersToDelete.List() {
		userName := user.(map[string]interface{})[consts.FieldUsername].(string)
		log.Printf("[DEBUG] Removing Okta user %s from Vault", userName)
		if err := deleteOktaUser(client, path, userName); err != nil {
			return fmt.Errorf("error removing user %s mapping to Vault for path %s: %s", userName, path, err)
		}
	}

	users := oldValue.(*schema.Set).Intersection(newValue.(*schema.Set))

	for _, v := range newUsers.List() {
		userMapping := v.(map[string]interface{})
		userName := userMapping[consts.FieldUsername].(string)

		log.Printf("[DEBUG] Adding Okta user %s to Vault", userName)

		user := oktaUser{
			Username: userName,
			Policies: util.ToStringArray(userMapping[consts.FieldPolicies].(*schema.Set).List()),
			Groups:   util.ToStringArray(userMapping[fieldGroups].(*schema.Set).List()),
		}

		if err := updateOktaUser(client, path, user); err != nil {
			return fmt.Errorf("error updating user %s mapping to Vault for path %s: %s", user.Username, path, err)
		}

		users.Add(v)
	}

	return nil
}

func resourceOktaGroupHash(v interface{}) int {
	m, castOk := v.(map[string]interface{})
	if !castOk {
		return 0
	}
	if v, ok := m[consts.FieldGroupName]; ok {
		return helper.HashCodeString(v.(string))
	}

	return 0
}

func resourceOktaUserHash(v interface{}) int {
	m, castOk := v.(map[string]interface{})
	if !castOk {
		return 0
	}
	if v, ok := m[consts.FieldUsername]; ok {
		return helper.HashCodeString(v.(string))
	}

	return 0
}
