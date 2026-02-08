// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

type dbConfigStore struct {
	m      sync.RWMutex
	d      sync.Once
	result map[string][]map[string]interface{}
}

func (s *dbConfigStore) Add(db *dbEngine, vals map[string]interface{}) {
	s.m.Lock()
	defer s.m.Unlock()
	s.d.Do(s.init)

	cur, ok := s.result[db.Name()]
	if !ok {
		cur = []map[string]interface{}{vals}
	} else {
		cur = append(cur, vals)
	}
	s.result[db.Name()] = cur
}

func (s *dbConfigStore) Get(db *dbEngine) []map[string]interface{} {
	s.m.RLock()
	defer s.m.RUnlock()
	if s.result == nil {
		return nil
	}

	return s.result[db.Name()]
}

func (s *dbConfigStore) Result() map[string][]map[string]interface{} {
	s.m.Lock()
	defer s.m.Unlock()
	s.d.Do(s.init)

	result := map[string][]map[string]interface{}{}
	for k, v := range s.result {
		result[k] = v
	}

	return result
}

func (s *dbConfigStore) init() {
	if s.result == nil {
		s.result = make(map[string][]map[string]interface{})
	}
}

func databaseSecretsMountCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, meta interface{}) error {
	// compute the number of configured database engines
	var engineCount int
	for _, engine := range dbEngines {
		count := d.Get(fmt.Sprintf("%s.#", engine)).(int)
		if count > 0 {
			for i := 0; i < count; i++ {
				key := fmt.Sprintf("%s.%d.name", engine, i)
				o, n := d.GetChange(key)
				// don't force new on engine addition
				if o.(string) != "" && o.(string) != n.(string) {
					if err := d.ForceNew(key); err != nil {
						return err
					}
				}
			}
		}
		engineCount += count
	}

	key := "engine_count"
	curCount := d.Get(key).(int)
	// set the new engine count
	if err := d.SetNew(key, engineCount); err != nil {
		return err
	}

	if engineCount < curCount {
		// force new resource creation if the number of configured engines has
		// decreased.
		// Once VAULT-5302 is fixed we can optionally apply the
		// ForceNew if the target Vault version has the fix.
		if err := d.ForceNew(key); err != nil {
			return err
		}
	}

	return nil
}

func databaseSecretsMountResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: databaseSecretsMountCreateOrUpdate,
		ReadContext:   provider.ReadContextWrapper(databaseSecretsMountRead),
		UpdateContext: databaseSecretsMountCreateOrUpdate,
		DeleteContext: databaseSecretsMountDelete,
		CustomizeDiff: databaseSecretsMountCustomizeDiff,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: getDatabaseSecretsMountSchema(),
	}
}

// getDatabaseSecretsMountSchema is used to define the schema for
// vault_database_secrets_mount
func getDatabaseSecretsMountSchema() schemaMap {
	s := getMountSchema("type")
	for k, v := range getDatabaseSchema(schema.TypeList) {
		v.ConflictsWith = nil
		v.MaxItems = 0
		addCommonDatabaseSchema(v)
		s[k] = v
	}

	// Used to gauge whether the resource should be recreated via ForceNew.
	// If the number of engines is reduced then the resource will be recreated.
	// This is handled in the Resource's CustomizeDiff function.
	s["engine_count"] = &schema.Schema{
		Type:        schema.TypeInt,
		Computed:    true,
		Description: "Total number of database secret engines configured under the mount.",
	}

	return s
}

func addCommonDatabaseSchema(s *schema.Schema) {
	elem := s.Elem.(*schema.Resource)
	for k, v := range getCommonDatabaseSchema() {
		// TODO handle intersection errors
		if _, ok := elem.Schema[k]; !ok {
			elem.Schema[k] = v
		}
	}
}

// getCommonDatabaseSchema is used to define the common schema for both
// database resources:
//   - vault_database_secrets_mount
//   - vault_database_secret_backend_connection
//
// New fields on the DB /config endpoint should be added here.
func getCommonDatabaseSchema() schemaMap {
	s := schemaMap{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the database connection.",
			// ForceNew:    true,
		},
		"plugin_name": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
			Description: "Specifies the name of the plugin to use for this connection. " +
				"Must be prefixed with the name of one of the supported database engine types.",
			ValidateFunc: func(i interface{}, s string) ([]string, []error) {
				var errs []error
				v, ok := i.(string)
				if !ok {
					errs = append(errs, fmt.Errorf("expected type of %q to be string", s))
				} else if err := validateDBPluginName(v); err != nil {
					errs = append(errs, err)
				}
				return nil, errs
			},
		},
		"verify_connection": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Specifies if the connection is verified during initial configuration.",
			Default:     true,
		},
		"allowed_roles": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "A list of roles that are allowed to use this connection.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"root_rotation_statements": {
			Type:        schema.TypeList,
			Optional:    true,
			Computed:    true,
			Description: "A list of database statements to be executed to rotate the root user's credentials.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"data": {
			Type:        schema.TypeMap,
			Optional:    true,
			Computed:    true,
			Description: "A map of sensitive data to pass to the endpoint. Useful for templated connection strings.",
			// TODO: revert to true
			Sensitive: false,
		},
	}

	// add common automated root rotation parameters
	for k, v := range provider.GetAutomatedRootRotationSchema() {
		s[k] = v
	}

	return s
}

// setCommonDatabaseSchema is used to define the schema for
// vault_database_secret_backend_connection
func setCommonDatabaseSchema(s schemaMap) schemaMap {
	for k, v := range getCommonDatabaseSchema() {
		s[k] = v
	}
	return s
}

func databaseSecretsMountCreateOrUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	var root string
	if d.IsNewResource() {
		root = d.Get("path").(string)
		if err := createMount(ctx, d, meta, client, root, consts.MountTypeDatabase); err != nil {
			return diag.FromErr(err)
		}
	} else {
		if err := mountUpdate(ctx, d, meta); err != nil {
			return err
		}
		root = d.Id()
	}
	d.SetId(root)

	var count int
	seen := make(map[string]bool)
	for _, engine := range dbEngines {
		if v, ok := d.GetOk(engine.Name()); ok {
			for i := range v.([]interface{}) {
				prefix := engine.ResourcePrefix(i)
				name := d.Get(prefix + "name").(string)
				path := databaseSecretBackendConnectionPath(root, name)
				if _, ok := seen[name]; ok {
					return diag.Errorf("duplicate name %q for engine %#v", name, engine)
				}
				seen[name] = true
				if err := writeDatabaseSecretConfig(ctx, d, client, engine, i, true, path, meta); err != nil {
					return diag.FromErr(err)
				}
				count++
			}
		}
	}

	if diagErr := databaseSecretsMountRead(ctx, d, meta); diagErr != nil {
		return diagErr
	}

	action := "Created"
	if !d.IsNewResource() {
		action = "Updated"
	}

	log.Printf("[DEBUG] %s %d database connections under %q", action, count, root)
	return nil
}

func databaseSecretsMountRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	if e := readMount(ctx, d, meta, true, false); e != nil {
		return diag.FromErr(e)
	}

	root := d.Id()
	// the call to readMount() may have unset the ID, in which case we can return
	// early.
	if root == "" {
		return nil
	}

	resp, err := client.Logical().ListWithContext(ctx, root+"/config")
	if err != nil {
		return diag.FromErr(err)
	}

	if resp == nil {
		return nil
	}

	store := &dbConfigStore{}
	if v, ok := resp.Data["keys"]; ok {
		for _, v := range v.([]interface{}) {
			if err := readDBEngineConfig(d, client, store, v.(string), meta); err != nil {
				return diag.FromErr(err)
			}
		}

		for k, v := range store.Result() {
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	return nil
}

func databaseSecretsMountDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return mountDelete(ctx, d, meta)
}

func readDBEngineConfig(d *schema.ResourceData, client *api.Client, store *dbConfigStore, name string, meta interface{}) error {
	root := d.Id()

	path := databaseSecretBackendConnectionPath(root, name)
	log.Printf("[DEBUG] Reading database connection config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading database connection config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Successfully read database connection config %q", path)
	if resp == nil {
		log.Printf("[WARN] Database connection %q not found", path)
		return nil
	}

	engine, err := getDBEngineFromResp(dbEngines, resp)
	if err != nil {
		return err
	}

	idx := len(store.Get(engine))
	result, err := getDBConnectionConfig(d, engine, idx, resp, meta)
	if err != nil {
		return err
	}

	for k, v := range getDBCommonConfig(d, resp, engine, idx, true, name, meta) {
		result[k] = v
	}

	store.Add(engine, result)

	return nil
}
