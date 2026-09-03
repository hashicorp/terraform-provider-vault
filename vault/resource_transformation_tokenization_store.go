package vault

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const transformTransformationTokenizationStoreEndpoint = "/transform/stores/{name}"

func transformTransformationTokenizationStoreResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		consts.FieldPath: {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for a back-end, for example, the path given in "$ vault auth enable -path=my-aws aws".`,
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},
		consts.FieldName: {
			Type:        schema.TypeString,
			Description: "The name of the store.",
			ForceNew:    true,
			Required:    true,
		},
		consts.FieldType: {
			Type:        schema.TypeString,
			Description: `Specifies the type of store, currently only "sql" is supported,`,
			Required:    true,
		},
		consts.FieldDriver: {
			Type: schema.TypeString,
			Description: "Specifies the database driver to use, and thus which SQL database type. " +
				"Currently the supported options are postgres, mysql, and mssql.",
			Required: true,
		},
		consts.FieldConnectionString: {
			Type: schema.TypeString,
			Description: "A database connection string with template slots for username and password that Vault will use for locating and connecting to a database. " +
				"Each database driver type has a different syntax for its connection strings.",
			Required: true,
		},
		consts.FieldUsername: {
			Type:        schema.TypeString,
			Description: "Username value to use to connect to database.",
			Required:    true,
		},
		consts.FieldPassword: {
			Type:        schema.TypeString,
			Description: "Password value to use to connect to database.",
			Required:    true,
			Sensitive:   true,
		},
		consts.FieldSupportedTransformations: {
			Type:        schema.TypeList,
			Description: `The types of transformations this store can support, currently only "tokenization" is supported.`,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		consts.FieldSchema: {
			Type:        schema.TypeString,
			Description: `The schema within the database to expect tokenization state tables. Default is "public".`,
			Optional:    true,
		},
		consts.FieldMaxOpenConnections: {
			Type:        schema.TypeInt,
			Description: "The maximum number of connections to the database at any given time. Default is 4.",
			Optional:    true,
		},
		consts.FieldMaxIdleConnections: {
			Type:        schema.TypeInt,
			Description: "The maximum number of idle connections to the database at any given time. Default is 4.",
			Optional:    true,
		},
		consts.FieldMaxConnectionLifetime: {
			Type: schema.TypeInt,
			Description: "The maximum amount of time a connection can be open before closing it. " +
				"0 means no limit. Default is 0.",
			Optional: true,
		},
	}
	return &schema.Resource{
		Schema:        fields,
		ReadContext:   provider.ReadContextWrapper(readTransformTransformationTokenizationStoreResource),
		CreateContext: createUpdateTransformTransformationTokenizationStoreResource,
		UpdateContext: createUpdateTransformTransformationTokenizationStoreResource,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		DeleteContext: deleteTransformTransformationTokenizationStoreResource,
	}
}

func createUpdateTransformTransformationTokenizationStoreResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	path := d.Get(consts.FieldPath).(string)
	vaultPath := util.ParsePath(path, transformTransformationTokenizationStoreEndpoint, d)
	log.Printf("[DEBUG] Creating/Updating %q", vaultPath)
	data := map[string]interface{}{}
	for _, v := range []string{consts.FieldType, consts.FieldDriver, consts.FieldConnectionString, consts.FieldUsername, consts.FieldPassword, consts.FieldSupportedTransformations, consts.FieldSchema, consts.FieldMaxOpenConnections, consts.FieldMaxIdleConnections, consts.FieldMaxConnectionLifetime} {
		if val, ok := d.GetOk(v); ok {
			data[v] = val
		}
	}
	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return diag.Errorf("error writing %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Wrote %q", vaultPath)

	d.SetId(vaultPath)
	return readTransformTransformationTokenizationStoreResource(ctx, d, meta)
}

func readTransformTransformationTokenizationStoreResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}

	vaultPath := d.Id()
	log.Printf("[DEBUG] Reading %q", vaultPath)
	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return diag.Errorf("error reading %q: %s", vaultPath, err)
	}
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}

	pathParams, err := util.PathParameters(transformTransformationTokenizationStoreEndpoint, vaultPath)
	if err != nil {
		return diag.FromErr(err)
	}
	for paramName, paramVal := range pathParams {
		if err := d.Set(paramName, paramVal); err != nil {
			return diag.Errorf("error setting state %q, %q: %s", paramName, paramVal, err)
		}
	}

	// fields returned by vault
	for _, field := range []string{consts.FieldConnectionString, consts.FieldDriver, consts.FieldSupportedTransformations} {
		if val, ok := resp.Data[field]; ok {
			if err := d.Set(field, val); err != nil {
				return diag.Errorf("error setting state key %q: %s", field, err)
			}
		}
	}

	// fields that aren't returned by vault,
	for _, field := range []string{consts.FieldType, consts.FieldUsername, consts.FieldPassword, consts.FieldSchema, consts.FieldMaxOpenConnections, consts.FieldMaxIdleConnections, consts.FieldMaxConnectionLifetime} {
		if err := d.Set(field, d.Get(field)); err != nil {
			return diag.Errorf("error setting state key %q: %s", field, err)
		}
	}

	return nil
}

func deleteTransformTransformationTokenizationStoreResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return diag.FromErr(e)
	}
	vaultPath := d.Id()
	log.Printf("[DEBUG] Deleting %q", vaultPath)

	if _, err := client.Logical().Delete(vaultPath); err != nil && !util.Is404(err) {
		return diag.Errorf("Error deleting %q: %s", vaultPath, err)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Deleted tokenization transformation store at: %q", vaultPath)
	return nil
}
