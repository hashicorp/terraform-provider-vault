// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

type (
	// VaultAPIValueGetter returns the value from the *schema.ResourceData for a key,
	// along with a boolean that denotes the key's existence.
	VaultAPIValueGetter func(*schema.ResourceData, string) (interface{}, bool)
)

func JsonDiffSuppress(k, old, new string, _ *schema.ResourceData) bool {
	var oldJSON, newJSON interface{}
	err := json.Unmarshal([]byte(old), &oldJSON)
	if err != nil {
		log.Printf("[WARN] Version of %q in state is not valid JSON: %s", k, err)
		return false
	}
	err = json.Unmarshal([]byte(new), &newJSON)
	if err != nil {
		log.Printf("[WARN] Version of %q in config is not valid JSON: %s", k, err)
		return false
	}
	return reflect.DeepEqual(oldJSON, newJSON)
}

func ToStringArray(input []interface{}) []string {
	output := make([]string, len(input))

	for i, item := range input {
		output[i] = item.(string)
	}

	return output
}

func Is404(err error) bool {
	return ErrorContainsHTTPCode(err, http.StatusNotFound)
}

func ErrorContainsHTTPCode(err error, codes ...int) bool {
	for _, code := range codes {
		if strings.Contains(err.Error(), fmt.Sprintf("Code: %d", code)) {
			return true
		}
	}
	return false
}

// CalculateConflictsWith returns a slice of field names that conflict with
// a single field (self).
func CalculateConflictsWith(self string, group []string) []string {
	result := make([]string, 0)
	seen := map[string]bool{
		self: true,
	}
	for _, item := range group {
		if _, ok := seen[item]; ok {
			continue
		}

		seen[item] = true
		result = append(result, item)
	}
	return result
}

func ArrayToTerraformList(values []string) string {
	output := make([]string, len(values))
	for idx, value := range values {
		output[idx] = fmt.Sprintf(`"%s"`, value)
	}
	return fmt.Sprintf("[%s]", strings.Join(output, ", "))
}

func TerraformSetToStringArray(set interface{}) []string {
	list := set.(*schema.Set).List()
	arr := make([]string, 0, len(list))
	for _, v := range list {
		arr = append(arr, v.(string))
	}
	return arr
}

func JsonStringArrayToStringArray(jsonList []interface{}) []string {
	strList := make([]string, 0, len(jsonList))
	for _, v := range jsonList {
		strList = append(strList, v.(string))
	}
	return strList
}

func IsExpiredTokenErr(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "invalid accessor") {
		return true
	}
	if strings.Contains(err.Error(), "failed to find accessor entry") {
		return true
	}
	return false
}

func ShortDur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func SliceHasElement(list []interface{}, search interface{}) (bool, int) {
	for i, ele := range list {
		if reflect.DeepEqual(ele, search) {
			return true, i
		}
	}
	return false, -1
}

func SliceAppendIfMissing(list []interface{}, search interface{}) []interface{} {
	if found, _ := SliceHasElement(list, search); !found {
		return append(list, search)
	}

	return list
}

// Warning: Slice order will be modified
func SliceRemoveIfPresent(list []interface{}, search interface{}) []interface{} {
	if found, index := SliceHasElement(list, search); found {
		// Set the index we found to be the last item
		list[index] = list[len(list)-1]
		// Return slice sans last item
		return list[:len(list)-1]
	}

	return list
}

// Example data:
//   - userSuppliedPath = "transform"
//   - endpoint = "/transform/role/{name}"
//   - parameters will include path parameters
func ParsePath(userSuppliedPath, endpoint string, d *schema.ResourceData) string {
	fields := strings.Split(endpoint, "/")
	if fields[0] == "" {
		// There was a leading slash that should be trimmed.
		fields = fields[1:]
	}
	isAuthPath := false
	if fields[0] == "auth" {
		fields = fields[1:]
		isAuthPath = true
	}

	// The first field should be the one the user supplied rather
	// than the default one shown.
	fields[0] = userSuppliedPath

	// Since endpoints start with a "/", the first field is always
	// an extraneous "" and should be dropped.
	recomprised := "/" + strings.Join(fields, "/")
	if isAuthPath {
		recomprised = "/auth" + recomprised
	}

	// For a recomprised string like "/my-transform/role/{name}",
	// this will return the fields of "/transform/role/" and
	// "name".
	fields = strings.FieldsFunc(recomprised, func(c rune) bool {
		return c == '{' || c == '}'
	})
	for _, field := range fields {
		valRaw, ok := d.GetOk(field)
		if !ok {
			continue
		}
		// All path parameters must be strings, so it's safe to
		// assume here.
		val := valRaw.(string)
		recomprised = strings.Replace(recomprised, fmt.Sprintf("{%s}", field), val, -1)
	}
	return recomprised
}

// PathParameters is just like regexp FindStringSubmatch,
// but it validates that the match is different from the string passed
// in, and that there's only one result.
func PathParameters(endpoint, vaultPath string) (map[string]string, error) {
	fields := strings.Split(endpoint, "/")

	// The first field is always "", let's strip it.
	if fields[0] != "" {
		return nil, fmt.Errorf("expected an endpoint starting with / but received %q", endpoint)
	}
	fields = fields[1:]

	// For paths beginning with auth, if we strip it off we can
	// parse them like the rest.
	isAuthEndpoint := false
	if fields[0] == "auth" {
		if len(fields) < 2 {
			// There are no further path parameters to parse.
			return nil, nil
		}
		fields = fields[1:]
		isAuthEndpoint = true
	}
	fields[0] = "{path}"

	for i, field := range fields {
		if strings.HasPrefix(field, "{") {
			fields[i] = strings.ReplaceAll(fields[i], "{", "(?P<")
			fields[i] = strings.ReplaceAll(fields[i], "}", ">.+)")
		}
	}
	pattern := "/"
	if isAuthEndpoint {
		pattern += "auth/"
	}
	pattern += strings.Join(fields, "/")

	endpointReg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("unable to compile regex: %q: %w\n", pattern, err)
	}

	match := endpointReg.FindStringSubmatch(vaultPath)
	result := make(map[string]string)
	for i, fieldName := range endpointReg.SubexpNames() {
		if i == 0 || fieldName == "" {
			continue
		}
		if i >= len(match) {
			return nil, fmt.Errorf("could not parse %q into %q", vaultPath, endpoint)
		}
		result[fieldName] = match[i]
	}
	return result, nil
}

// StatusCheckRetry for any response having a status code in statusCode.
func StatusCheckRetry(statusCodes ...int) retryablehttp.CheckRetry {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		// ensure that the client controlled consistency policy is honoured.
		if retry, err := api.DefaultRetryPolicy(ctx, resp, err); err != nil || retry {
			return retry, err
		}

		if resp != nil {
			for _, code := range statusCodes {
				if code == resp.StatusCode {
					return true, nil
				}
			}
		}
		return false, nil
	}
}

// SetupCCCRetryClient for handling Client Controlled Consistency related
// requests.
func SetupCCCRetryClient(client *api.Client, maxRetry int) {
	client.SetReadYourWrites(true)
	client.SetMaxRetries(maxRetry)
	client.SetCheckRetry(StatusCheckRetry(http.StatusNotFound))

	// ensure that the clone has the reasonable backoff min/max durations set.
	if client.MinRetryWait() == 0 {
		client.SetMinRetryWait(time.Millisecond * 1000)
	}
	if client.MaxRetryWait() == 0 {
		client.SetMaxRetryWait(time.Millisecond * 1500)
	}
	if client.MaxRetryWait() < client.MinRetryWait() {
		client.SetMaxRetryWait(client.MinRetryWait())
	}

	bo := retryablehttp.LinearJitterBackoff
	client.SetBackoff(bo)

	to := time.Duration(0)
	for i := 0; i < client.MaxRetries(); i++ {
		to += bo(client.MaxRetryWait(), client.MaxRetryWait(), i, nil)
	}
	client.SetClientTimeout(to + time.Second*30)
}

// SetResourceData from a data map.
func SetResourceData(d *schema.ResourceData, data map[string]interface{}) error {
	for k := range data {
		if err := d.Set(k, data[k]); err != nil {
			return fmt.Errorf("error setting resource data for key %q, err=%w", k, err)
		}
	}

	return nil
}

// NormalizeMountPath to be in a form valid for accessing values from api.MountOutput
func NormalizeMountPath(path string) string {
	return TrimSlashes(path) + consts.PathDelim
}

// TrimSlashes from path.
func TrimSlashes(path string) string {
	return strings.Trim(path, consts.PathDelim)
}

// CheckMountEnabled in Vault, path must contain a trailing '/',
func CheckMountEnabled(client *api.Client, path string) (bool, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, err
	}

	_, ok := mounts[NormalizeMountPath(path)]

	return ok, nil
}

// GetAPIRequestDataWithMap to pass to Vault from schema.ResourceData.
// The fieldMap specifies the schema field to its vault constituent.
// If the vault field is empty, then two fields are mapped 1:1.
func GetAPIRequestDataWithMap(d *schema.ResourceData, fieldMap map[string]string) map[string]interface{} {
	data := make(map[string]interface{})
	for k1, k2 := range fieldMap {
		if k2 == "" {
			k2 = k1
		}

		data[k2] = getAPIRequestValue(d, k1)
	}

	return data
}

// GetAPIRequestDataWithSlice to pass to Vault from schema.ResourceData.
func GetAPIRequestDataWithSlice(d *schema.ResourceData, fields []string) map[string]interface{} {
	data := make(map[string]interface{})
	for _, k := range fields {
		data[k] = getAPIRequestValue(d, k)
	}

	return data
}

// GetAPIRequestDataWithSliceOk to pass to Vault from schema.ResourceData.
// Only field values that are set in schema.ResourceData will be returned
func GetAPIRequestDataWithSliceOk(d *schema.ResourceData, fields []string) map[string]interface{} {
	return getAPIRequestDataWithSlice(d, GetAPIRequestValueOk, fields)
}

// GetAPIRequestDataWithSliceOkExists to pass to Vault from schema.ResourceData.
// Only field values that are set in schema.ResourceData will be returned
func GetAPIRequestDataWithSliceOkExists(d *schema.ResourceData, fields []string) map[string]interface{} {
	return getAPIRequestDataWithSlice(d, GetAPIRequestValueOkExists, fields)
}

func getAPIRequestDataWithSlice(d *schema.ResourceData, f VaultAPIValueGetter, fields []string) map[string]interface{} {
	data := make(map[string]interface{})
	for _, k := range fields {
		if v, ok := f(d, k); ok {
			data[k] = v
		}
	}

	return data
}

func getAPIRequestValue(d *schema.ResourceData, k string) interface{} {
	return getAPIValue(d.Get(k))
}

func getAPIValue(i interface{}) interface{} {
	switch s := i.(type) {
	case *schema.Set:
		return s.List()
	default:
		return s
	}
}

// GetAPIRequestValueOk returns the Vault API compatible value from *schema.ResourceData for provided key,
// along with boolean representing keys existence in the resource data.
// This is equivalent to calling the schema.ResourceData's GetOk() method.
func GetAPIRequestValueOk(d *schema.ResourceData, k string) (interface{}, bool) {
	sv, ok := d.GetOk(k)
	return getAPIValue(sv), ok
}

// GetAPIRequestValueOkExists returns the Vault API compatible value from *schema.ResourceData for provided key,
// along with boolean representing keys existence in the resource data.
// This is equivalent to calling the schema.ResourceData's deprecated GetOkExists() method.
func GetAPIRequestValueOkExists(d *schema.ResourceData, k string) (interface{}, bool) {
	sv, ok := d.GetOkExists(k)
	return getAPIValue(sv), ok
}

// GetAPIRequestValue returns the value from *schema.ResourceData for provide key.
// The existence boolean is always true, so it should be ignored,
// this is done  in order to satisfy the VaultAPIValueGetter type.
// This is equivalent to calling the schema.ResourceData's Get() method.
func GetAPIRequestValue(d *schema.ResourceData, k string) (interface{}, bool) {
	return getAPIValue(d.Get(k)), true
}

func Remount(d *schema.ResourceData, client *api.Client, mountField string, isAuthMount bool) (string, error) {
	ret := d.Get(mountField).(string)

	if d.HasChange(mountField) {
		// since this function is only called within Update
		// we know that remount is enabled
		o, n := d.GetChange(mountField)
		oldPath := o.(string)
		newPath := n.(string)
		if isAuthMount {
			oldPath = "auth/" + oldPath
			newPath = "auth/" + newPath
		}

		err := client.Sys().Remount(oldPath, newPath)
		if err != nil {
			return "", fmt.Errorf("error remounting to %q: %w", newPath, err)
		}

		// ID for Auth backends only contains mount path
		d.SetId(ret)
	}

	return ret, nil
}
