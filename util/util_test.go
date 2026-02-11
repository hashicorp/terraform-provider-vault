// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

type testingStruct struct {
	foobar bool
	list   []string
}

func TestExpiredTokenError(t *testing.T) {
	if ok := IsExpiredTokenErr(fmt.Errorf("error: invalid accessor custom_accesor_value")); !ok {
		t.Errorf("Should be expired")
	}
	if ok := IsExpiredTokenErr(fmt.Errorf("error: failed to find accessor entry custom_accesor_value")); !ok {
		t.Errorf("Should be expired")
	}
	if ok := IsExpiredTokenErr(nil); ok {
		t.Errorf("Shouldn't be expired")
	}
	if ok := IsExpiredTokenErr(fmt.Errorf("Error making request")); ok {
		t.Errorf("Shouldn't be expired")
	}
}

func TestSliceHasElement_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}

	found, index := SliceHasElement(slice, 2)
	if !found && index != 1 {
		t.Errorf("Slice should find element")
	}

	found, index = SliceHasElement(slice, 10)
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}
}

func TestSliceHasElement_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}

	found, index := SliceHasElement(slice, testingStruct{foobar: true, list: []string{"I", "gotta", "go"}})
	if !found && index != 1 {
		t.Errorf("Slice should find element")
	}

	found, index = SliceHasElement(slice, testingStruct{foobar: false, list: []string{}})
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}

	found, index = SliceHasElement(slice, 10)
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}
}

func TestSliceAppendIfMissing_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}
	expectedAppend := []interface{}{1, 2, 3, 4, 5, 6}

	append := SliceAppendIfMissing(slice, 3)
	if !reflect.DeepEqual(slice, append) {
		t.Errorf("Slice should not be appended")
	}

	append = SliceAppendIfMissing(slice, 6)
	if !reflect.DeepEqual(expectedAppend, append) {
		t.Errorf("Slice should be appended")
	}
}

func TestSliceAppendIfMissing_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
	}
	expectedAppend := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}

	append := SliceAppendIfMissing(slice, testingStruct{foobar: false, list: []string{"hello", "world"}})
	if !reflect.DeepEqual(slice, append) {
		t.Errorf("Slice should not be appended")
	}

	append = SliceAppendIfMissing(slice, testingStruct{foobar: true, list: []string{"I", "gotta", "go"}})
	if !reflect.DeepEqual(expectedAppend, append) {
		t.Errorf("Slice should be appended")
	}
}

func TestSliceRemoveIfPresent_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}
	expected := []interface{}{1, 2, 5, 4}

	removed := SliceRemoveIfPresent(slice, 10)
	if !reflect.DeepEqual(slice, removed) {
		t.Errorf("Slice should not be modified")
	}

	removed = SliceRemoveIfPresent(slice, 3)
	if !reflect.DeepEqual(expected, removed) {
		t.Errorf("Slice should be modified")
	}

	empty := make([]interface{}, 0)
	if len(SliceRemoveIfPresent(empty, 0)) != 0 {
		t.Errorf("Slice should be empty")
	}

	single := []interface{}{1}
	if len(SliceRemoveIfPresent(single, 1)) != 0 {
		t.Errorf("Slice should be empty")
	}
}

func TestSliceRemoveIfPresent_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}
	expected := []interface{}{
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
	}

	removed := SliceRemoveIfPresent(slice, testingStruct{foobar: false, list: []string{}})
	if !reflect.DeepEqual(slice, removed) {
		t.Errorf("Slice should not be modified")
	}

	removed = SliceRemoveIfPresent(slice, testingStruct{foobar: false, list: []string{"hello", "world"}})
	if !reflect.DeepEqual(expected, removed) {
		t.Errorf("Slice should be modified")
	}
}

func TestParsePath(t *testing.T) {
	testCases := []struct {
		inputUserSuppliedPath, inputEndpoint string
		inputData                            *schema.ResourceData
		expected                             string
	}{
		{
			inputUserSuppliedPath: "my/transform/hello",
			inputEndpoint:         "/transform/role/{name}",
			inputData: schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"name": {Type: schema.TypeString},
			}, map[string]interface{}{
				"name": "foo",
			}),
			expected: "/my/transform/hello/role/foo",
		},
		{
			inputUserSuppliedPath: "jwt-1914071788362821795",
			inputEndpoint:         "/auth/jwt/config",
			inputData:             &schema.ResourceData{},
			expected:              "/auth/jwt-1914071788362821795/config",
		},
		{
			inputUserSuppliedPath: "accounting-transit",
			inputEndpoint:         "/transit/export/{type}/{name}/{version}",
			inputData: schema.TestResourceDataRaw(t, map[string]*schema.Schema{
				"name":    {Type: schema.TypeString},
				"type":    {Type: schema.TypeString},
				"version": {Type: schema.TypeString},
			}, map[string]interface{}{
				"version": "1",
				"type":    "encryption-key",
				"name":    "my-key",
			}),
			expected: "/accounting-transit/export/encryption-key/my-key/1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.inputUserSuppliedPath, func(t *testing.T) {
			actual := ParsePath(testCase.inputUserSuppliedPath, testCase.inputEndpoint, testCase.inputData)
			if actual != testCase.expected {
				t.Fatalf("expected %q, received %q", testCase.expected, actual)
			}
		})
	}
}

func TestPathParameters(t *testing.T) {
	testCases := []struct {
		endpoint, vaultPath string
		expected            map[string]string
	}{
		{
			endpoint:  "/transform/role/{name}",
			vaultPath: "/transform-56614161/foo7306072804/role/test-role-54539268/foo87766695434",
			expected: map[string]string{
				"path": "transform-56614161/foo7306072804",
				"name": "test-role-54539268/foo87766695434",
			},
		},
		{
			endpoint:  "/transit/sign/{name}/{urlalgorithm}",
			vaultPath: "/transit/sign/my-key/sha2-512",
			expected: map[string]string{
				"path":         "transit",
				"name":         "my-key",
				"urlalgorithm": "sha2-512",
			},
		},
		{
			endpoint:  "/transit/sign/{name}/{urlalgorithm}",
			vaultPath: "/my-transit/sign/my-key/sha2-512",
			expected: map[string]string{
				"path":         "my-transit",
				"name":         "my-key",
				"urlalgorithm": "sha2-512",
			},
		},
		{
			endpoint:  "/auth/approle/tidy/secret-id",
			vaultPath: "/auth/my-approle/tidy/secret-id",
			expected: map[string]string{
				"path": "my-approle",
			},
		},
		{
			endpoint:  "/sys/mfa/method/totp/{name}/admin-generate",
			vaultPath: "/sys/mfa/method/totp/my_totp/admin-generate",
			expected: map[string]string{
				"path": "sys",
				"name": "my_totp",
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.endpoint, func(t *testing.T) {
			result, err := PathParameters(testCase.endpoint, testCase.vaultPath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result, testCase.expected) {
				t.Fatalf("expected %+v but received %+v", testCase.expected, result)
			}
		})
	}
}

func TestGetAPIRequestDataWithMap(t *testing.T) {
	tests := []struct {
		name string
		d    map[string]*schema.Schema
		m    map[string]string
		sm   map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "basic-default",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
			},
			m: map[string]string{
				"name": "",
			},
			sm: map[string]interface{}{
				"name": "bob",
			},
			want: map[string]interface{}{
				"name": "bob",
			},
		},
		{
			name: "basic-remap",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
			},
			m: map[string]string{
				"name": "nom",
			},
			sm: map[string]interface{}{
				"name": "bob",
			},
			want: map[string]interface{}{
				"nom": "bob",
			},
		},
		{
			name: "map",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
				"parts": {
					Type: schema.TypeMap,
				},
			},
			m: map[string]string{
				"name":  "",
				"parts": "",
			},
			sm: map[string]interface{}{
				"name": "bob",
				"parts": map[string]interface{}{
					"bolt": "0.60",
				},
			},
			want: map[string]interface{}{
				"name": "bob",
				"parts": map[string]interface{}{
					"bolt": "0.60",
				},
			},
		},
		{
			name: "set",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
				"parts": {
					Type: schema.TypeSet,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
			m: map[string]string{
				"name":  "",
				"parts": "",
			},
			sm: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
			want: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := schema.TestResourceDataRaw(t, tt.d, tt.sm)
			if got := GetAPIRequestDataWithMap(r, tt.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAPIRequestDataWithMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAPIRequestDataWithSlice(t *testing.T) {
	tests := []struct {
		name string
		d    map[string]*schema.Schema
		s    []string
		sm   map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "basic-default",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
			},
			s: []string{"name"},
			sm: map[string]interface{}{
				"name": "bob",
			},
			want: map[string]interface{}{
				"name": "bob",
			},
		},
		{
			name: "set",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
				"parts": {
					Type: schema.TypeSet,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
			s: []string{
				"name",
				"parts",
			},
			sm: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
			want: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := schema.TestResourceDataRaw(t, tt.d, tt.sm)
			if got := GetAPIRequestDataWithSlice(r, tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAPIRequestDataWithSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAPIRequestDataWithSliceOk(t *testing.T) {
	tests := []struct {
		name string
		d    map[string]*schema.Schema
		s    []string
		sm   map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "basic-default",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
			},
			s: []string{"name"},
			sm: map[string]interface{}{
				"name": "bob",
			},
			want: map[string]interface{}{
				"name": "bob",
			},
		},
		{
			name: "set",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
				"parts": {
					Type: schema.TypeSet,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
			s: []string{
				"name",
				"parts",
			},
			sm: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
			want: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
		},
		{
			name: "parts-field-not-configured",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
			},
			s: []string{
				"name",
				"parts",
			},
			sm: map[string]interface{}{
				"name": "alice",
			},
			want: map[string]interface{}{
				"name": "alice",
			},
		},
		{
			name: "zero-value-int-field",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
				"enabled": {
					Type: schema.TypeInt,
				},
			},
			s: []string{
				"name",
				"enabled",
			},
			sm: map[string]interface{}{
				"name":    "alice",
				"enabled": 0,
			},
			want: map[string]interface{}{
				"name": "alice",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := schema.TestResourceDataRaw(t, tt.d, tt.sm)
			if got := GetAPIRequestDataWithSliceOk(r, tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAPIRequestDataWithSliceOk() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAPIRequestDataWithSliceOkExists(t *testing.T) {
	tests := []struct {
		name string
		d    map[string]*schema.Schema
		s    []string
		sm   map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "basic-default",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
			},
			s: []string{"name"},
			sm: map[string]interface{}{
				"name": "bob",
			},
			want: map[string]interface{}{
				"name": "bob",
			},
		},
		{
			name: "set",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
				"parts": {
					Type: schema.TypeSet,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
			},
			s: []string{
				"name",
				"parts",
			},
			sm: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
			want: map[string]interface{}{
				"name": "alice",
				"parts": []interface{}{
					"bolt",
				},
			},
		},
		{
			name: "parts-field-not-configured",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
			},
			s: []string{
				"name",
				"parts",
			},
			sm: map[string]interface{}{
				"name": "alice",
			},
			want: map[string]interface{}{
				"name": "alice",
			},
		},
		{
			name: "zero-value-int-field",
			d: map[string]*schema.Schema{
				"name": {
					Type: schema.TypeString,
				},
				"enabled": {
					Type: schema.TypeInt,
				},
			},
			s: []string{
				"name",
				"enabled",
			},
			sm: map[string]interface{}{
				"name":    "alice",
				"enabled": 0,
			},
			want: map[string]interface{}{
				"name":    "alice",
				"enabled": 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := schema.TestResourceDataRaw(t, tt.d, tt.sm)
			if got := GetAPIRequestDataWithSliceOkExists(r, tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAPIRequestDataWithSliceOkExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateConflictsWith(t *testing.T) {
	tests := []struct {
		name  string
		self  string
		group []string
		want  []string
	}{
		{
			name:  "empty",
			self:  "basic",
			group: []string{},
			want:  []string{},
		},
		{
			name:  "empty-self",
			self:  "basic",
			group: []string{"basic"},
			want:  []string{},
		},
		{
			name:  "single",
			self:  "single",
			group: []string{"foo"},
			want:  []string{"foo"},
		},
		{
			name:  "single-self",
			self:  "single",
			group: []string{"foo", "single"},
			want:  []string{"foo"},
		},
		{
			name:  "multiple-self",
			self:  "multiple",
			group: []string{"multiple", "foo", "multiple"},
			want:  []string{"foo"},
		},
		{
			name:  "duplicates-other",
			self:  "multiple",
			group: []string{"foo", "bar", "foo", "bar"},
			want:  []string{"foo", "bar"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CalculateConflictsWith(tt.self, tt.group); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CalculateConflictsWith() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRetryWrite(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		reqData      map[string]interface{}
		req          *RetryRequestOpts
		retryHandler *testutil.TestRetryHandler
		want         *api.Secret
		wantErr      bool
	}{
		{
			name: "ok-without-retries",
			path: "foo/baz",
			reqData: map[string]interface{}{
				"qux": "baz",
			},
			req: &RetryRequestOpts{
				MaxTries:    3,
				Delay:       time.Millisecond * 100,
				StatusCodes: []int{http.StatusBadRequest},
			},
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount: 1,
			},
			want: &api.Secret{
				Data: map[string]interface{}{
					"qux": "baz",
				},
			},
			wantErr: false,
		},
		{
			name: "ok-with-retries",
			path: "foo/baz",
			reqData: map[string]interface{}{
				"baz": "biff",
			},
			req: &RetryRequestOpts{
				MaxTries:    3,
				Delay:       time.Millisecond * 100,
				StatusCodes: []int{http.StatusBadRequest},
			},
			retryHandler: &testutil.TestRetryHandler{
				OKAtCount:   2,
				RetryStatus: http.StatusBadRequest,
			},
			want: &api.Secret{
				Data: map[string]interface{}{
					"baz": "biff",
				},
			},
			wantErr: false,
		},
		{
			name: "non-retryable-no-status",
			path: "foo/baz",
			reqData: map[string]interface{}{
				"baz": "biff",
			},
			req: &RetryRequestOpts{
				MaxTries:    3,
				Delay:       time.Millisecond * 100,
				StatusCodes: []int{},
			},
			retryHandler: &testutil.TestRetryHandler{
				RetryStatus: http.StatusConflict,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "max-retries-exceeded-single",
			path: "foo/baz",
			reqData: map[string]interface{}{
				"baz": "biff",
			},
			req: &RetryRequestOpts{
				MaxTries:    3,
				Delay:       time.Millisecond * 100,
				StatusCodes: []int{http.StatusBadRequest},
			},
			retryHandler: &testutil.TestRetryHandler{
				RetryStatus: http.StatusBadRequest,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "max-retries-exceeded-choices",
			path: "foo/baz",
			reqData: map[string]interface{}{
				"baz": "biff",
			},
			req: &RetryRequestOpts{
				MaxTries:    3,
				Delay:       time.Millisecond * 100,
				StatusCodes: []int{http.StatusBadRequest, http.StatusConflict},
			},
			retryHandler: &testutil.TestRetryHandler{
				RetryStatus: http.StatusConflict,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, ln := testutil.TestHTTPServer(t, tt.retryHandler.Handler())
			defer ln.Close()

			config.Address = fmt.Sprintf("http://%s", ln.Addr())
			client, err := api.NewClient(config)
			if err != nil {
				t.Fatal(err)
			}

			if !tt.wantErr && tt.retryHandler.RespData == nil {
				b, err := json.Marshal(tt.reqData)
				if err != nil {
					t.Fatal(err)
				}
				tt.retryHandler.RespData = b
			}

			got, err := RetryWrite(client, tt.path, tt.reqData, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("RetryWrite() error = %v, wantErr %v", err,
					tt.wantErr)
				return
			}

			if tt.wantErr {
				if len(tt.req.StatusCodes) == 0 {
					if tt.retryHandler.Retries != 0 {
						t.Fatalf("expected 0 retries, actual %d",
							tt.retryHandler.Retries)
					}
					if tt.retryHandler.Requests != 1 {
						t.Fatalf("expected 1 requests, actual %d",
							tt.retryHandler.Requests)
					}
				} else {
					if int(tt.req.MaxTries) != tt.retryHandler.Retries {
						t.Fatalf("expected %d retries, actual %d",
							tt.req.MaxTries, tt.retryHandler.Requests)
					}
				}
			} else {
				if tt.retryHandler.OKAtCount != tt.retryHandler.Requests {
					t.Fatalf("expected %d retries, actual %d",
						tt.retryHandler.OKAtCount, tt.retryHandler.Requests)
				}

				var expectedRetries int
				if tt.retryHandler.OKAtCount > 1 {
					expectedRetries = tt.retryHandler.Requests - 1
				}

				if expectedRetries != tt.retryHandler.Retries {
					t.Fatalf("expected %d retries, actual %d",
						expectedRetries, tt.retryHandler.Requests)
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RetryWrite() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetStringSliceFromSecret(t *testing.T) {
	fieldName := "foo"
	var testArray [2]string
	testArray[0] = "1"
	testArray[1] = "2"

	tests := []struct {
		name       string
		secretData map[string]interface{}
		want       []string
		wantOk     bool
	}{
		{"nil-data", nil, nil, false},
		{"field-missing", map[string]interface{}{}, nil, false},
		{"nil-element", map[string]interface{}{fieldName: nil}, nil, false},
		{"not-a-slice", map[string]interface{}{fieldName: "test-value"}, nil, false},
		{"array-val", map[string]interface{}{fieldName: testArray}, []string{"1", "2"}, true},
		{"mixed-slice", map[string]interface{}{fieldName: []interface{}{1, "2"}}, []string{"1", "2"}, true},
		{"int-slice", map[string]interface{}{fieldName: []int{1, 2}}, []string{"1", "2"}, true},
		{"string-slice", map[string]interface{}{fieldName: []string{"test1", "test2"}}, []string{"test1", "test2"}, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			secret := &api.Secret{Data: tt.secretData}
			got, gotOk := GetStringSliceFromSecret(secret, fieldName)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetStringSliceFromSecret() got = %v, want %v", got, tt.want)
			}
			if gotOk != tt.wantOk {
				t.Errorf("GetStringSliceFromSecret() gotOk = %v, wantOk %v", gotOk, tt.wantOk)
			}
		})
	}
}
