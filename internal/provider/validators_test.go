// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func Test_validateNoTrailingSlash(t *testing.T) {
	testCases := []struct {
		name        string
		val         string
		expectedErr []error
	}{
		{
			name: "valid-single",
			val:  "foo",
		},
		{
			name: "invalid",
			val:  "foo/",
			expectedErr: []error{
				fmt.Errorf(`value "foo/" for "test_property" contains leading/trailing "/"`),
			},
		},
		{
			name: "valid-nested",
			val:  "foo/bar",
		},
		{
			name: "invalid-nested",
			val:  "foo/bar/",
			expectedErr: []error{
				fmt.Errorf(`value "foo/bar/" for "test_property" contains leading/trailing "/"`),
			},
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := ValidateNoTrailingSlash(tc.val, "test_property")

			if len(errs) == 0 && tc.expectedErr == nil {
				return
			}

			if len(errs) != 0 && tc.expectedErr == nil {
				t.Fatalf("expected test case %d to produce no errors, got %v", i, errs)
			}

			if !reflect.DeepEqual(errs, tc.expectedErr) {
				t.Fatalf("expected test case %d to produce error matching \"%s\", got %v", i, tc.expectedErr, errs)
			}
		})
	}
}

func Test_validateNoLeadingTrailingSlashes(t *testing.T) {
	type args struct {
		i interface{}
		k string
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		want     []string
		wantErrs []error
	}{
		{
			name: "valid",
			args: args{
				i: "foo",
				k: "bar",
			},
		},
		{
			name: "invalid-leading",
			args: args{
				i: "/foo",
				k: "bar",
			},
			wantErr: true,
		},
		{
			name: "invalid-trailing",
			args: args{
				i: "foo/",
				k: "bar",
			},
			wantErr: true,
		},
		{
			name: "invalid-both",
			args: args{
				i: "/foo/",
				k: "bar",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, actualErrs := ValidateNoLeadingTrailingSlashes(tt.args.i, tt.args.k)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateNoLeadingTrailingSlashes() got = %v, want %v", got, tt.want)
			}

			var expectedErrs []error
			if tt.wantErr {
				var e error
				if tt.args.k != "" {
					e = fmt.Errorf(`value %q for %q contains leading/trailing %q`,
						tt.args.i, tt.args.k, consts.PathDelim)
				} else {
					e = fmt.Errorf(`value for %q contains leading/trailing %q`,
						tt.args.i, consts.PathDelim)
				}
				expectedErrs = append(expectedErrs, e)
			}

			if tt.wantErr && actualErrs == nil {
				t.Fatalf("expected errors %#v, actual %#v", expectedErrs, actualErrs)
			}

			if !reflect.DeepEqual(actualErrs, expectedErrs) {
				t.Errorf("validateNoLeadingTrailingSlashes() actualErrs = %v, want %v", actualErrs, expectedErrs)
			}
		})
	}
}

func TestValidateDiagPath(t *testing.T) {
	tests := []struct {
		name string
		i    interface{}
		path cty.Path
		want diag.Diagnostics
	}{
		{
			name: "valid",
			i:    "foo/bar/baz",
			want: nil,
		},
		{
			name: "trailing",
			i:    "foo/bar/baz/",
			want: diag.Diagnostics{
				{
					Severity:      diag.Error,
					Summary:       "Invalid path specified.",
					Detail:        fmt.Sprintf(`value contains leading/trailing %q`, consts.PathDelim),
					AttributePath: nil,
				},
			},
		},
		{
			name: "leading",
			i:    "/foo/bar/baz",
			want: diag.Diagnostics{
				{
					Severity:      diag.Error,
					Summary:       "Invalid path specified.",
					Detail:        fmt.Sprintf(`value contains leading/trailing %q`, consts.PathDelim),
					AttributePath: nil,
				},
			},
		},
		{
			name: "both",
			i:    "/foo/bar/baz/",
			want: diag.Diagnostics{
				{
					Severity:      diag.Error,
					Summary:       "Invalid path specified.",
					Detail:        fmt.Sprintf(`value contains leading/trailing %q`, consts.PathDelim),
					AttributePath: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateDiagPath(tt.i, tt.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateDiagPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetValidateDiagChoices(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		choices []string
		want    diag.Diagnostics
	}{
		{
			name:    "basic",
			value:   "foo",
			choices: []string{"foo", "baz", "bar"},
			want:    nil,
		},
		{
			name:    "casing",
			value:   "Foo",
			choices: []string{"foo", "Foo", "bar"},
			want:    nil,
		},
		{
			name:    "invalid",
			value:   "qux",
			choices: []string{"foo", "baz", "bar"},
			want: diag.Diagnostics{
				{
					Severity: diag.Error,
					Summary:  "Unsupported value.",
					Detail: fmt.Sprintf(
						"Valid choices are: %s",
						strings.Join([]string{"foo", "baz", "bar"}, ", ")),
					AttributePath: nil,
				},
			},
		},
		{
			name:    "invalid-casing",
			value:   "Qux",
			choices: []string{"qux", "baz", "bar"},
			want: diag.Diagnostics{
				{
					Severity: diag.Error,
					Summary:  "Unsupported value.",
					Detail: fmt.Sprintf(
						"Valid choices are: %s",
						strings.Join([]string{"qux", "baz", "bar"}, ", ")),
					AttributePath: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := GetValidateDiagChoices(tt.choices)
			if got := f(tt.value, nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetValidateDiagChoices()() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetValidateDiagURL(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		schemes []string
		want    diag.Diagnostics
	}{
		{
			name:    "basic",
			value:   "http://foo.baz:8080/qux",
			schemes: []string{"http"},
			want:    nil,
		},
		{
			name:    "invalid-scheme",
			value:   "https://foo.baz:8080/qux",
			schemes: []string{"http", "tcp"},
			want: diag.Diagnostics{
				{
					Severity: diag.Error,
					Summary:  `Unsupported scheme "https"`,
					Detail: fmt.Sprintf(
						"Valid schemes are: %s",
						strings.Join([]string{"http", "tcp"}, ", ")),
					AttributePath: nil,
				},
			},
		},
		{
			name:    "invalid-url",
			value:   "foo.bar",
			schemes: []string{"http", "tcp"},
			want: diag.Diagnostics{
				{
					Severity:      diag.Error,
					Summary:       "Invalid URI.",
					Detail:        `Failed to parse URL, err=parse "foo.bar": invalid URI for request`,
					AttributePath: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := GetValidateDiagURI(tt.schemes)
			if got := f(tt.value, nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetValidateDiagURI()() got = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestValidateDiagUUID(t *testing.T) {
	type args struct{}
	tests := []struct {
		name string
		i    interface{}
		path cty.Path
		want diag.Diagnostics
	}{
		{
			name: "valid",
			i:    "323e4572-a92c-13d3-a457-426614173970",
			want: nil,
			path: nil,
		},
		{
			name: "rfc4122-casing",
			i:    "323E4572-a92c-13d3-a457-426614173970",
			path: nil,
			want: diag.Diagnostics{
				{
					Severity: diag.Error,
					Summary:  "Invalid UUID",
					Detail: "Value must be in valid hexadecimal format, " +
						"e.g. 323e4572-a92c-13d3-a457-426614173990",
					AttributePath: nil,
				},
			},
		},
		{
			name: "truncated",
			i:    "323e4572-a92c-13d3-a457-4266141739",
			want: diag.Diagnostics{
				{
					Severity: diag.Error,
					Summary:  "Invalid UUID",
					Detail: "Value must be in valid hexadecimal format, " +
						"e.g. 323e4572-a92c-13d3-a457-426614173990",
					AttributePath: nil,
				},
			},
			path: nil,
		},
		{
			name: "empty",
			i:    "",
			want: diag.Diagnostics{
				{
					Severity: diag.Error,
					Summary:  "Invalid UUID",
					Detail: "Value must be in valid hexadecimal format, " +
						"e.g. 323e4572-a92c-13d3-a457-426614173990",
					AttributePath: nil,
				},
			},
			path: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateDiagUUID(tt.i, tt.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateDiagUUID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateDiagSemVer(t *testing.T) {
	want := diag.Diagnostics{
		{
			Severity: diag.Error,
			Summary:  "Invalid semantic version",
			Detail: "Value must be in valid semantic version string, e.g. " +
				"1.12.0",
			AttributePath: nil,
		},
	}
	type args struct{}
	tests := []struct {
		name string
		i    interface{}
		path cty.Path
		want diag.Diagnostics
	}{
		{
			name: "invalid",
			i:    "v0. 2.0",
			path: nil,
			want: want,
		},
		{
			name: "invalid-empty",
			i:    "",
			path: nil,
			want: want,
		},
		{
			name: "valid",
			i:    "0.2.0",
			path: nil,
			want: nil,
		},
		{
			name: "valid-with-v-prefix",
			i:    "v0.2.0",
			path: nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateDiagSemVer(tt.i, tt.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateDiagSemVer() = %v, want %v", got, tt.want)
			}
		})
	}
}
