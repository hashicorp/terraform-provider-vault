package vault

import (
	"fmt"
	"reflect"
	"testing"
)

func Test_validateNoTrailingSlash(t *testing.T) {
	testCases := []struct {
		val         string
		expectedErr []error
	}{
		{
			val: "foo",
		},
		{
			val: "foo/",
			expectedErr: []error{
				fmt.Errorf(`invalid value "foo/" for "test_property", contains leading/trailing "/"`),
			},
		},
		{
			val: "foo/bar",
		},
		{
			val: "foo/bar/",
			expectedErr: []error{
				fmt.Errorf(`invalid value "foo/bar/" for "test_property", contains leading/trailing "/"`),
			},
		},
	}

	for i, tc := range testCases {
		_, errs := validateNoTrailingSlash(tc.val, "test_property")

		if len(errs) == 0 && tc.expectedErr == nil {
			continue
		}

		if len(errs) != 0 && tc.expectedErr == nil {
			t.Fatalf("expected test case %d to produce no errors, got %v", i, errs)
		}

		if !reflect.DeepEqual(errs, tc.expectedErr) {
			t.Fatalf("expected test case %d to produce error matching \"%s\", got %v", i, tc.expectedErr, errs)
		}
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
			got, actualErrs := validateNoLeadingTrailingSlashes(tt.args.i, tt.args.k)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateNoLeadingTrailingSlashes() got = %v, want %v", got, tt.want)
			}

			var expectedErrs []error
			if tt.wantErr {
				expectedErrs = []error{
					fmt.Errorf(`invalid value %q for %q, contains leading/trailing %q`,
						tt.args.i, tt.args.k, pathDelim),
				}
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
