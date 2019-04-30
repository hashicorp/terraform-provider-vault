package vault

import (
	"regexp"
	"testing"
)

func TestValidateNoTrailingSlash(t *testing.T) {
	testCases := []struct {
		val         string
		expectedErr *regexp.Regexp
	}{
		{
			val: "foo",
		},
		{
			val:         "foo/",
			expectedErr: regexp.MustCompile(`cannot write to a path ending in '/'`),
		},
		{
			val: "foo/bar",
		},
		{
			val:         "foo/bar/",
			expectedErr: regexp.MustCompile(`cannot write to a path ending in '/'`),
		},
	}

	matchErr := func(errs []error, r *regexp.Regexp) bool {
		// err must match one provided
		for _, err := range errs {
			if r.MatchString(err.Error()) {
				return true
			}
		}

		return false
	}

	for i, tc := range testCases {
		_, errs := validateNoTrailingSlash(tc.val, "test_property")

		if len(errs) == 0 && tc.expectedErr == nil {
			continue
		}

		if len(errs) != 0 && tc.expectedErr == nil {
			t.Fatalf("expected test case %d to produce no errors, got %v", i, errs)
		}

		if !matchErr(errs, tc.expectedErr) {
			t.Fatalf("expected test case %d to produce error matching \"%s\", got %v", i, tc.expectedErr, errs)
		}
	}
}
