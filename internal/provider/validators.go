// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gosimple/slug"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var (
	regexpPathLeading  = regexp.MustCompile(fmt.Sprintf(`^%s`, consts.PathDelim))
	regexpPathTrailing = regexp.MustCompile(fmt.Sprintf(`%s$`, consts.PathDelim))
	RegexpPath         = regexp.MustCompile(fmt.Sprintf(`%s|%s`, regexpPathLeading, regexpPathTrailing))
	regexpUUID         = regexp.MustCompile("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$")
)

func ValidateStringSlug(i interface{}, k string) (s []string, es []error) {
	v, ok := i.(string)
	if !ok {
		es = append(es, fmt.Errorf("expected type of %s to be string", k))
		return
	}

	if !slug.IsSlug(v) {
		es = append(es, fmt.Errorf("expected %s to be a slugified value, i.e: 'my-slug-without-spaces'", k))
	}
	return
}

func ValidateDuration(i interface{}, k string) (s []string, es []error) {
	v, ok := i.(string)
	if !ok {
		es = append(es, fmt.Errorf("expected type of %s to be string", k))
		return
	}

	if _, err := time.ParseDuration(v); err != nil {
		es = append(es, fmt.Errorf("expected '%s' to be a valid duration string", k))
	}
	return
}

func ValidateNoTrailingSlash(i interface{}, k string) ([]string, []error) {
	var errs []error
	if err := validatePath(regexpPathTrailing, i, k); err != nil {
		errs = append(errs, err)
	}

	return nil, errs
}

func ValidateNoLeadingTrailingSlashes(i interface{}, k string) ([]string, []error) {
	var errs []error
	if err := validatePath(RegexpPath, i, k); err != nil {
		errs = append(errs, err)
	}

	return nil, errs
}

func ValidateDiagPath(i interface{}, path cty.Path) diag.Diagnostics {
	return validateDiagPath(RegexpPath, i, path)
}

func validateDiagPath(r *regexp.Regexp, i interface{}, path cty.Path) diag.Diagnostics {
	var diags diag.Diagnostics
	if err := validatePath(r, i, ""); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity:      diag.Error,
			Summary:       "Invalid path specified.",
			Detail:        err.Error(),
			AttributePath: path,
		})
	}

	return diags
}

func validatePath(r *regexp.Regexp, i interface{}, k string) error {
	errPrefix := "value"
	if k != "" {
		errPrefix = fmt.Sprintf("%s %q for %q", errPrefix, i, k)
	}

	v, ok := i.(string)
	if !ok {
		return fmt.Errorf("%s must be a string, not %T", errPrefix, i)
	}

	if v == "" {
		return fmt.Errorf("%s cannot be empty", errPrefix)
	}

	if r.MatchString(v) {
		return fmt.Errorf("%s contains leading/trailing %q", errPrefix, consts.PathDelim)
	}

	return nil
}

// GetValidateDiagChoices sets up a SchemaValidateDiag func that checks that
// the configured string value is supported.
func GetValidateDiagChoices(choices []string) schema.SchemaValidateDiagFunc {
	return func(i interface{}, path cty.Path) diag.Diagnostics {
		have := i.(string)
		if len(choices) == 0 {
			// not much value in this
			return nil
		}

		for _, choice := range choices {
			if have == choice {
				return nil
			}
		}

		return diag.Diagnostics{
			{
				Severity:      diag.Error,
				Summary:       "Unsupported value.",
				Detail:        fmt.Sprintf("Valid choices are: %s", strings.Join(choices, ", ")),
				AttributePath: path,
			},
		}
	}
}

// GetValidateDiagURI sets up a SchemaValidateDiag func that checks that
// the raw url is valid request URI, and optionally contains a supported scheme.
func GetValidateDiagURI(schemes []string) schema.SchemaValidateDiagFunc {
	return func(i interface{}, path cty.Path) diag.Diagnostics {
		have := i.(string)
		u, err := url.ParseRequestURI(have)
		if err != nil {
			return diag.Diagnostics{
				{
					Severity:      diag.Error,
					Summary:       "Invalid URI.",
					Detail:        fmt.Sprintf("Failed to parse URL, err=%s", err),
					AttributePath: path,
				},
			}
		}

		if len(schemes) == 0 {
			return nil
		}

		for _, scheme := range schemes {
			if scheme == u.Scheme {
				return nil
			}
		}

		return diag.Diagnostics{
			{
				Severity:      diag.Error,
				Summary:       fmt.Sprintf("Unsupported scheme %q", u.Scheme),
				Detail:        fmt.Sprintf("Valid schemes are: %s", strings.Join(schemes, ", ")),
				AttributePath: path,
			},
		}
	}
}

// ValidateDiagUUID validates that the input string conforms format defined in rfc4122.
func ValidateDiagUUID(i interface{}, path cty.Path) diag.Diagnostics {
	have := i.(string)
	if !regexpUUID.MatchString(have) {
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Invalid UUID",
				Detail: "Value must be in valid hexadecimal format, e.g. " +
					"323e4572-a92c-13d3-a457-426614173990",
				AttributePath: path,
			},
		}
	}

	return nil
}

// ValidateSemVer validates that the input string conforms to SemVer 2.0.0
func ValidateDiagSemVer(i interface{}, path cty.Path) diag.Diagnostics {
	have := i.(string)
	if _, err := version.NewSemver(have); err != nil {
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Invalid semantic version",
				Detail: "Value must be in valid semantic version string, e.g. " +
					"1.12.0",
				AttributePath: path,
			},
		}
	}

	return nil
}
