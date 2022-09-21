package provider

import (
	"fmt"
	"regexp"
	"time"

	"github.com/gosimple/slug"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var (
	regexpPathLeading  = regexp.MustCompile(fmt.Sprintf(`^%s`, consts.PathDelim))
	regexpPathTrailing = regexp.MustCompile(fmt.Sprintf(`%s$`, consts.PathDelim))
	regexpPath         = regexp.MustCompile(fmt.Sprintf(`%s|%s`, regexpPathLeading, regexpPathTrailing))
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
	if err := validatePath(regexpPath, i, k); err != nil {
		errs = append(errs, err)
	}

	return nil, errs
}

func ValidateDiagPath(i interface{}, path cty.Path) diag.Diagnostics {
	return validateDiagPath(regexpPath, i, path)
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
