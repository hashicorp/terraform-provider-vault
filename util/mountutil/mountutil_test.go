// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mountutil

import (
	"net/http"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestIsMountNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "with-err-mount-not-found",
			err:  ErrMountNotFound,
			want: true,
		},
		{
			name: "with-response-error-no-secret-engine-mount",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors: []string{
					"No secret engine mount at auth/operator/",
				},
			},
			want: true,
		},
		{
			name: "with-response-error-no-auth-engine-mount",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors: []string{
					"No auth engine at auth/operator/",
				},
			},
			want: true,
		},
		{
			name: "with-response-error-both",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors: []string{
					"No secret engine mount at auth/operator/",
					"No auth engine at auth/operator/",
				},
			},
			want: true,
		},
		{
			name: "with-response-error-others",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors: []string{
					"Some other error",
					"No auth engine at auth/operator/",
				},
			},
			want: true,
		},
		{
			name: "with-not-found-status-code",
			err: &api.ResponseError{
				StatusCode: http.StatusNotFound,
				Errors: []string{
					"some error",
				},
			},
			want: true,
		},
		{
			name: "with-response-error-canary",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors: []string{
					"secret engine mount",
				},
			},
			want: false,
		},
		{
			name: "with-nil-error",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, IsMountNotFoundError(tt.err), "IsMountNotFoundError(%v)", tt.err)
		})
	}
}
